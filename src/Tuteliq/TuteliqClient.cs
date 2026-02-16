using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tuteliq;

/// <summary>
/// Tuteliq API client for AI-powered child safety analysis.
/// </summary>
/// <example>
/// <code>
/// var client = new TuteliqClient("your-api-key");
/// var result = await client.DetectBullyingAsync(new DetectBullyingInput { Content = "test" });
/// if (result.IsBullying) Console.WriteLine($"Severity: {result.Severity}");
/// </code>
/// </example>
public class TuteliqClient : IDisposable
{
    private const int MaxContentLength = 50_000;
    private const int MaxMessagesCount = 100;
    private const int MaxBackoffMs = 30_000;
    private const string SdkIdentifier = "Dotnet SDK";

    private readonly HttpClient _httpClient;
    private readonly string _apiKey;
    private readonly int _timeout;
    private readonly int _maxRetries;
    private readonly int _retryDelay;
    private readonly bool _ownsHttpClient;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = new SnakeCaseNamingPolicy(),
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = true,
    };

    private sealed class SnakeCaseNamingPolicy : JsonNamingPolicy
    {
        public override string ConvertName(string name)
        {
            if (string.IsNullOrEmpty(name)) return name;
            var sb = new StringBuilder();
            for (int i = 0; i < name.Length; i++)
            {
                var c = name[i];
                if (char.IsUpper(c))
                {
                    if (i > 0) sb.Append('_');
                    sb.Append(char.ToLowerInvariant(c));
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }
    }

    /// <summary>Current monthly usage statistics (updated after each request).</summary>
    public Usage? Usage { get; private set; }

    /// <summary>Current rate limit information (updated after each request).</summary>
    public RateLimitInfo? RateLimit { get; private set; }

    /// <summary>Usage warning message if over 80% of monthly limit.</summary>
    public string? UsageWarning { get; private set; }

    /// <summary>Request ID from the last API call.</summary>
    public string? LastRequestId { get; private set; }

    /// <summary>Latency of the last API call in milliseconds.</summary>
    public long? LastLatencyMs { get; private set; }

    /// <summary>
    /// Creates a new Tuteliq client.
    /// </summary>
    /// <param name="apiKey">Your Tuteliq API key.</param>
    /// <param name="options">Optional configuration.</param>
    public TuteliqClient(string apiKey, TuteliqOptions? options = null)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            throw new ArgumentException("API key is required", nameof(apiKey));
        if (apiKey.Length < 10)
            throw new ArgumentException("API key appears to be invalid (too short)", nameof(apiKey));

        options ??= new TuteliqOptions();

        if (options.Timeout < 1_000 || options.Timeout > 120_000)
            throw new ArgumentOutOfRangeException(nameof(options), "Timeout must be between 1000 and 120000 ms");
        if (options.Retries < 0 || options.Retries > 10)
            throw new ArgumentOutOfRangeException(nameof(options), "Retries must be between 0 and 10");

        _apiKey = apiKey;
        _timeout = options.Timeout;
        _maxRetries = options.Retries;
        _retryDelay = options.RetryDelay;

        _httpClient = new HttpClient { BaseAddress = new Uri(options.BaseUrl) };
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _ownsHttpClient = true;
    }

    /// <summary>
    /// Creates a new Tuteliq client with a custom HttpClient (for DI scenarios).
    /// </summary>
    public TuteliqClient(string apiKey, HttpClient httpClient, TuteliqOptions? options = null)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            throw new ArgumentException("API key is required", nameof(apiKey));

        options ??= new TuteliqOptions();

        _apiKey = apiKey;
        _timeout = options.Timeout;
        _maxRetries = options.Retries;
        _retryDelay = options.RetryDelay;
        _httpClient = httpClient;
        _ownsHttpClient = false;

        if (_httpClient.DefaultRequestHeaders.Authorization == null)
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
    }

    // =========================================================================
    // Safety Detection
    // =========================================================================

    /// <summary>
    /// Detect bullying in text content.
    /// </summary>
    public async Task<BullyingResult> DetectBullyingAsync(DetectBullyingInput input, CancellationToken ct = default)
    {
        ValidateContentLength(input.Content);

        var body = new Dictionary<string, object?> { ["text"] = input.Content };
        AddContext(body, input.Context);
        AddTrackingFields(body, input.ExternalId, input.CustomerId, input.Metadata);

        return await PostAsync<BullyingResult>("/api/v1/safety/bullying", body, ct);
    }

    /// <summary>
    /// Detect grooming patterns in a conversation.
    /// </summary>
    public async Task<GroomingResult> DetectGroomingAsync(DetectGroomingInput input, CancellationToken ct = default)
    {
        ValidateMessagesCount(input.Messages.Count);

        var messages = input.Messages.Select(m => new Dictionary<string, string>
        {
            ["sender_role"] = m.Role.ToApiString(),
            ["text"] = m.Content
        }).ToList();

        var body = new Dictionary<string, object?> { ["messages"] = messages };

        var context = new Dictionary<string, object>();
        if (input.ChildAge.HasValue) context["child_age"] = input.ChildAge.Value;
        context["platform"] = ResolvePlatform(input.Context?.Platform);
        body["context"] = context;

        AddTrackingFields(body, input.ExternalId, input.CustomerId, input.Metadata);

        return await PostAsync<GroomingResult>("/api/v1/safety/grooming", body, ct);
    }

    /// <summary>
    /// Detect unsafe content (self-harm, violence, hate speech, etc.).
    /// </summary>
    public async Task<UnsafeResult> DetectUnsafeAsync(DetectUnsafeInput input, CancellationToken ct = default)
    {
        ValidateContentLength(input.Content);

        var body = new Dictionary<string, object?> { ["text"] = input.Content };
        AddContext(body, input.Context);
        AddTrackingFields(body, input.ExternalId, input.CustomerId, input.Metadata);

        return await PostAsync<UnsafeResult>("/api/v1/safety/unsafe", body, ct);
    }

    /// <summary>
    /// Quick combined analysis — runs bullying and unsafe detection in parallel.
    /// </summary>
    public async Task<AnalyzeResult> AnalyzeAsync(string content, AnalysisContext? context = null, CancellationToken ct = default)
    {
        return await AnalyzeAsync(new AnalyzeInput { Content = content, Context = context }, ct);
    }

    /// <summary>
    /// Combined analysis with full options.
    /// </summary>
    public async Task<AnalyzeResult> AnalyzeAsync(AnalyzeInput input, CancellationToken ct = default)
    {
        ValidateContentLength(input.Content);

        var checks = input.Include ?? new List<string> { "bullying", "unsafe" };

        BullyingResult? bullyingResult = null;
        UnsafeResult? unsafeResult = null;

        var tasks = new List<Task>();

        if (checks.Contains("bullying"))
        {
            var task = DetectBullyingAsync(new DetectBullyingInput
            {
                Content = input.Content,
                Context = input.Context,
                ExternalId = input.ExternalId,
                CustomerId = input.CustomerId,
                Metadata = input.Metadata,
            }, ct).ContinueWith(t => bullyingResult = t.Result, ct);
            tasks.Add(task);
        }

        if (checks.Contains("unsafe"))
        {
            var task = DetectUnsafeAsync(new DetectUnsafeInput
            {
                Content = input.Content,
                Context = input.Context,
                ExternalId = input.ExternalId,
                CustomerId = input.CustomerId,
                Metadata = input.Metadata,
            }, ct).ContinueWith(t => unsafeResult = t.Result, ct);
            tasks.Add(task);
        }

        await Task.WhenAll(tasks);

        var maxRiskScore = Math.Max(
            bullyingResult?.RiskScore ?? 0,
            unsafeResult?.RiskScore ?? 0);

        var riskLevel = maxRiskScore switch
        {
            >= 0.9 => RiskLevel.Critical,
            >= 0.7 => RiskLevel.High,
            >= 0.5 => RiskLevel.Medium,
            >= 0.3 => RiskLevel.Low,
            _ => RiskLevel.Safe
        };

        var findings = new List<string>();
        if (bullyingResult?.IsBullying == true)
            findings.Add($"Bullying detected ({bullyingResult.SeverityRaw})");
        if (unsafeResult?.Unsafe == true)
            findings.Add($"Unsafe content: {string.Join(", ", unsafeResult.Categories)}");

        var summary = findings.Count == 0 ? "No safety concerns detected." : string.Join(". ", findings);

        string recommendedAction = "none";
        var actions = new List<string?> { bullyingResult?.RecommendedAction, unsafeResult?.RecommendedAction };
        if (actions.Contains("immediate_intervention")) recommendedAction = "immediate_intervention";
        else if (actions.Contains("flag_for_moderator")) recommendedAction = "flag_for_moderator";
        else if (actions.Contains("monitor")) recommendedAction = "monitor";

        return new AnalyzeResult
        {
            RiskLevel = riskLevel,
            RiskScore = maxRiskScore,
            Summary = summary,
            Bullying = bullyingResult,
            Unsafe = unsafeResult,
            RecommendedAction = recommendedAction,
            ExternalId = input.ExternalId,
            CustomerId = input.CustomerId,
            Metadata = input.Metadata,
        };
    }

    // =========================================================================
    // Emotion Analysis
    // =========================================================================

    /// <summary>
    /// Analyze emotions in content or conversations.
    /// </summary>
    public async Task<EmotionsResult> AnalyzeEmotionsAsync(AnalyzeEmotionsInput input, CancellationToken ct = default)
    {
        var body = new Dictionary<string, object?>();

        if (input.Messages != null && input.Messages.Count > 0)
        {
            ValidateMessagesCount(input.Messages.Count);
            body["messages"] = input.Messages.Select(m => new Dictionary<string, string>
            {
                ["sender"] = m.Sender,
                ["text"] = m.Content
            }).ToList();
        }
        else if (!string.IsNullOrEmpty(input.Content))
        {
            body["messages"] = new List<Dictionary<string, string>>
            {
                new() { ["sender"] = "user", ["text"] = input.Content }
            };
        }

        AddContext(body, input.Context);
        AddTrackingFields(body, input.ExternalId, input.CustomerId, input.Metadata);

        return await PostAsync<EmotionsResult>("/api/v1/analysis/emotions", body, ct);
    }

    // =========================================================================
    // Guidance
    // =========================================================================

    /// <summary>
    /// Generate an age-appropriate action plan.
    /// </summary>
    public async Task<ActionPlanResult> GetActionPlanAsync(GetActionPlanInput input, CancellationToken ct = default)
    {
        var body = new Dictionary<string, object?>
        {
            ["role"] = input.Audience.ToApiString(),
            ["situation"] = input.Situation,
        };

        if (input.ChildAge.HasValue) body["child_age"] = input.ChildAge.Value;
        if (input.Severity.HasValue) body["severity"] = input.Severity.Value.ToApiString();
        AddTrackingFields(body, input.ExternalId, input.CustomerId, input.Metadata);

        return await PostAsync<ActionPlanResult>("/api/v1/guidance/action-plan", body, ct);
    }

    // =========================================================================
    // Reports
    // =========================================================================

    /// <summary>
    /// Generate a professional incident report.
    /// </summary>
    public async Task<ReportResult> GenerateReportAsync(GenerateReportInput input, CancellationToken ct = default)
    {
        ValidateMessagesCount(input.Messages.Count);

        var messages = input.Messages.Select(m => new Dictionary<string, string>
        {
            ["sender"] = m.Sender,
            ["text"] = m.Content
        }).ToList();

        var body = new Dictionary<string, object?> { ["messages"] = messages };

        var meta = new Dictionary<string, object>();
        if (input.ChildAge.HasValue) meta["child_age"] = input.ChildAge.Value;
        if (input.IncidentType != null) meta["type"] = input.IncidentType;
        if (meta.Count > 0) body["meta"] = meta;

        AddTrackingFields(body, input.ExternalId, input.CustomerId, input.Metadata);

        return await PostAsync<ReportResult>("/api/v1/reports/incident", body, ct);
    }

    // =========================================================================
    // Account Management (GDPR)
    // =========================================================================

    /// <summary>
    /// Delete all account data (GDPR Article 17 — Right to Erasure).
    /// </summary>
    public async Task<AccountDeletionResult> DeleteAccountDataAsync(CancellationToken ct = default)
    {
        return await RequestWithRetryAsync<AccountDeletionResult>(HttpMethod.Delete, "/api/v1/account/data", null, ct);
    }

    /// <summary>
    /// Export all account data as JSON (GDPR Article 20 — Right to Data Portability).
    /// </summary>
    public async Task<AccountExportResult> ExportAccountDataAsync(CancellationToken ct = default)
    {
        return await RequestWithRetryAsync<AccountExportResult>(HttpMethod.Get, "/api/v1/account/export", null, ct);
    }

    /// <summary>
    /// Record user consent (GDPR Article 7).
    /// </summary>
    public async Task<ConsentActionResult> RecordConsentAsync(RecordConsentInput input, CancellationToken ct = default)
    {
        var body = new { consent_type = input.ConsentType, version = input.Version };
        return await RequestWithRetryAsync<ConsentActionResult>(HttpMethod.Post, "/api/v1/account/consent", body, ct);
    }

    /// <summary>
    /// Get current consent status (GDPR Article 7).
    /// </summary>
    public async Task<ConsentStatusResult> GetConsentStatusAsync(string? consentType = null, CancellationToken ct = default)
    {
        var query = consentType != null ? $"?type={consentType}" : "";
        return await RequestWithRetryAsync<ConsentStatusResult>(HttpMethod.Get, $"/api/v1/account/consent{query}", null, ct);
    }

    /// <summary>
    /// Withdraw consent (GDPR Article 7.3).
    /// </summary>
    public async Task<ConsentActionResult> WithdrawConsentAsync(string consentType, CancellationToken ct = default)
    {
        return await RequestWithRetryAsync<ConsentActionResult>(HttpMethod.Delete, $"/api/v1/account/consent/{consentType}", null, ct);
    }

    /// <summary>
    /// Rectify user data (GDPR Article 16 — Right to Rectification).
    /// </summary>
    public async Task<RectifyDataResult> RectifyDataAsync(RectifyDataInput input, CancellationToken ct = default)
    {
        var body = new { collection = input.Collection, document_id = input.DocumentId, fields = input.Fields };
        return await RequestWithRetryAsync<RectifyDataResult>(HttpMethod.Patch, "/api/v1/account/data", body, ct);
    }

    /// <summary>
    /// Get audit logs (GDPR Article 15 — Right of Access).
    /// </summary>
    public async Task<AuditLogsResult> GetAuditLogsAsync(string? action = null, int? limit = null, CancellationToken ct = default)
    {
        var parameters = new List<string>();
        if (action != null) parameters.Add($"action={action}");
        if (limit.HasValue) parameters.Add($"limit={limit.Value}");
        var query = parameters.Count > 0 ? $"?{string.Join("&", parameters)}" : "";
        return await RequestWithRetryAsync<AuditLogsResult>(HttpMethod.Get, $"/api/v1/account/audit-logs{query}", null, ct);
    }

    // =========================================================================
    // Breach Management (GDPR Article 33/34)
    // =========================================================================

    /// <summary>
    /// Log a new data breach.
    /// </summary>
    public async Task<LogBreachResult> LogBreachAsync(LogBreachInput input, CancellationToken ct = default)
    {
        var body = new
        {
            title = input.Title,
            description = input.Description,
            severity = input.Severity,
            affected_user_ids = input.AffectedUserIds,
            data_categories = input.DataCategories,
            reported_by = input.ReportedBy,
        };
        return await RequestWithRetryAsync<LogBreachResult>(HttpMethod.Post, "/api/v1/admin/breach", body, ct);
    }

    /// <summary>
    /// List data breaches.
    /// </summary>
    public async Task<BreachListResult> ListBreachesAsync(string? status = null, int? limit = null, CancellationToken ct = default)
    {
        var parameters = new List<string>();
        if (status != null) parameters.Add($"status={status}");
        if (limit.HasValue) parameters.Add($"limit={limit.Value}");
        var query = parameters.Count > 0 ? $"?{string.Join("&", parameters)}" : "";
        return await RequestWithRetryAsync<BreachListResult>(HttpMethod.Get, $"/api/v1/admin/breach{query}", null, ct);
    }

    /// <summary>
    /// Get a single breach by ID.
    /// </summary>
    public async Task<BreachResult> GetBreachAsync(string id, CancellationToken ct = default)
    {
        return await RequestWithRetryAsync<BreachResult>(HttpMethod.Get, $"/api/v1/admin/breach/{id}", null, ct);
    }

    /// <summary>
    /// Update a breach's status.
    /// </summary>
    public async Task<BreachResult> UpdateBreachStatusAsync(string id, UpdateBreachInput input, CancellationToken ct = default)
    {
        var bodyDict = new Dictionary<string, object?> { ["status"] = input.Status };
        if (input.NotificationStatus != null) bodyDict["notification_status"] = input.NotificationStatus;
        if (input.Notes != null) bodyDict["notes"] = input.Notes;
        return await RequestWithRetryAsync<BreachResult>(HttpMethod.Patch, $"/api/v1/admin/breach/{id}", bodyDict, ct);
    }

    // =========================================================================
    // Voice Analysis
    // =========================================================================

    /// <summary>
    /// Analyze a voice/audio file for safety concerns.
    /// </summary>
    public async Task<VoiceAnalysisResult> AnalyzeVoiceAsync(
        byte[] file,
        string filename,
        string analysisType = "all",
        string? fileId = null,
        string? externalId = null,
        string? customerId = null,
        Dictionary<string, object>? metadata = null,
        string? ageGroup = null,
        string? language = null,
        string? platform = null,
        int? childAge = null,
        CancellationToken ct = default)
    {
        var content = new MultipartFormDataContent();
        content.Add(new ByteArrayContent(file), "file", filename);
        content.Add(new StringContent(analysisType), "analysis_type");
        content.Add(new StringContent(ResolvePlatform(platform)), "platform");
        if (fileId != null) content.Add(new StringContent(fileId), "file_id");
        if (externalId != null) content.Add(new StringContent(externalId), "external_id");
        if (customerId != null) content.Add(new StringContent(customerId), "customer_id");
        if (metadata != null) content.Add(new StringContent(JsonSerializer.Serialize(metadata, JsonOptions)), "metadata");
        if (ageGroup != null) content.Add(new StringContent(ageGroup), "age_group");
        if (language != null) content.Add(new StringContent(language), "language");
        if (childAge != null) content.Add(new StringContent(childAge.Value.ToString()), "child_age");
        return await MultipartRequestAsync<VoiceAnalysisResult>("/api/v1/safety/voice", content, ct);
    }

    // =========================================================================
    // Image Analysis
    // =========================================================================

    /// <summary>
    /// Analyze an image file for safety concerns.
    /// </summary>
    public async Task<ImageAnalysisResult> AnalyzeImageAsync(
        byte[] file,
        string filename,
        string analysisType = "all",
        string? fileId = null,
        string? externalId = null,
        string? customerId = null,
        Dictionary<string, object>? metadata = null,
        string? ageGroup = null,
        string? platform = null,
        CancellationToken ct = default)
    {
        var content = new MultipartFormDataContent();
        content.Add(new ByteArrayContent(file), "file", filename);
        content.Add(new StringContent(analysisType), "analysis_type");
        content.Add(new StringContent(ResolvePlatform(platform)), "platform");
        if (fileId != null) content.Add(new StringContent(fileId), "file_id");
        if (externalId != null) content.Add(new StringContent(externalId), "external_id");
        if (customerId != null) content.Add(new StringContent(customerId), "customer_id");
        if (metadata != null) content.Add(new StringContent(JsonSerializer.Serialize(metadata, JsonOptions)), "metadata");
        if (ageGroup != null) content.Add(new StringContent(ageGroup), "age_group");
        return await MultipartRequestAsync<ImageAnalysisResult>("/api/v1/safety/image", content, ct);
    }

    // =========================================================================
    // Webhooks
    // =========================================================================

    /// <summary>
    /// List all webhooks for the current account.
    /// </summary>
    public async Task<WebhookListResult> ListWebhooksAsync(CancellationToken ct = default)
    {
        return await RequestWithRetryAsync<WebhookListResult>(HttpMethod.Get, "/api/v1/webhooks", null, ct);
    }

    /// <summary>
    /// Create a new webhook.
    /// </summary>
    public async Task<CreateWebhookResult> CreateWebhookAsync(CreateWebhookInput input, CancellationToken ct = default)
    {
        var body = new Dictionary<string, object?>
        {
            ["url"] = input.Url,
            ["events"] = input.Events,
            ["active"] = input.Active,
        };
        return await RequestWithRetryAsync<CreateWebhookResult>(HttpMethod.Post, "/api/v1/webhooks", body, ct);
    }

    /// <summary>
    /// Update an existing webhook.
    /// </summary>
    public async Task<UpdateWebhookResult> UpdateWebhookAsync(string webhookId, UpdateWebhookInput input, CancellationToken ct = default)
    {
        var body = new Dictionary<string, object?>();
        if (input.Url != null) body["url"] = input.Url;
        if (input.Events != null) body["events"] = input.Events;
        if (input.Active.HasValue) body["active"] = input.Active.Value;
        return await RequestWithRetryAsync<UpdateWebhookResult>(HttpMethod.Patch, $"/api/v1/webhooks/{webhookId}", body, ct);
    }

    /// <summary>
    /// Delete a webhook.
    /// </summary>
    public async Task<DeleteWebhookResult> DeleteWebhookAsync(string webhookId, CancellationToken ct = default)
    {
        return await RequestWithRetryAsync<DeleteWebhookResult>(HttpMethod.Delete, $"/api/v1/webhooks/{webhookId}", null, ct);
    }

    /// <summary>
    /// Send a test event to a webhook.
    /// </summary>
    public async Task<TestWebhookResult> TestWebhookAsync(string webhookId, CancellationToken ct = default)
    {
        return await RequestWithRetryAsync<TestWebhookResult>(HttpMethod.Post, $"/api/v1/webhooks/{webhookId}/test", null, ct);
    }

    /// <summary>
    /// Regenerate the secret for a webhook.
    /// </summary>
    public async Task<RegenerateSecretResult> RegenerateWebhookSecretAsync(string webhookId, CancellationToken ct = default)
    {
        return await RequestWithRetryAsync<RegenerateSecretResult>(HttpMethod.Post, $"/api/v1/webhooks/{webhookId}/secret", null, ct);
    }

    // =========================================================================
    // Pricing
    // =========================================================================

    /// <summary>
    /// Get available pricing plans.
    /// </summary>
    public async Task<PricingResult> GetPricingAsync(CancellationToken ct = default)
    {
        return await RequestWithRetryAsync<PricingResult>(HttpMethod.Get, "/api/v1/pricing", null, ct);
    }

    /// <summary>
    /// Get detailed pricing information including tier limits and features.
    /// </summary>
    public async Task<PricingDetailsResult> GetPricingDetailsAsync(CancellationToken ct = default)
    {
        return await RequestWithRetryAsync<PricingDetailsResult>(HttpMethod.Get, "/api/v1/pricing/details", null, ct);
    }

    // =========================================================================
    // Usage
    // =========================================================================

    /// <summary>
    /// Get usage history for the current API key.
    /// </summary>
    public async Task<UsageHistoryResult> GetUsageHistoryAsync(int? days = null, CancellationToken ct = default)
    {
        var query = days.HasValue ? $"?days={days.Value}" : "";
        return await RequestWithRetryAsync<UsageHistoryResult>(HttpMethod.Get, $"/api/v1/usage/history{query}", null, ct);
    }

    /// <summary>
    /// Get usage grouped by tool/endpoint.
    /// </summary>
    public async Task<UsageByToolResult> GetUsageByToolAsync(string? date = null, CancellationToken ct = default)
    {
        var query = date != null ? $"?date={date}" : "";
        return await RequestWithRetryAsync<UsageByToolResult>(HttpMethod.Get, $"/api/v1/usage/by-tool{query}", null, ct);
    }

    /// <summary>
    /// Get monthly usage summary including billing and rate limit information.
    /// </summary>
    public async Task<UsageMonthlyResult> GetUsageMonthlyAsync(CancellationToken ct = default)
    {
        return await RequestWithRetryAsync<UsageMonthlyResult>(HttpMethod.Get, "/api/v1/usage/monthly", null, ct);
    }

    // =========================================================================
    // Voice Streaming
    // =========================================================================

    /// <summary>
    /// Create a voice streaming session over WebSocket.
    /// </summary>
    public VoiceStreamSession CreateVoiceStream(VoiceStreamConfig? config = null, VoiceStreamHandlers? handlers = null)
    {
        return new VoiceStreamSession(_apiKey, config, handlers);
    }

    // =========================================================================
    // Private Methods
    // =========================================================================

    private async Task<T> PostAsync<T>(string path, Dictionary<string, object?> body, CancellationToken ct)
    {
        return await RequestWithRetryAsync<T>(HttpMethod.Post, path, body, ct);
    }

    private async Task<T> MultipartRequestAsync<T>(string path, MultipartFormDataContent content, CancellationToken ct = default)
    {
        Exception? lastError = null;

        for (int attempt = 0; attempt <= _maxRetries; attempt++)
        {
            try
            {
                var sw = Stopwatch.StartNew();

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(_timeout);

                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = content };
                    request.Headers.Add("X-API-Key", _apiKey);

                    using var response = await _httpClient.SendAsync(request, cts.Token);

                    sw.Stop();
                    LastLatencyMs = sw.ElapsedMilliseconds;

                    ParseResponseHeaders(response);

                    var responseBody = await response.Content.ReadAsStringAsync(cts.Token);

                    if (!response.IsSuccessStatusCode)
                        HandleErrorResponse(response.StatusCode, responseBody);

                    return JsonSerializer.Deserialize<T>(responseBody, JsonOptions)
                        ?? throw new TuteliqException("Failed to parse API response");
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (OperationCanceledException)
                {
                    throw new Tuteliq.TimeoutException($"Request to {path} timed out after {_timeout}ms");
                }
                catch (HttpRequestException ex)
                {
                    throw new NetworkException($"Network error: {ex.Message}", ex);
                }
            }
            catch (AuthenticationException) { throw; }
            catch (ValidationException) { throw; }
            catch (NotFoundException) { throw; }
            catch (TierAccessException) { throw; }
            catch (RateLimitException ex) when (attempt < _maxRetries)
            {
                lastError = ex;
                var delay = ex.RetryAfterSeconds.HasValue
                    ? ex.RetryAfterSeconds.Value * 1000
                    : CalculateBackoff(attempt);
                await Task.Delay(delay, ct);
            }
            catch (TuteliqException ex) when (attempt < _maxRetries && IsRetryable(ex))
            {
                lastError = ex;
                await Task.Delay(CalculateBackoff(attempt), ct);
            }
        }

        throw lastError ?? new TuteliqException("Request failed after retries");
    }

    private async Task<T> RequestWithRetryAsync<T>(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        Exception? lastError = null;

        for (int attempt = 0; attempt <= _maxRetries; attempt++)
        {
            try
            {
                return await PerformRequestAsync<T>(method, path, body, ct);
            }
            catch (AuthenticationException) { throw; }
            catch (ValidationException) { throw; }
            catch (NotFoundException) { throw; }
            catch (TierAccessException) { throw; }
            catch (RateLimitException ex) when (attempt < _maxRetries)
            {
                lastError = ex;
                var delay = ex.RetryAfterSeconds.HasValue
                    ? ex.RetryAfterSeconds.Value * 1000
                    : CalculateBackoff(attempt);
                await Task.Delay(delay, ct);
            }
            catch (TuteliqException ex) when (attempt < _maxRetries && IsRetryable(ex))
            {
                lastError = ex;
                await Task.Delay(CalculateBackoff(attempt), ct);
            }
        }

        throw lastError ?? new TuteliqException("Request failed after retries");
    }

    private async Task<T> PerformRequestAsync<T>(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_timeout);

        try
        {
            using var request = new HttpRequestMessage(method, path);

            if (body != null)
            {
                var json = JsonSerializer.Serialize(body, JsonOptions);
                request.Content = new StringContent(json, Encoding.UTF8, "application/json");
            }

            using var response = await _httpClient.SendAsync(request, cts.Token);

            sw.Stop();
            LastLatencyMs = sw.ElapsedMilliseconds;

            ParseResponseHeaders(response);

            var responseBody = await response.Content.ReadAsStringAsync(cts.Token);

            if (!response.IsSuccessStatusCode)
                HandleErrorResponse(response.StatusCode, responseBody);

            return JsonSerializer.Deserialize<T>(responseBody, JsonOptions)
                ?? throw new TuteliqException("Failed to parse API response");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw new Tuteliq.TimeoutException($"Request to {path} timed out after {_timeout}ms");
        }
        catch (HttpRequestException ex)
        {
            throw new NetworkException($"Network error: {ex.Message}", ex);
        }
    }

    private void ParseResponseHeaders(HttpResponseMessage response)
    {
        LastRequestId = GetHeader(response, "x-request-id");

        if (int.TryParse(GetHeader(response, "x-monthly-limit"), out var limit) &&
            int.TryParse(GetHeader(response, "x-monthly-used"), out var used) &&
            int.TryParse(GetHeader(response, "x-monthly-remaining"), out var remaining))
        {
            Usage = new Usage { Limit = limit, Used = used, Remaining = remaining };
        }

        if (int.TryParse(GetHeader(response, "x-ratelimit-limit"), out var rlLimit) &&
            int.TryParse(GetHeader(response, "x-ratelimit-remaining"), out var rlRemaining))
        {
            var rl = new RateLimitInfo { Limit = rlLimit, Remaining = rlRemaining };
            if (long.TryParse(GetHeader(response, "x-ratelimit-reset"), out var rlReset))
                rl.Reset = rlReset;
            RateLimit = rl;
        }

        UsageWarning = GetHeader(response, "x-usage-warning");
    }

    private void HandleErrorResponse(HttpStatusCode statusCode, string responseBody)
    {
        string message = "Request failed";
        string? code = null;
        object? details = null;
        string? suggestion = null;
        int? retryAfter = null;

        try
        {
            using var doc = JsonDocument.Parse(responseBody);
            if (doc.RootElement.TryGetProperty("error", out var errorObj))
            {
                if (errorObj.TryGetProperty("message", out var msgEl)) message = msgEl.GetString() ?? message;
                if (errorObj.TryGetProperty("code", out var codeEl)) code = codeEl.GetString();
                if (errorObj.TryGetProperty("suggestion", out var sugEl)) suggestion = sugEl.GetString();
                if (errorObj.TryGetProperty("details", out var detEl)) details = detEl.ToString();
            }
        }
        catch { }

        var status = (int)statusCode;

        throw status switch
        {
            400 => new ValidationException(message, code, details, suggestion),
            401 => new AuthenticationException(message, code, details, suggestion),
            403 => new TierAccessException(message, code, details, suggestion),
            404 => new NotFoundException(message, code, details, suggestion),
            429 => new RateLimitException(message, retryAfter, code, details, suggestion),
            >= 500 => new ServerException(message, status, code, details, suggestion),
            _ => new TuteliqException(message, status, code, details, suggestion),
        };
    }

    private int CalculateBackoff(int attempt)
    {
        var delay = _retryDelay * (1 << attempt);
        var jitter = Random.Shared.Next(0, (int)(delay * 0.25));
        return Math.Min(delay + jitter, MaxBackoffMs);
    }

    private static bool IsRetryable(TuteliqException ex)
    {
        return ex is ServerException or NetworkException or Tuteliq.TimeoutException;
    }

    private static string? GetHeader(HttpResponseMessage response, string name)
    {
        return response.Headers.TryGetValues(name, out var values) ? values.FirstOrDefault() : null;
    }

    private static string ResolvePlatform(string? platform = null)
    {
        if (!string.IsNullOrEmpty(platform))
            return $"{platform} - {SdkIdentifier}";
        return SdkIdentifier;
    }

    private static void AddContext(Dictionary<string, object?> body, AnalysisContext? context)
    {
        var dict = new Dictionary<string, object>();
        if (context != null)
        {
            if (context.Language != null) dict["language"] = context.Language;
            if (context.AgeGroup != null) dict["age_group"] = context.AgeGroup;
            if (context.Relationship != null) dict["relationship"] = context.Relationship;
        }
        dict["platform"] = ResolvePlatform(context?.Platform);
        body["context"] = dict;
    }

    private static void AddTrackingFields(Dictionary<string, object?> body, string? externalId, string? customerId, Dictionary<string, object>? metadata)
    {
        if (externalId != null) body["external_id"] = externalId;
        if (customerId != null) body["customer_id"] = customerId;
        if (metadata != null) body["metadata"] = metadata;
    }

    private static void ValidateContentLength(string content)
    {
        if (string.IsNullOrEmpty(content))
            throw new ValidationException("Content is required");
        if (content.Length > MaxContentLength)
            throw new ValidationException($"Content exceeds maximum length of {MaxContentLength} characters");
    }

    private static void ValidateMessagesCount(int count)
    {
        if (count == 0)
            throw new ValidationException("At least one message is required");
        if (count > MaxMessagesCount)
            throw new ValidationException($"Messages exceed maximum count of {MaxMessagesCount}");
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
