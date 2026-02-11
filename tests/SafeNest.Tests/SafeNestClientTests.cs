using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SafeNest.Tests;

// =============================================================================
// Helper: Mock HttpMessageHandler
// =============================================================================

internal class MockHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;
    public List<HttpRequestMessage> Requests { get; } = new();

    public MockHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) => _handler = handler;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Requests.Add(request);
        return Task.FromResult(_handler(request));
    }

    public static MockHandler WithJson(object body, HttpStatusCode status = HttpStatusCode.OK,
        Dictionary<string, string>? headers = null)
    {
        return new MockHandler(_ =>
        {
            var json = JsonSerializer.Serialize(body, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
            });
            var response = new HttpResponseMessage(status)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
            if (headers != null)
                foreach (var (key, value) in headers)
                    response.Headers.TryAddWithoutValidation(key, value);
            return response;
        });
    }

    public static MockHandler WithError(HttpStatusCode status, string message, string? code = null)
    {
        return new MockHandler(_ =>
        {
            var errorBody = new { error = new { message, code } };
            var json = JsonSerializer.Serialize(errorBody);
            return new HttpResponseMessage(status)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
        });
    }
}

// =============================================================================
// Constructor Tests
// =============================================================================

public class ConstructorTests
{
    [Fact]
    public void Throws_when_api_key_is_null()
    {
        Assert.Throws<ArgumentException>(() => new SafeNestClient(null!));
    }

    [Fact]
    public void Throws_when_api_key_is_empty()
    {
        Assert.Throws<ArgumentException>(() => new SafeNestClient(""));
    }

    [Fact]
    public void Throws_when_api_key_too_short()
    {
        Assert.Throws<ArgumentException>(() => new SafeNestClient("abc"));
    }

    [Fact]
    public void Throws_when_timeout_out_of_range()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new SafeNestClient("test-api-key-1234", new SafeNestOptions { Timeout = 500 }));
    }

    [Fact]
    public void Throws_when_retries_out_of_range()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new SafeNestClient("test-api-key-1234", new SafeNestOptions { Retries = 11 }));
    }

    [Fact]
    public void Creates_client_with_valid_params()
    {
        using var client = new SafeNestClient("test-api-key-1234");
        Assert.NotNull(client);
    }

    [Fact]
    public void Creates_client_with_custom_http_client()
    {
        var httpClient = new HttpClient { BaseAddress = new Uri("https://example.com") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient);
        Assert.NotNull(client);
    }
}

// =============================================================================
// Bullying Detection Tests
// =============================================================================

public class BullyingDetectionTests
{
    [Fact]
    public async Task DetectBullying_returns_result()
    {
        var handler = MockHandler.WithJson(new
        {
            is_bullying = true,
            bullying_type = new[] { "verbal" },
            confidence = 0.95,
            severity = "high",
            rationale = "Contains insults",
            recommended_action = "flag_for_moderator",
            risk_score = 0.85,
            external_id = "ext-1",
            customer_id = "cust-1"
        }, headers: new Dictionary<string, string>
        {
            ["x-request-id"] = "req-123",
            ["x-monthly-limit"] = "10000",
            ["x-monthly-used"] = "50",
            ["x-monthly-remaining"] = "9950",
            ["x-ratelimit-limit"] = "300",
            ["x-ratelimit-remaining"] = "299",
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        var result = await client.DetectBullyingAsync(new DetectBullyingInput
        {
            Content = "you are stupid and ugly",
            ExternalId = "ext-1",
            CustomerId = "cust-1"
        });

        Assert.True(result.IsBullying);
        Assert.Contains("verbal", result.BullyingType);
        Assert.Equal(0.95, result.Confidence);
        Assert.Equal(Severity.High, result.Severity);
        Assert.Equal("ext-1", result.ExternalId);
        Assert.Equal("cust-1", result.CustomerId);
        Assert.Equal("req-123", client.LastRequestId);
        Assert.NotNull(client.Usage);
        Assert.Equal(10000, client.Usage!.Limit);
        Assert.Equal(50, client.Usage.Used);
        Assert.NotNull(client.RateLimit);
    }

    [Fact]
    public async Task DetectBullying_sends_context_and_tracking()
    {
        var handler = MockHandler.WithJson(new
        {
            is_bullying = false, bullying_type = Array.Empty<string>(), confidence = 0.1,
            severity = "low", rationale = "", recommended_action = "none", risk_score = 0.05
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        await client.DetectBullyingAsync(new DetectBullyingInput
        {
            Content = "hello friend",
            Context = new AnalysisContext { Language = "en", AgeGroup = "7-10", Platform = "chat" },
            ExternalId = "ext-1",
            CustomerId = "cust-1",
            Metadata = new Dictionary<string, object> { ["key"] = "value" }
        });

        Assert.Single(handler.Requests);
        var request = handler.Requests[0];
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("/api/v1/safety/bullying", request.RequestUri?.AbsolutePath);

        var body = await request.Content!.ReadAsStringAsync();
        Assert.Contains("\"text\"", body);
        Assert.Contains("\"external_id\"", body);
        Assert.Contains("\"customer_id\"", body);
        Assert.Contains("\"context\"", body);
        Assert.Contains("\"metadata\"", body);
    }

    [Fact]
    public async Task DetectBullying_validates_empty_content()
    {
        using var client = new SafeNestClient("test-api-key-1234");
        await Assert.ThrowsAsync<ValidationException>(() =>
            client.DetectBullyingAsync(new DetectBullyingInput { Content = "" }));
    }

    [Fact]
    public async Task DetectBullying_validates_content_too_long()
    {
        using var client = new SafeNestClient("test-api-key-1234");
        await Assert.ThrowsAsync<ValidationException>(() =>
            client.DetectBullyingAsync(new DetectBullyingInput { Content = new string('x', 50_001) }));
    }
}

// =============================================================================
// Grooming Detection Tests
// =============================================================================

public class GroomingDetectionTests
{
    [Fact]
    public async Task DetectGrooming_returns_result()
    {
        var handler = MockHandler.WithJson(new
        {
            grooming_risk = "high",
            flags = new[] { "age_inquiry", "isolation_attempt" },
            confidence = 0.88,
            rationale = "Suspicious patterns",
            risk_score = 0.82,
            recommended_action = "immediate_intervention"
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        var result = await client.DetectGroomingAsync(new DetectGroomingInput
        {
            Messages = new List<GroomingMessage>
            {
                new(MessageRole.Unknown, "hey how old are you?"),
                new(MessageRole.Child, "I'm 12"),
            },
            ChildAge = 12,
            Context = new AnalysisContext { Platform = "Discord" }
        });

        Assert.Equal(GroomingRisk.High, result.GroomingRisk);
        Assert.Contains("age_inquiry", result.Flags);
        Assert.Equal(0.88, result.Confidence);
    }

    [Fact]
    public async Task DetectGrooming_validates_empty_messages()
    {
        using var client = new SafeNestClient("test-api-key-1234");
        await Assert.ThrowsAsync<ValidationException>(() =>
            client.DetectGroomingAsync(new DetectGroomingInput()));
    }

    [Fact]
    public async Task DetectGrooming_validates_too_many_messages()
    {
        using var client = new SafeNestClient("test-api-key-1234");
        var messages = Enumerable.Range(0, 101)
            .Select(i => new GroomingMessage(MessageRole.Child, $"msg {i}"))
            .ToList();
        await Assert.ThrowsAsync<ValidationException>(() =>
            client.DetectGroomingAsync(new DetectGroomingInput { Messages = messages }));
    }
}

// =============================================================================
// Unsafe Content Detection Tests
// =============================================================================

public class UnsafeDetectionTests
{
    [Fact]
    public async Task DetectUnsafe_returns_result()
    {
        var handler = MockHandler.WithJson(new
        {
            @unsafe = true,
            categories = new[] { "violence" },
            severity = "medium",
            confidence = 0.75,
            risk_score = 0.6,
            rationale = "Contains violent language",
            recommended_action = "monitor"
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        var result = await client.DetectUnsafeAsync(new DetectUnsafeInput
        {
            Content = "some text",
            CustomerId = "tenant-42"
        });

        Assert.True(result.Unsafe);
        Assert.Contains("violence", result.Categories);
        Assert.Equal(Severity.Medium, result.Severity);
    }
}

// =============================================================================
// Emotion Analysis Tests
// =============================================================================

public class EmotionAnalysisTests
{
    [Fact]
    public async Task AnalyzeEmotions_with_content()
    {
        var handler = MockHandler.WithJson(new
        {
            dominant_emotions = new[] { "sadness", "anxiety" },
            emotion_scores = new Dictionary<string, double> { ["sadness"] = 0.8, ["anxiety"] = 0.6 },
            trend = "worsening",
            summary = "Shows signs of distress",
            recommended_followup = "Check in with child"
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        var result = await client.AnalyzeEmotionsAsync(new AnalyzeEmotionsInput
        {
            Content = "I feel sad and alone"
        });

        Assert.Contains("sadness", result.DominantEmotions);
        Assert.Equal(EmotionTrend.Worsening, result.Trend);
    }

    [Fact]
    public async Task AnalyzeEmotions_with_messages()
    {
        var handler = MockHandler.WithJson(new
        {
            dominant_emotions = new[] { "joy" },
            trend = "improving",
            summary = "Positive",
            recommended_followup = "None"
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        var result = await client.AnalyzeEmotionsAsync(new AnalyzeEmotionsInput
        {
            Messages = new List<EmotionMessage>
            {
                new("alice", "I had a great day!"),
                new("bob", "That's awesome!")
            }
        });

        Assert.Equal(EmotionTrend.Improving, result.Trend);
    }
}

// =============================================================================
// Action Plan Tests
// =============================================================================

public class ActionPlanTests
{
    [Fact]
    public async Task GetActionPlan_returns_result()
    {
        var handler = MockHandler.WithJson(new
        {
            audience = "parent",
            steps = new[] { "Step 1", "Step 2", "Step 3" },
            tone = "empathetic",
            approx_reading_level = "grade 8"
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        var result = await client.GetActionPlanAsync(new GetActionPlanInput
        {
            Situation = "Child being bullied at school",
            ChildAge = 10,
            Audience = Audience.Parent,
            Severity = Severity.Medium
        });

        Assert.Equal(3, result.Steps.Count);
        Assert.Equal("empathetic", result.Tone);
    }

    [Fact]
    public async Task GetActionPlan_sends_correct_body()
    {
        var handler = MockHandler.WithJson(new
        {
            audience = "educator", steps = new[] { "Step 1" }, tone = "professional"
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        await client.GetActionPlanAsync(new GetActionPlanInput
        {
            Situation = "test",
            Audience = Audience.Educator,
            Severity = Severity.High,
            ExternalId = "ext-1"
        });

        var body = await handler.Requests[0].Content!.ReadAsStringAsync();
        Assert.Contains("\"role\"", body);
        Assert.Contains("educator", body);
        Assert.Contains("\"severity\"", body);
        Assert.Contains("high", body);
        Assert.Contains("\"external_id\"", body);
    }
}

// =============================================================================
// Report Generation Tests
// =============================================================================

public class ReportTests
{
    [Fact]
    public async Task GenerateReport_returns_result()
    {
        var handler = MockHandler.WithJson(new
        {
            summary = "Incident involving verbal harassment",
            risk_level = "high",
            categories = new[] { "harassment" },
            recommended_next_steps = new[] { "Contact parent", "Notify school" }
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        var result = await client.GenerateReportAsync(new GenerateReportInput
        {
            Messages = new List<ReportMessage>
            {
                new("bully", "You're so dumb"),
                new("victim", "Please stop")
            },
            ChildAge = 11,
            IncidentType = "harassment"
        });

        Assert.Equal(RiskLevel.High, result.RiskLevel);
        Assert.Equal(2, result.RecommendedNextSteps.Count);
    }
}

// =============================================================================
// Analyze (Combined) Tests
// =============================================================================

public class AnalyzeTests
{
    [Fact]
    public async Task Analyze_combines_bullying_and_unsafe()
    {
        int callCount = 0;
        var handler = new MockHandler(req =>
        {
            callCount++;
            var path = req.RequestUri?.AbsolutePath ?? "";
            string json;

            if (path.Contains("bullying"))
            {
                json = JsonSerializer.Serialize(new
                {
                    is_bullying = true,
                    bullying_type = new[] { "verbal" },
                    confidence = 0.9,
                    severity = "high",
                    rationale = "Insults",
                    recommended_action = "flag_for_moderator",
                    risk_score = 0.8
                });
            }
            else
            {
                json = JsonSerializer.Serialize(new
                {
                    @unsafe = false,
                    categories = Array.Empty<string>(),
                    severity = "low",
                    confidence = 0.2,
                    risk_score = 0.1,
                    rationale = "",
                    recommended_action = "none"
                });
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        var result = await client.AnalyzeAsync("test content");

        Assert.Equal(2, callCount);
        Assert.Equal(RiskLevel.High, result.RiskLevel);
        Assert.Equal(0.8, result.RiskScore);
        Assert.NotNull(result.Bullying);
        Assert.True(result.Bullying!.IsBullying);
        Assert.NotNull(result.Unsafe);
        Assert.Contains("Bullying detected", result.Summary);
    }

    [Fact]
    public async Task Analyze_with_tracking_fields()
    {
        var handler = MockHandler.WithJson(new
        {
            is_bullying = false, bullying_type = Array.Empty<string>(), confidence = 0.1,
            severity = "low", rationale = "", recommended_action = "none", risk_score = 0.05
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        var result = await client.AnalyzeAsync(new AnalyzeInput
        {
            Content = "hello",
            Include = new List<string> { "bullying" },
            ExternalId = "ext-1",
            CustomerId = "cust-1"
        });

        Assert.Equal("ext-1", result.ExternalId);
        Assert.Equal("cust-1", result.CustomerId);
    }
}

// =============================================================================
// Error Handling Tests
// =============================================================================

public class ErrorHandlingTests
{
    [Fact]
    public async Task Throws_AuthenticationException_on_401()
    {
        var handler = MockHandler.WithError(HttpStatusCode.Unauthorized, "Invalid API key", "AUTH_1001");
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        var ex = await Assert.ThrowsAsync<AuthenticationException>(() =>
            client.DetectBullyingAsync(new DetectBullyingInput { Content = "test" }));
        Assert.Equal(401, ex.StatusCode);
        Assert.Equal("AUTH_1001", ex.Code);
    }

    [Fact]
    public async Task Throws_ValidationException_on_400()
    {
        var handler = MockHandler.WithError(HttpStatusCode.BadRequest, "Invalid input", "VAL_2001");
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        var ex = await Assert.ThrowsAsync<ValidationException>(() =>
            client.DetectBullyingAsync(new DetectBullyingInput { Content = "test" }));
        Assert.Equal(400, ex.StatusCode);
    }

    [Fact]
    public async Task Throws_TierAccessException_on_403()
    {
        var handler = MockHandler.WithError(HttpStatusCode.Forbidden, "Upgrade required");
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        await Assert.ThrowsAsync<TierAccessException>(() =>
            client.DetectBullyingAsync(new DetectBullyingInput { Content = "test" }));
    }

    [Fact]
    public async Task Throws_NotFoundException_on_404()
    {
        var handler = MockHandler.WithError(HttpStatusCode.NotFound, "Not found");
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        await Assert.ThrowsAsync<NotFoundException>(() =>
            client.DetectBullyingAsync(new DetectBullyingInput { Content = "test" }));
    }

    [Fact]
    public async Task Throws_RateLimitException_on_429()
    {
        var handler = MockHandler.WithError((HttpStatusCode)429, "Rate limit exceeded", "RATE_3001");
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        await Assert.ThrowsAsync<RateLimitException>(() =>
            client.DetectBullyingAsync(new DetectBullyingInput { Content = "test" }));
    }

    [Fact]
    public async Task Throws_ServerException_on_500()
    {
        var handler = MockHandler.WithError(HttpStatusCode.InternalServerError, "Internal error");
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient, new SafeNestOptions { Retries = 0 });

        var ex = await Assert.ThrowsAsync<ServerException>(() =>
            client.DetectBullyingAsync(new DetectBullyingInput { Content = "test" }));
        Assert.Equal(500, ex.StatusCode);
    }
}

// =============================================================================
// Enum Extension Tests
// =============================================================================

public class EnumTests
{
    [Theory]
    [InlineData("low", Severity.Low)]
    [InlineData("medium", Severity.Medium)]
    [InlineData("high", Severity.High)]
    [InlineData("critical", Severity.Critical)]
    [InlineData("unknown", Severity.Low)]
    [InlineData(null, Severity.Low)]
    public void ParseSeverity(string? input, Severity expected)
    {
        Assert.Equal(expected, EnumExtensions.ParseSeverity(input));
    }

    [Theory]
    [InlineData("none", GroomingRisk.None)]
    [InlineData("low", GroomingRisk.Low)]
    [InlineData("high", GroomingRisk.High)]
    [InlineData("critical", GroomingRisk.Critical)]
    [InlineData(null, GroomingRisk.None)]
    public void ParseGroomingRisk(string? input, GroomingRisk expected)
    {
        Assert.Equal(expected, EnumExtensions.ParseGroomingRisk(input));
    }

    [Theory]
    [InlineData("safe", RiskLevel.Safe)]
    [InlineData("moderate", RiskLevel.Medium)]
    [InlineData("critical", RiskLevel.Critical)]
    [InlineData(null, RiskLevel.Safe)]
    public void ParseRiskLevel(string? input, RiskLevel expected)
    {
        Assert.Equal(expected, EnumExtensions.ParseRiskLevel(input));
    }

    [Theory]
    [InlineData("improving", EmotionTrend.Improving)]
    [InlineData("stable", EmotionTrend.Stable)]
    [InlineData("worsening", EmotionTrend.Worsening)]
    [InlineData(null, EmotionTrend.Stable)]
    public void ParseEmotionTrend(string? input, EmotionTrend expected)
    {
        Assert.Equal(expected, EnumExtensions.ParseEmotionTrend(input));
    }

    [Fact]
    public void ToApiString_round_trips()
    {
        Assert.Equal("high", Severity.High.ToApiString());
        Assert.Equal("critical", GroomingRisk.Critical.ToApiString());
        Assert.Equal("safe", RiskLevel.Safe.ToApiString());
        Assert.Equal("educator", Audience.Educator.ToApiString());
        Assert.Equal("child", MessageRole.Child.ToApiString());
        Assert.Equal("grooming.detected", WebhookEventType.GroomingDetected.ToApiString());
    }
}

// =============================================================================
// Retry Tests
// =============================================================================

public class RetryTests
{
    [Fact]
    public async Task Retries_on_server_error()
    {
        int callCount = 0;
        var handler = new MockHandler(_ =>
        {
            callCount++;
            if (callCount <= 2)
            {
                return new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent("{\"error\":{\"message\":\"Internal error\"}}", Encoding.UTF8, "application/json")
                };
            }
            var json = JsonSerializer.Serialize(new
            {
                is_bullying = false, bullying_type = Array.Empty<string>(), confidence = 0.1,
                severity = "low", rationale = "", recommended_action = "none", risk_score = 0.05
            });
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient,
            new SafeNestOptions { Retries = 3, RetryDelay = 10 });

        var result = await client.DetectBullyingAsync(new DetectBullyingInput { Content = "test" });
        Assert.False(result.IsBullying);
        Assert.Equal(3, callCount);
    }

    [Fact]
    public async Task Does_not_retry_on_auth_error()
    {
        int callCount = 0;
        var handler = new MockHandler(_ =>
        {
            callCount++;
            return new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Content = new StringContent("{\"error\":{\"message\":\"Invalid API key\"}}", Encoding.UTF8, "application/json")
            };
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.safenest.dev") };
        using var client = new SafeNestClient("test-api-key-1234", httpClient,
            new SafeNestOptions { Retries = 3, RetryDelay = 10 });

        await Assert.ThrowsAsync<AuthenticationException>(() =>
            client.DetectBullyingAsync(new DetectBullyingInput { Content = "test" }));
        Assert.Equal(1, callCount);
    }
}
