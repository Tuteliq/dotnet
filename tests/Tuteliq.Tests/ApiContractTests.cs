using System.Text.Json;
using Xunit;

namespace Tuteliq.Tests;

// =============================================================================
// Contract tests: request paths, methods and bodies, and responses shaped like
// the ones the API returns. All values are invented.
// =============================================================================

internal static class TestClient
{
    public static TuteliqClient Create(MockHandler handler)
    {
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.tuteliq.ai") };
        return new TuteliqClient("test-api-key-1234", httpClient, new TuteliqOptions { Retries = 0 });
    }

    public static JsonElement Body(MockHandler handler, int index = 0)
        => JsonDocument.Parse(handler.RequestBodies[index]).RootElement;
}

public class VerificationSessionContractTests
{
    private const string CreatedSessionJson = """
        {
          "chip_policy": "optional",
          "auto_capture": true,
          "session_id": "sess_7f3a9c",
          "mobile_url": "https://verify.tuteliq.ai/age/?session=sess_7f3a9c&token=tok_example",
          "expires_at": 1767225599000,
          "mode": "age",
          "verification_mode": "full",
          "recommended_image_width": 2560
        }
        """;

    [Fact]
    public async Task Create_parses_numeric_expires_at()
    {
        var handler = MockHandler.WithRawJson(CreatedSessionJson, System.Net.HttpStatusCode.Created);
        using var client = TestClient.Create(handler);

        var result = await client.CreateVerificationSessionAsync(new CreateVerificationSessionInput { Mode = VerificationMode.Age });

        Assert.Equal("sess_7f3a9c", result.SessionId);
        Assert.Equal("1767225599000", result.ExpiresAt.ToString());
    }

    [Fact]
    public async Task Create_sends_national_id_for_the_id_card_document_type()
    {
        var handler = MockHandler.WithRawJson(CreatedSessionJson, System.Net.HttpStatusCode.Created);
        using var client = TestClient.Create(handler);

#pragma warning disable CS0618
        await client.CreateVerificationSessionAsync(new CreateVerificationSessionInput
        {
            Mode = VerificationMode.Identity,
            DocumentType = DocumentType.IdCard,
        });
#pragma warning restore CS0618

        Assert.Equal("national_id", TestClient.Body(handler).GetProperty("document_type").GetString());
    }

    [Fact]
    public async Task Create_does_not_send_fields_the_api_ignores()
    {
        var handler = MockHandler.WithRawJson(CreatedSessionJson, System.Net.HttpStatusCode.Created);
        using var client = TestClient.Create(handler);

#pragma warning disable CS0618
        await client.CreateVerificationSessionAsync(new CreateVerificationSessionInput
        {
            Mode = VerificationMode.Age,
            RedirectUrl = "https://example.com/done",
            ExternalId = "ext-1",
            CustomerId = "cust-1",
            Metadata = new Dictionary<string, object> { ["k"] = "v" },
        });
#pragma warning restore CS0618

        var body = TestClient.Body(handler);
        Assert.False(body.TryGetProperty("redirect_url", out _));
        Assert.False(body.TryGetProperty("external_id", out _));
        Assert.False(body.TryGetProperty("customer_id", out _));
        Assert.False(body.TryGetProperty("metadata", out _));
        Assert.Equal("POST", handler.Requests[0].Method.Method);
        Assert.Equal("/api/v1/verify/session", handler.Requests[0].RequestUri?.AbsolutePath);
    }

    [Fact]
    public async Task Poll_parses_numeric_timestamps()
    {
        var handler = MockHandler.WithRawJson("""
            {
              "session_id": "sess_7f3a9c",
              "status": "pending",
              "result": null,
              "step_progress": null,
              "chip_policy": "optional",
              "created_at": 1767224699000,
              "expires_at": 1767225599000
            }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.GetVerificationSessionAsync("sess_7f3a9c");

        Assert.Equal("1767224699000", result.CreatedAt?.ToString());
        Assert.Equal("1767225599000", result.ExpiresAt?.ToString());
    }

    [Fact]
    public async Task Poll_reads_document_required_as_its_own_status()
    {
        var handler = MockHandler.WithRawJson("""
            { "session_id": "sess_7f3a9c", "status": "document_required", "result": null, "created_at": 1767224699000, "expires_at": 1767225599000 }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.GetVerificationSessionAsync("sess_7f3a9c");

        Assert.NotEqual(VerificationSessionStatus.Pending, result.Status);
        Assert.Equal("document_required", result.Status.ToApiString());
    }
}

public class WebhookContractTests
{
    [Fact]
    public async Task List_reads_is_active()
    {
        var handler = MockHandler.WithRawJson("""
            {
              "webhooks": [{
                "id": "wh_1", "name": "Moderation", "url": "https://example.com/hook",
                "events": ["incident.critical"], "is_active": true, "failure_count": 0,
                "last_triggered_at": null, "last_error": null,
                "created_at": "2026-01-01T00:00:00.000Z", "updated_at": "2026-01-01T00:00:00.000Z"
              }]
            }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.ListWebhooksAsync();

#pragma warning disable CS0618
        Assert.True(result.Webhooks[0].Active);
#pragma warning restore CS0618
    }

    [Fact]
    public async Task Create_does_not_send_active()
    {
        var handler = MockHandler.WithRawJson("""
            { "id": "wh_1", "name": "Moderation", "url": "https://example.com/hook", "secret": "whsec_example",
              "events": ["incident.critical"], "is_active": true, "created_at": "2026-01-01T00:00:00.000Z" }
            """, System.Net.HttpStatusCode.Created);
        using var client = TestClient.Create(handler);

        await client.CreateWebhookAsync(new CreateWebhookInput
        {
            Name = "Moderation",
            Url = "https://example.com/hook",
            Events = new List<string> { "incident.critical" },
        });

        var body = TestClient.Body(handler);
        Assert.False(body.TryGetProperty("active", out _));
        Assert.Equal("/api/v1/webhooks", handler.Requests[0].RequestUri?.AbsolutePath);
    }

    [Fact]
    public async Task Update_uses_put_and_sends_is_active()
    {
        var handler = MockHandler.WithRawJson("""
            { "id": "wh_1", "name": "Moderation", "url": "https://example.com/hook",
              "events": ["incident.critical"], "is_active": false, "updated_at": "2026-01-02T00:00:00.000Z" }
            """);
        using var client = TestClient.Create(handler);

#pragma warning disable CS0618
        await client.UpdateWebhookAsync("wh_1", new UpdateWebhookInput { Active = false });
#pragma warning restore CS0618

        Assert.Equal(HttpMethod.Put, handler.Requests[0].Method);
        Assert.Equal("/api/v1/webhooks/wh_1", handler.Requests[0].RequestUri?.AbsolutePath);
        var body = TestClient.Body(handler);
        Assert.False(body.GetProperty("is_active").GetBoolean());
        Assert.False(body.TryGetProperty("active", out _));
    }

    [Fact]
    public async Task Test_posts_the_webhook_id_to_the_test_route()
    {
        var handler = MockHandler.WithRawJson("""
            { "success": true, "status_code": 200, "latency_ms": 142 }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.TestWebhookAsync("wh_1");

        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal("/api/v1/webhooks/test", handler.Requests[0].RequestUri?.AbsolutePath);
        Assert.Equal("wh_1", TestClient.Body(handler).GetProperty("webhook_id").GetString());
        Assert.Equal(200, result.StatusCode);
    }

    [Fact]
    public async Task Regenerate_secret_calls_the_regenerate_route()
    {
        var handler = MockHandler.WithRawJson("""{ "secret": "whsec_rotated_example" }""");
        using var client = TestClient.Create(handler);

        var result = await client.RegenerateWebhookSecretAsync("wh_1");

        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal("/api/v1/webhooks/wh_1/regenerate-secret", handler.Requests[0].RequestUri?.AbsolutePath);
        Assert.Equal("whsec_rotated_example", result.Secret);
    }
}

public class LanguageContractTests
{
    [Fact]
    public void Language_lists_every_supported_code()
    {
        var expected = new[]
        {
            "en", "es", "pt", "uk", "sv", "no", "da", "fi", "de", "fr", "nl", "pl", "it", "tr", "ro", "el",
            "cs", "hu", "bg", "hr", "sk", "lt", "lv", "et", "sl", "mt", "ga", "zh", "ja", "ko", "ar", "ru",
        };

        var actual = Enum.GetValues<Language>().Select(l => l.ToApiString()).ToArray();

        Assert.Equal(expected.OrderBy(c => c), actual.OrderBy(c => c));
    }
}

public class VerificationSessionFieldTests
{
    [Fact]
    public async Task Create_sends_chip_policy_and_auto_capture_and_reads_the_new_response_fields()
    {
        var handler = MockHandler.WithRawJson("""
            {
              "chip_policy": "instead_of_photo", "auto_capture": false, "session_id": "sess_7f3a9c",
              "mobile_url": "https://verify.tuteliq.ai/identity/?session=sess_7f3a9c&token=tok_example",
              "expires_at": 1767225599000, "mode": "identity", "verification_mode": "full", "recommended_image_width": 2560
            }
            """, System.Net.HttpStatusCode.Created);
        using var client = TestClient.Create(handler);

        var result = await client.CreateVerificationSessionAsync(new CreateVerificationSessionInput
        {
            Mode = VerificationMode.Identity,
            DocumentType = DocumentType.NationalId,
            ChipPolicy = ChipPolicy.InsteadOfPhoto,
            AutoCapture = false,
        });

        var body = TestClient.Body(handler);
        Assert.Equal("identity", body.GetProperty("mode").GetString());
        Assert.Equal("national_id", body.GetProperty("document_type").GetString());
        Assert.Equal("instead_of_photo", body.GetProperty("chip_policy").GetString());
        Assert.False(body.GetProperty("auto_capture").GetBoolean());

        Assert.Equal(1767225599000L, result.ExpiresAt);
        Assert.Equal("instead_of_photo", result.ChipPolicy);
        Assert.False(result.AutoCapture);
        Assert.Equal("full", result.VerificationCheck);
        Assert.Equal(2560, result.RecommendedImageWidth);
        Assert.Equal(VerificationMode.Identity, result.Mode);
    }

    [Fact]
    public async Task Create_omits_chip_policy_and_auto_capture_when_unset()
    {
        var handler = MockHandler.WithRawJson("""{ "session_id": "s", "mobile_url": "u", "expires_at": 1, "mode": "age" }""");
        using var client = TestClient.Create(handler);

        await client.CreateVerificationSessionAsync(new CreateVerificationSessionInput { Mode = VerificationMode.Age });

        var body = TestClient.Body(handler);
        Assert.False(body.TryGetProperty("chip_policy", out _));
        Assert.False(body.TryGetProperty("auto_capture", out _));
        Assert.False(body.TryGetProperty("document_type", out _));
    }

    [Fact]
    public async Task Poll_reads_a_completed_result_with_match_score()
    {
        var handler = MockHandler.WithRawJson("""
            {
              "session_id": "sess_7f3a9c",
              "status": "completed",
              "result": {
                "status": "verified", "age": 34, "age_range": null, "is_minor": false,
                "document_evidence": "photo_and_chip",
                "face_match": { "matched": true, "confidence": 0.58, "match_score": 0.91 },
                "liveness": { "valid": true },
                "date_of_birth": "1992-03-14",
                "failure_reasons": [],
                "document": {
                  "ocr_confidence": 92.5, "first_name": "Alex", "last_name": "Example",
                  "document_type": "passport", "country_code": "SE", "chip_verified": true,
                  "chip_issuer_trusted": null,
                  "national_id": { "value": "000000-0000", "valid": false, "type": "personal_number", "country_code": "SE" }
                }
              },
              "verification_mode": "full",
              "document_evidence": "photo_and_chip",
              "step_progress": "done",
              "chip_policy": "optional",
              "capture": null,
              "created_at": 1767224699000,
              "expires_at": 1767225599000
            }
            """);
        using var client = TestClient.Create(handler);

        var session = await client.GetVerificationSessionAsync("sess_7f3a9c");
        var result = session.GetResult();

        Assert.Equal(VerificationSessionStatus.Completed, session.Status);
        Assert.Equal(1767224699000L, session.CreatedAt);
        Assert.Equal("full", session.VerificationCheck);
        Assert.Equal("photo_and_chip", session.DocumentEvidence);
        Assert.Equal("done", session.StepProgress);
        Assert.Equal("/api/v1/verify/session/sess_7f3a9c", handler.Requests[0].RequestUri?.AbsolutePath);

        Assert.NotNull(result);
        Assert.Equal(VerificationStatus.Verified, result!.Status);
        Assert.Equal(34, result.Age);
        Assert.False(result.IsMinor);
        Assert.True(result.FaceMatch!.Matched);
        Assert.Equal(0.91, result.FaceMatch.MatchScore);
        Assert.Null(result.FaceMatch.Distance);
        Assert.True(result.Liveness!.Valid);
        Assert.Equal("SE", result.Document!.CountryCode);
        Assert.True(result.Document.ChipVerified);
        Assert.Null(result.Document.ChipIssuerTrusted);
        Assert.False(result.Document.NationalId!.Valid);
    }

    [Fact]
    public async Task Poll_without_a_result_returns_null_from_GetResult()
    {
        var handler = MockHandler.WithRawJson("""{ "session_id": "s", "status": "in_progress", "result": null, "created_at": 1, "expires_at": 2 }""");
        using var client = TestClient.Create(handler);

        var session = await client.GetVerificationSessionAsync("s");

        Assert.Equal(VerificationSessionStatus.InProgress, session.Status);
        Assert.Null(session.GetResult());
    }
}

public class WebhookFieldTests
{
    [Fact]
    public async Task Create_sends_name_and_reads_the_flat_response()
    {
        var handler = MockHandler.WithRawJson("""
            { "id": "wh_1", "name": "Moderation", "url": "https://example.com/hook", "secret": "whsec_example",
              "events": ["incident.critical", "verification.completed"], "is_active": true, "created_at": "2026-01-01T00:00:00.000Z" }
            """, System.Net.HttpStatusCode.Created);
        using var client = TestClient.Create(handler);

        var result = await client.CreateWebhookAsync(new CreateWebhookInput
        {
            Name = "Moderation",
            Url = "https://example.com/hook",
            Events = new List<string> { WebhookEvents.IncidentCritical, WebhookEvents.VerificationCompleted },
            Headers = new Dictionary<string, string> { ["X-Env"] = "test" },
        });

        var body = TestClient.Body(handler);
        Assert.Equal("Moderation", body.GetProperty("name").GetString());
        Assert.Equal("verification.completed", body.GetProperty("events")[1].GetString());
        Assert.Equal("test", body.GetProperty("headers").GetProperty("X-Env").GetString());
        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);

        Assert.Equal("wh_1", result.Id);
        Assert.Equal("whsec_example", result.Secret);
        Assert.True(result.IsActive);
    }

    [Fact]
    public async Task Create_requires_a_name()
    {
        var handler = MockHandler.WithRawJson("{}");
        using var client = TestClient.Create(handler);

        await Assert.ThrowsAsync<ValidationException>(() => client.CreateWebhookAsync(new CreateWebhookInput
        {
            Url = "https://example.com/hook",
            Events = new List<string> { WebhookEvents.IncidentCritical },
        }));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task List_reads_name_failure_count_and_is_active()
    {
        var handler = MockHandler.WithRawJson("""
            { "webhooks": [{ "id": "wh_1", "name": "Moderation", "url": "https://example.com/hook", "events": ["csam.critical"],
              "is_active": true, "failure_count": 3, "last_triggered_at": "2026-01-03T00:00:00.000Z", "last_error": "timeout",
              "created_at": "2026-01-01T00:00:00.000Z", "updated_at": "2026-01-02T00:00:00.000Z" }] }
            """);
        using var client = TestClient.Create(handler);

        var hook = (await client.ListWebhooksAsync()).Webhooks[0];

        Assert.Equal("Moderation", hook.Name);
        Assert.True(hook.IsActive);
        Assert.Equal(3, hook.FailureCount);
        Assert.Equal("timeout", hook.LastError);
    }

    [Fact]
    public async Task Update_sends_only_the_fields_set_and_reads_the_flat_response()
    {
        var handler = MockHandler.WithRawJson("""
            { "id": "wh_1", "name": "Renamed", "url": "https://example.com/hook", "events": ["incident.high"], "is_active": true, "updated_at": "2026-01-02T00:00:00.000Z" }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.UpdateWebhookAsync("wh_1", new UpdateWebhookInput { Name = "Renamed", IsActive = true });

        var body = TestClient.Body(handler);
        Assert.Equal("Renamed", body.GetProperty("name").GetString());
        Assert.True(body.GetProperty("is_active").GetBoolean());
        Assert.False(body.TryGetProperty("url", out _));
        Assert.Equal("Renamed", result.Name);
        Assert.True(result.IsActive);
    }

    [Fact]
    public async Task Delete_reads_success()
    {
        var handler = MockHandler.WithRawJson("""{ "success": true, "message": "Webhook deleted successfully" }""");
        using var client = TestClient.Create(handler);

        var result = await client.DeleteWebhookAsync("wh_1");

        Assert.True(result.Success);
        Assert.Equal(HttpMethod.Delete, handler.Requests[0].Method);
        Assert.Equal("/api/v1/webhooks/wh_1", handler.Requests[0].RequestUri?.AbsolutePath);
    }

    [Fact]
    public async Task Test_reads_a_failed_delivery()
    {
        var handler = MockHandler.WithRawJson("""{ "success": false, "status_code": 500, "latency_ms": 87, "error": "HTTP 500" }""");
        using var client = TestClient.Create(handler);

        var result = await client.TestWebhookAsync("wh_1");

        Assert.False(result.Success);
        Assert.Equal(500, result.StatusCode);
        Assert.Equal(87, result.LatencyMs);
        Assert.Equal("HTTP 500", result.Error);
    }

    [Theory]
    [InlineData(WebhookEventType.IncidentCritical, "incident.critical")]
    [InlineData(WebhookEventType.IncidentHigh, "incident.high")]
    [InlineData(WebhookEventType.GroomingDetected, "grooming.detected")]
    [InlineData(WebhookEventType.SelfHarmDetected, "self_harm.detected")]
    [InlineData(WebhookEventType.BullyingSevere, "bullying.severe")]
    [InlineData(WebhookEventType.VerificationCompleted, "verification.completed")]
    [InlineData(WebhookEventType.MinorDetected, "minor.detected")]
    [InlineData(WebhookEventType.CsamDetected, "csam.detected")]
    [InlineData(WebhookEventType.CsamCritical, "csam.critical")]
    public void WebhookEventType_matches_the_api(WebhookEventType type, string expected)
    {
        Assert.Equal(expected, type.ToApiString());
    }

    [Fact]
    public void Every_webhook_event_type_is_covered()
    {
        Assert.Equal(9, Enum.GetValues<WebhookEventType>().Length);
    }
}

public class VoiceStreamUriTests
{
    [Fact]
    public void Default_url_is_the_versioned_safety_route()
    {
        Assert.Equal("wss://api.tuteliq.ai/api/v1/safety/voice/stream", VoiceStreamSession.BuildUri(null).ToString());
    }

    [Theory]
    [InlineData("https://api.tuteliq.ai", "wss://api.tuteliq.ai/api/v1/safety/voice/stream")]
    [InlineData("https://api.tuteliq.ai/", "wss://api.tuteliq.ai/api/v1/safety/voice/stream")]
    [InlineData("http://localhost:3000", "ws://localhost:3000/api/v1/safety/voice/stream")]
    [InlineData("https://staging.example.com:8443", "wss://staging.example.com:8443/api/v1/safety/voice/stream")]
    public void Url_follows_the_client_base_url(string baseUrl, string expected)
    {
        Assert.Equal(expected, VoiceStreamSession.BuildUri(new Uri(baseUrl)).ToString());
    }
}
