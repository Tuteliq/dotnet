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
