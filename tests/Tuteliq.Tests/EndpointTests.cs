using System.Net;
using Xunit;

namespace Tuteliq.Tests;

// =============================================================================
// Endpoints added to match the current API. All values are invented.
// =============================================================================

public class IncidentTests
{
    private const string IncidentRowJson = """
        {
          "id": "inc_1", "risk_category": "grooming", "risk_level": "high", "confidence_score": 0.82,
          "detected_patterns": ["secrecy"], "recommended_actions": ["flag_for_moderator"], "platform": "ExampleChat",
          "language": "en", "source": "text", "file_id": null, "status": "new", "policy_action": null,
          "recommended_status": "reviewed", "escalation_capped": null, "escalation_capped_reason": null,
          "speaker_stance": null, "action_capped": null, "action_capped_reason": null, "is_test": true,
          "external_id": "ext-1", "customer_id": null, "created_at": "2026-05-01T10:00:00.000Z"
        }
        """;

    [Fact]
    public async Task List_sends_filters_and_reads_a_page()
    {
        var handler = MockHandler.WithRawJson($$"""
            { "incidents": [{{IncidentRowJson}}], "next_cursor": "cur_2", "total_returned": 1 }
            """);
        using var client = TestClient.Create(handler);

        var page = await client.ListIncidentsAsync(new ListIncidentsInput
        {
            Category = "grooming",
            Severity = "high",
            Status = "new",
            From = "2026-05-01T00:00:00Z",
            ExternalId = "ext 1",
            Limit = 50,
            Cursor = "cur_1",
            IncludeSummary = true,
        });

        var uri = handler.Requests[0].RequestUri!;
        Assert.Equal(HttpMethod.Get, handler.Requests[0].Method);
        Assert.Equal("/api/v1/incidents", uri.AbsolutePath);
        Assert.Equal(
            "?category=grooming&severity=high&status=new&from=2026-05-01T00%3A00%3A00Z&external_id=ext%201&limit=50&cursor=cur_1&include_summary=true",
            uri.Query);

        Assert.Equal("cur_2", page.NextCursor);
        Assert.Equal(1, page.TotalReturned);
        var row = page.Incidents[0];
        Assert.Equal("inc_1", row.Id);
        Assert.Equal("grooming", row.RiskCategory);
        Assert.Equal("high", row.RiskLevel);
        Assert.Equal("reviewed", row.RecommendedStatus);
        Assert.True(row.IsTest);
        Assert.Null(row.PolicyAction);
    }

    [Fact]
    public async Task List_without_filters_sends_no_query()
    {
        var handler = MockHandler.WithRawJson("""{ "incidents": [], "next_cursor": null, "total_returned": 0 }""");
        using var client = TestClient.Create(handler);

        var page = await client.ListIncidentsAsync();

        Assert.Equal("", handler.Requests[0].RequestUri!.Query);
        Assert.Null(page.NextCursor);
    }

    [Fact]
    public async Task Get_reads_detail_with_message_analysis()
    {
        var detail = IncidentRowJson.TrimEnd().TrimEnd('}') + """
            , "summary": "Invented summary.", "review": null,
              "message_analysis": [{ "message_index": 0, "risk_score": 0.1, "flags": [] }, { "message_index": 1, "risk_score": 0.8, "flags": ["secrecy"] }]
            }
            """;
        var handler = MockHandler.WithRawJson(detail);
        using var client = TestClient.Create(handler);

        var incident = await client.GetIncidentAsync("inc_1");

        Assert.Equal("/api/v1/incidents/inc_1", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("Invented summary.", incident.Summary?.GetString());
        Assert.Equal(2, incident.MessageAnalysis!.Count);
        Assert.Equal(0.8, incident.MessageAnalysis[1].RiskScore);
    }

    [Fact]
    public async Task Overview_sends_the_window_and_reads_the_counts()
    {
        var handler = MockHandler.WithRawJson("""
            {
              "timeframe": { "from": "2026-04-01T00:00:00.000Z", "to": "2026-05-01T00:00:00.000Z" },
              "total_incidents": 40, "requires_review_count": 3, "last_24h_count": 2, "last_7d_count": 9, "last_30d_count": 40,
              "counts_by_category": { "bullying": 30, "grooming": 10 }, "counts_by_severity": { "high": 5 },
              "counts_by_source": { "text": 40 }, "counts_by_status": { "new": 12 },
              "top_platforms": [{ "platform": "ExampleChat", "count": 40 }]
            }
            """);
        using var client = TestClient.Create(handler);

        var overview = await client.GetIncidentsOverviewAsync(from: "2026-04-01T00:00:00Z");

        Assert.Equal("/api/v1/incidents/overview", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("?from=2026-04-01T00%3A00%3A00Z", handler.Requests[0].RequestUri!.Query);
        Assert.Equal(3, overview.RequiresReviewCount);
        Assert.Equal(10, overview.CountsByCategory["grooming"]);
        Assert.Equal("ExampleChat", overview.TopPlatforms[0].Platform);
    }

    [Fact]
    public async Task Trends_sends_the_bucket_and_reads_the_series()
    {
        var handler = MockHandler.WithRawJson("""
            {
              "bucket_size": "week",
              "timeframe": { "from": "2026-04-01T00:00:00.000Z", "to": "2026-05-01T00:00:00.000Z" },
              "series": [{ "bucket_start": "2026-04-06T00:00:00.000Z", "total": 7, "by_severity": { "low": 6, "critical": 1 } }]
            }
            """);
        using var client = TestClient.Create(handler);

        var trends = await client.GetIncidentTrendsAsync(bucket: "week");

        Assert.Equal("/api/v1/incidents/trends", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("?bucket=week", handler.Requests[0].RequestUri!.Query);
        Assert.Equal("week", trends.BucketSize);
        Assert.Equal(1, trends.Series[0].BySeverity["critical"]);
    }

    [Fact]
    public async Task Review_posts_the_decision_and_reads_the_receipt()
    {
        var handler = MockHandler.WithRawJson("""
            {
              "incident_id": "inc_1",
              "original": { "risk_category": "grooming", "risk_level": "high" },
              "revised": { "risk_category": "grooming", "risk_level": "low" },
              "audit_receipt": { "request_id": "req_1", "timestamp": "2026-05-02T00:00:00.000Z", "signature": "sig_example" }
            }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.ReviewIncidentAsync("inc_1", new ReviewIncidentInput
        {
            Action = ModeratorAction.Downgrade,
            ReasonCode = ModeratorReasonCode.InsufficientSeverity,
            NewRiskLevel = "low",
            ModeratorExternalId = "moderator-42",
        });

        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal("/api/v1/incidents/inc_1/review", handler.Requests[0].RequestUri!.AbsolutePath);
        var body = TestClient.Body(handler);
        Assert.Equal("downgrade", body.GetProperty("action").GetString());
        Assert.Equal("insufficient_severity", body.GetProperty("reason_code").GetString());
        Assert.Equal("low", body.GetProperty("new_risk_level").GetString());
        Assert.Equal("moderator-42", body.GetProperty("moderator_external_id").GetString());
        Assert.False(body.TryGetProperty("reason_comment", out _));

        Assert.Equal("low", result.Revised!.RiskLevel);
        Assert.Equal("req_1", result.AuditReceipt!.RequestId);
    }

    [Fact]
    public async Task Review_requires_a_moderator_id()
    {
        var handler = MockHandler.WithRawJson("{}");
        using var client = TestClient.Create(handler);

        await Assert.ThrowsAsync<ValidationException>(() => client.ReviewIncidentAsync("inc_1", new ReviewIncidentInput
        {
            Action = ModeratorAction.Confirm,
            ReasonCode = ModeratorReasonCode.ConfirmedAccurate,
        }));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Review_reclassify_requires_a_new_category()
    {
        var handler = MockHandler.WithRawJson("{}");
        using var client = TestClient.Create(handler);

        await Assert.ThrowsAsync<ValidationException>(() => client.ReviewIncidentAsync("inc_1", new ReviewIncidentInput
        {
            Action = ModeratorAction.Reclassify,
            ReasonCode = ModeratorReasonCode.IncorrectCategory,
            ModeratorExternalId = "moderator-42",
        }));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Batch_review_posts_the_ids_and_reads_each_outcome()
    {
        var handler = MockHandler.WithRawJson("""
            {
              "total": 2, "succeeded": 1, "failed": 1,
              "results": [
                { "incident_id": "inc_1", "ok": true, "original": { "risk_category": "bullying", "risk_level": "moderate" },
                  "revised": { "risk_category": "bullying", "risk_level": "moderate" }, "audit_receipt": null },
                { "incident_id": "inc_2", "ok": false, "error": "RESOURCE_NOT_FOUND" }
              ]
            }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.BatchReviewIncidentsAsync(new BatchReviewIncidentsInput
        {
            IncidentIds = new List<string> { "inc_1", "inc_2" },
            Action = ModeratorAction.Dismiss,
            ReasonCode = ModeratorReasonCode.FalsePositive,
            ModeratorExternalId = "moderator-42",
        });

        Assert.Equal("/api/v1/incidents/batch-review", handler.Requests[0].RequestUri!.AbsolutePath);
        var body = TestClient.Body(handler);
        Assert.Equal("inc_2", body.GetProperty("incident_ids")[1].GetString());
        Assert.Equal("dismiss", body.GetProperty("action").GetString());
        Assert.Equal("false_positive", body.GetProperty("reason_code").GetString());

        Assert.Equal(1, result.Failed);
        Assert.True(result.Results[0].Ok);
        Assert.Null(result.Results[0].AuditReceipt);
        Assert.Equal("RESOURCE_NOT_FOUND", result.Results[1].Error);
    }

    [Fact]
    public async Task Batch_review_rejects_more_than_100_ids()
    {
        var handler = MockHandler.WithRawJson("{}");
        using var client = TestClient.Create(handler);

        await Assert.ThrowsAsync<ValidationException>(() => client.BatchReviewIncidentsAsync(new BatchReviewIncidentsInput
        {
            IncidentIds = Enumerable.Range(0, 101).Select(i => $"inc_{i}").ToList(),
            Action = ModeratorAction.Dismiss,
            ReasonCode = ModeratorReasonCode.FalsePositive,
            ModeratorExternalId = "moderator-42",
        }));
        Assert.Empty(handler.Requests);
    }

    [Theory]
    [InlineData(ModeratorAction.Confirm, "confirm")]
    [InlineData(ModeratorAction.Downgrade, "downgrade")]
    [InlineData(ModeratorAction.Escalate, "escalate")]
    [InlineData(ModeratorAction.Reclassify, "reclassify")]
    [InlineData(ModeratorAction.Dismiss, "dismiss")]
    [InlineData(ModeratorAction.Resolve, "resolve")]
    [InlineData(ModeratorAction.Reopen, "reopen")]
    public void ModeratorAction_matches_the_api(ModeratorAction action, string expected)
    {
        Assert.Equal(expected, action.ToApiString());
    }

    [Theory]
    [InlineData(ModeratorReasonCode.ConfirmedAccurate, "confirmed_accurate")]
    [InlineData(ModeratorReasonCode.FalsePositive, "false_positive")]
    [InlineData(ModeratorReasonCode.OutOfContext, "out_of_context")]
    [InlineData(ModeratorReasonCode.InsufficientSeverity, "insufficient_severity")]
    [InlineData(ModeratorReasonCode.IncorrectCategory, "incorrect_category")]
    [InlineData(ModeratorReasonCode.RequiresLawEnforcement, "requires_law_enforcement")]
    [InlineData(ModeratorReasonCode.ParentNotified, "parent_notified")]
    [InlineData(ModeratorReasonCode.Other, "other")]
    public void ModeratorReasonCode_matches_the_api(ModeratorReasonCode code, string expected)
    {
        Assert.Equal(expected, code.ToApiString());
    }
}

public class DocumentAnalysisTests
{
    [Fact]
    public async Task Analyze_document_posts_multipart_and_reads_the_result()
    {
        var handler = MockHandler.WithRawJson("""
            {
              "file_id": "doc-1",
              "document_hash": "0000000000000000000000000000000000000000000000000000000000000000",
              "total_pages": 2, "pages_analyzed": 2,
              "extraction_summary": { "text_layer_pages": 2, "ocr_pages": 0, "failed_pages": 0, "average_ocr_confidence": 0 },
              "page_results": [{
                "page_number": 1, "text_preview": "Invented page text", "extraction_method": "text_layer",
                "results": [{ "endpoint": "unsafe", "detected": false, "severity": 0, "confidence": 0.9, "risk_score": 0.05,
                              "level": "low", "categories": [], "evidence": [], "recommended_action": "none", "rationale": "Invented." }],
                "page_risk_score": 0.05, "page_severity": "none"
              }],
              "overall_risk_score": 0.05, "overall_severity": "none", "detected_endpoints": [], "flagged_pages": [],
              "credits_used": 4, "processing_time_ms": 812, "language": "en", "language_status": "stable"
            }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.AnalyzeDocumentAsync(new AnalyzeDocumentInput
        {
            File = new byte[] { 0x25, 0x50, 0x44, 0x46 },
            Filename = "report.pdf",
            Endpoints = new List<string> { DocumentEndpointName.Unsafe, DocumentEndpointName.Grooming },
            FileId = "doc-1",
            SplitBySender = true,
        });

        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal("/api/v1/safety/document", handler.Requests[0].RequestUri!.AbsolutePath);
        var body = handler.RequestBodies[0];
        Assert.Contains("name=file; filename=report.pdf", body);
        Assert.Contains("[\"unsafe\",\"grooming\"]", body);
        Assert.Contains("name=split_by_sender", body);
        Assert.Contains("name=file_id", body);

        Assert.Equal("doc-1", result.FileId);
        Assert.Equal(2, result.TotalPages);
        Assert.Equal("none", result.OverallSeverity);
        Assert.Equal("unsafe", result.PageResults[0].Results[0].Endpoint);
        Assert.Equal(4, result.CreditsUsed);
    }

    [Fact]
    public async Task Analyze_document_requires_a_file_and_name()
    {
        var handler = MockHandler.WithRawJson("{}");
        using var client = TestClient.Create(handler);

        await Assert.ThrowsAsync<ValidationException>(() => client.AnalyzeDocumentAsync(new AnalyzeDocumentInput { File = Array.Empty<byte>(), Filename = "a.pdf" }));
        await Assert.ThrowsAsync<ValidationException>(() => client.AnalyzeDocumentAsync(new AnalyzeDocumentInput { File = new byte[] { 1 }, Filename = " " }));
        Assert.Empty(handler.Requests);
    }
}

public class VerifyImageMatchTests
{
    [Fact]
    public async Task Sends_base64_images_and_checks_and_reads_each_check()
    {
        var handler = MockHandler.WithRawJson("""
            {
              "schema_version": "1.0", "checks_run": ["face_match", "age"],
              "face_match": { "matched": true, "similarity": 0.6, "match_score": 0.88 },
              "age": { "estimated_age": 31, "confidence": 0.97 },
              "credits_used": 3, "processing_ms": 410
            }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.VerifyImageMatchAsync(new VerifyImageMatchInput
        {
            Image = new byte[] { 1, 2, 3 },
            ReferenceImage = new byte[] { 4, 5, 6 },
            Checks = new List<ImageMatchCheck> { ImageMatchCheck.FaceMatch, ImageMatchCheck.Age },
        });

        Assert.Equal("/api/v1/verify-image-match", handler.Requests[0].RequestUri!.AbsolutePath);
        var body = TestClient.Body(handler);
        Assert.Equal("AQID", body.GetProperty("image").GetString());
        Assert.Equal("BAUG", body.GetProperty("reference_image").GetString());
        Assert.Equal("face_match", body.GetProperty("checks")[0].GetString());

        Assert.Equal(0.88, result.FaceMatch!.MatchScore);
        Assert.Equal(31, result.Age!.EstimatedAge);
        Assert.Null(result.Forensic);
        Assert.Null(result.Synthetic);
    }

    [Fact]
    public async Task Omits_reference_and_checks_when_unset()
    {
        var handler = MockHandler.WithRawJson("""
            { "schema_version": "1.0", "checks_run": ["age", "forensic", "synthetic"], "age": null,
              "forensic": { "nsfw": false, "nsfw_confidence": 0.01, "skin_exposure_level": "low" },
              "synthetic": { "has_c2pa": false }, "credits_used": 3, "processing_ms": 300 }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.VerifyImageMatchAsync(new VerifyImageMatchInput { Image = new byte[] { 1 } });

        var body = TestClient.Body(handler);
        Assert.False(body.TryGetProperty("reference_image", out _));
        Assert.False(body.TryGetProperty("checks", out _));
        Assert.Null(result.Age);
        Assert.Equal("low", result.Forensic!.SkinExposureLevel);
        Assert.False(result.Synthetic!.HasC2pa);
        Assert.Null(result.Synthetic.IsSynthetic);
    }
}

public class RedactTests
{
    [Fact]
    public async Task Redacts_a_text()
    {
        var handler = MockHandler.WithRawJson("""
            { "text": "Call me on [PHONE_1]", "counts": { "phone": 1 }, "entities_total": 1, "mode": "precise",
              "strict_anonymisation": false, "model_applied": true, "credits_used": 1 }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.RedactAsync(new RedactInput { Text = "Call me on 000 000 0000", Mode = RedactMode.Precise, Language = "en" });

        Assert.Equal("/api/v1/privacy/redact", handler.Requests[0].RequestUri!.AbsolutePath);
        var body = TestClient.Body(handler);
        Assert.Equal("precise", body.GetProperty("mode").GetString());
        Assert.Equal("en", body.GetProperty("language").GetString());
        Assert.False(body.TryGetProperty("messages", out _));
        Assert.False(body.TryGetProperty("strict_anonymisation", out _));

        Assert.Equal("Call me on [PHONE_1]", result.Text);
        Assert.Equal(1, result.Counts["phone"]);
        Assert.True(result.ModelApplied);
    }

    [Fact]
    public async Task Redacts_messages()
    {
        var handler = MockHandler.WithRawJson("""
            { "messages": ["hi [NAME_1]", "bye [NAME_1]"], "counts": { "name": 2 }, "entities_total": 2, "mode": "protective",
              "strict_anonymisation": true, "model_applied": true, "credits_used": 1 }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.RedactAsync(new RedactInput { Messages = new List<string> { "hi Sam", "bye Sam" }, StrictAnonymisation = true });

        var body = TestClient.Body(handler);
        Assert.Equal(2, body.GetProperty("messages").GetArrayLength());
        Assert.True(body.GetProperty("strict_anonymisation").GetBoolean());
        Assert.Equal("bye [NAME_1]", result.Messages![1]);
    }

    [Fact]
    public async Task Requires_exactly_one_of_text_or_messages()
    {
        var handler = MockHandler.WithRawJson("{}");
        using var client = TestClient.Create(handler);

        await Assert.ThrowsAsync<ValidationException>(() => client.RedactAsync(new RedactInput()));
        await Assert.ThrowsAsync<ValidationException>(() => client.RedactAsync(new RedactInput { Text = "a", Messages = new List<string> { "b" } }));
        await Assert.ThrowsAsync<ValidationException>(() => client.RedactAsync(new RedactInput { Text = "   " }));
        Assert.Empty(handler.Requests);
    }
}

public class DistressSignalsTests
{
    [Fact]
    public async Task Detect_distress_signals_reads_the_extra_fields()
    {
        var handler = MockHandler.WithRawJson("""
            {
              "endpoint": "distress-signals", "detected": false, "severity": 0.1, "confidence": 0.9, "risk_score": 0.1,
              "level": "low", "categories": [], "recommended_action": "none", "rationale": "Invented.",
              "language": "en", "language_status": "stable",
              "distress_reading": "figurative", "distress_subject": "speaker", "support_suggested": false
            }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.DetectDistressSignalsAsync(new DetectionInput { Content = "this homework is killing me" });

        Assert.Equal("/api/v1/safety/distress-signals", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("this homework is killing me", TestClient.Body(handler).GetProperty("text").GetString());
        Assert.Equal("figurative", result.DistressReading);
        Assert.Equal("speaker", result.DistressSubject);
        Assert.False(result.SupportSuggested);
        Assert.False(result.Detected);
    }
}

public class UsageEndpointTests
{
    [Fact]
    public async Task Summary_reads_camel_case_fields()
    {
        var handler = MockHandler.WithRawJson("""
            { "apiKeyId": "key_1", "tier": "pro", "date": "2026-05-01",
              "usage": { "totalRequests": 120, "successRequests": 118, "errorRequests": 2 },
              "quota": { "requestsPerMinute": 300, "requestsPerMonth": 100000, "requestsPerDay": -1, "remainingToday": -1 } }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.GetUsageSummaryAsync("2026-05-01");

        Assert.Equal("/api/v1/usage/summary", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("?date=2026-05-01", handler.Requests[0].RequestUri!.Query);
        Assert.Equal("key_1", result.ApiKeyId);
        Assert.Equal(118, result.Usage.SuccessRequests);
        Assert.Equal(-1, result.Quota.RequestsPerDay);
    }

    [Fact]
    public async Task Quota_reads_limits_and_remaining()
    {
        var handler = MockHandler.WithRawJson("""
            { "apiKeyId": "key_1", "tier": "pro", "resetsInSeconds": 42,
              "limits": { "requestsPerMinute": 300, "requestsPerMonth": 100000, "requestsPerDay": -1 },
              "current": { "requestsThisMinute": 10, "requestsToday": 500 },
              "remaining": { "requestsThisMinute": 290, "requestsToday": -1 } }
            """);
        using var client = TestClient.Create(handler);

        var result = await client.GetQuotaAsync();

        Assert.Equal("/api/v1/usage/quota", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal(42, result.ResetsInSeconds);
        Assert.Equal(300, result.Limits.RequestsPerMinute);
        Assert.Equal(290, result.Remaining.RequestsThisMinute);
        Assert.Equal(500, result.Current.RequestsToday);
    }
}
