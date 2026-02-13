using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tuteliq;

// =============================================================================
// Configuration
// =============================================================================

/// <summary>
/// Configuration options for the Tuteliq client.
/// </summary>
public class TuteliqOptions
{
    /// <summary>Request timeout in milliseconds (default: 30000, range: 1000-120000).</summary>
    public int Timeout { get; set; } = 30_000;

    /// <summary>Number of retry attempts for transient failures (default: 3, range: 0-10).</summary>
    public int Retries { get; set; } = 3;

    /// <summary>Initial retry delay in milliseconds (default: 1000).</summary>
    public int RetryDelay { get; set; } = 1_000;

    /// <summary>API base URL (default: https://api.tuteliq.ai).</summary>
    public string BaseUrl { get; set; } = "https://api.tuteliq.ai";
}

// =============================================================================
// Context
// =============================================================================

/// <summary>
/// Optional context for analysis requests.
/// </summary>
public class AnalysisContext
{
    /// <summary>Language code (e.g. "en").</summary>
    [JsonPropertyName("language")]
    public string? Language { get; set; }

    /// <summary>Age group (e.g. "7-10", "11-13", "14-17").</summary>
    [JsonPropertyName("age_group")]
    public string? AgeGroup { get; set; }

    /// <summary>Relationship between participants (e.g. "classmates").</summary>
    [JsonPropertyName("relationship")]
    public string? Relationship { get; set; }

    /// <summary>Platform name (e.g. "Discord", "chat").</summary>
    [JsonPropertyName("platform")]
    public string? Platform { get; set; }
}

// =============================================================================
// Messages
// =============================================================================

/// <summary>
/// A message in a grooming detection conversation.
/// </summary>
public class GroomingMessage
{
    /// <summary>Role of the sender (adult, child, or unknown).</summary>
    public MessageRole Role { get; set; }

    /// <summary>Message content.</summary>
    public string Content { get; set; } = "";

    public GroomingMessage() { }

    public GroomingMessage(MessageRole role, string content)
    {
        Role = role;
        Content = content;
    }
}

/// <summary>
/// A message for emotion analysis.
/// </summary>
public class EmotionMessage
{
    public string Sender { get; set; } = "";
    public string Content { get; set; } = "";

    public EmotionMessage() { }

    public EmotionMessage(string sender, string content)
    {
        Sender = sender;
        Content = content;
    }
}

/// <summary>
/// A message for incident reports.
/// </summary>
public class ReportMessage
{
    public string Sender { get; set; } = "";
    public string Content { get; set; } = "";

    public ReportMessage() { }

    public ReportMessage(string sender, string content)
    {
        Sender = sender;
        Content = content;
    }
}

// =============================================================================
// Input Types
// =============================================================================

/// <summary>
/// Input for bullying detection.
/// </summary>
public class DetectBullyingInput
{
    /// <summary>Text content to analyze (max 50KB).</summary>
    public string Content { get; set; } = "";
    public AnalysisContext? Context { get; set; }
    /// <summary>Your unique identifier for correlation with your systems (max 255 chars).</summary>
    public string? ExternalId { get; set; }
    /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
    public string? CustomerId { get; set; }
    public Dictionary<string, object>? Metadata { get; set; }
}

/// <summary>
/// Input for grooming detection.
/// </summary>
public class DetectGroomingInput
{
    /// <summary>Conversation messages to analyze (max 100).</summary>
    public List<GroomingMessage> Messages { get; set; } = new();
    /// <summary>Age of the child in the conversation.</summary>
    public int? ChildAge { get; set; }
    public AnalysisContext? Context { get; set; }
    /// <summary>Your unique identifier for correlation with your systems (max 255 chars).</summary>
    public string? ExternalId { get; set; }
    /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
    public string? CustomerId { get; set; }
    public Dictionary<string, object>? Metadata { get; set; }
}

/// <summary>
/// Input for unsafe content detection.
/// </summary>
public class DetectUnsafeInput
{
    /// <summary>Text content to analyze (max 50KB).</summary>
    public string Content { get; set; } = "";
    public AnalysisContext? Context { get; set; }
    /// <summary>Your unique identifier for correlation with your systems (max 255 chars).</summary>
    public string? ExternalId { get; set; }
    /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
    public string? CustomerId { get; set; }
    public Dictionary<string, object>? Metadata { get; set; }
}

/// <summary>
/// Input for combined safety analysis.
/// </summary>
public class AnalyzeInput
{
    /// <summary>Text content to analyze (max 50KB).</summary>
    public string Content { get; set; } = "";
    public AnalysisContext? Context { get; set; }
    /// <summary>Which checks to run: "bullying", "unsafe", "grooming" (default: bullying + unsafe).</summary>
    public List<string>? Include { get; set; }
    /// <summary>Your unique identifier for correlation with your systems (max 255 chars).</summary>
    public string? ExternalId { get; set; }
    /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
    public string? CustomerId { get; set; }
    public Dictionary<string, object>? Metadata { get; set; }
}

/// <summary>
/// Input for emotion analysis.
/// </summary>
public class AnalyzeEmotionsInput
{
    /// <summary>Single text content to analyze.</summary>
    public string? Content { get; set; }
    /// <summary>Conversation messages to analyze.</summary>
    public List<EmotionMessage>? Messages { get; set; }
    public AnalysisContext? Context { get; set; }
    /// <summary>Your unique identifier for correlation with your systems (max 255 chars).</summary>
    public string? ExternalId { get; set; }
    /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
    public string? CustomerId { get; set; }
    public Dictionary<string, object>? Metadata { get; set; }
}

/// <summary>
/// Input for action plan generation.
/// </summary>
public class GetActionPlanInput
{
    /// <summary>Description of the safety situation.</summary>
    public string Situation { get; set; } = "";
    /// <summary>Age of the child involved.</summary>
    public int? ChildAge { get; set; }
    /// <summary>Target audience for the plan (default: Parent).</summary>
    public Audience Audience { get; set; } = Audience.Parent;
    /// <summary>Severity of the situation.</summary>
    public Severity? Severity { get; set; }
    /// <summary>Your unique identifier for correlation with your systems (max 255 chars).</summary>
    public string? ExternalId { get; set; }
    /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
    public string? CustomerId { get; set; }
    public Dictionary<string, object>? Metadata { get; set; }
}

/// <summary>
/// Input for incident report generation.
/// </summary>
public class GenerateReportInput
{
    /// <summary>Messages involved in the incident (max 100).</summary>
    public List<ReportMessage> Messages { get; set; } = new();
    /// <summary>Age of the child involved.</summary>
    public int? ChildAge { get; set; }
    /// <summary>Type of incident (e.g. "harassment").</summary>
    public string? IncidentType { get; set; }
    /// <summary>Your unique identifier for correlation with your systems (max 255 chars).</summary>
    public string? ExternalId { get; set; }
    /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
    public string? CustomerId { get; set; }
    public Dictionary<string, object>? Metadata { get; set; }
}

// =============================================================================
// Result Types
// =============================================================================

/// <summary>
/// Result of bullying detection.
/// </summary>
public class BullyingResult
{
    [JsonPropertyName("is_bullying")]
    public bool IsBullying { get; set; }

    [JsonPropertyName("bullying_type")]
    public List<string> BullyingType { get; set; } = new();

    [JsonPropertyName("confidence")]
    public double Confidence { get; set; }

    [JsonPropertyName("severity")]
    public string SeverityRaw { get; set; } = "low";

    [JsonIgnore]
    public Severity Severity => EnumExtensions.ParseSeverity(SeverityRaw);

    [JsonPropertyName("rationale")]
    public string Rationale { get; set; } = "";

    [JsonPropertyName("recommended_action")]
    public string RecommendedAction { get; set; } = "";

    [JsonPropertyName("risk_score")]
    public double RiskScore { get; set; }

    [JsonPropertyName("external_id")]
    public string? ExternalId { get; set; }

    [JsonPropertyName("customer_id")]
    public string? CustomerId { get; set; }

    [JsonPropertyName("metadata")]
    public Dictionary<string, object>? Metadata { get; set; }
}

/// <summary>
/// Result of grooming detection.
/// </summary>
public class GroomingResult
{
    [JsonPropertyName("grooming_risk")]
    public string GroomingRiskRaw { get; set; } = "none";

    [JsonIgnore]
    public GroomingRisk GroomingRisk => EnumExtensions.ParseGroomingRisk(GroomingRiskRaw);

    [JsonPropertyName("flags")]
    public List<string> Flags { get; set; } = new();

    [JsonPropertyName("confidence")]
    public double Confidence { get; set; }

    [JsonPropertyName("rationale")]
    public string Rationale { get; set; } = "";

    [JsonPropertyName("risk_score")]
    public double RiskScore { get; set; }

    [JsonPropertyName("recommended_action")]
    public string RecommendedAction { get; set; } = "";

    [JsonPropertyName("external_id")]
    public string? ExternalId { get; set; }

    [JsonPropertyName("customer_id")]
    public string? CustomerId { get; set; }

    [JsonPropertyName("metadata")]
    public Dictionary<string, object>? Metadata { get; set; }
}

/// <summary>
/// Result of unsafe content detection.
/// </summary>
public class UnsafeResult
{
    [JsonPropertyName("unsafe")]
    public bool Unsafe { get; set; }

    [JsonPropertyName("categories")]
    public List<string> Categories { get; set; } = new();

    [JsonPropertyName("severity")]
    public string SeverityRaw { get; set; } = "low";

    [JsonIgnore]
    public Severity Severity => EnumExtensions.ParseSeverity(SeverityRaw);

    [JsonPropertyName("confidence")]
    public double Confidence { get; set; }

    [JsonPropertyName("risk_score")]
    public double RiskScore { get; set; }

    [JsonPropertyName("rationale")]
    public string Rationale { get; set; } = "";

    [JsonPropertyName("recommended_action")]
    public string RecommendedAction { get; set; } = "";

    [JsonPropertyName("external_id")]
    public string? ExternalId { get; set; }

    [JsonPropertyName("customer_id")]
    public string? CustomerId { get; set; }

    [JsonPropertyName("metadata")]
    public Dictionary<string, object>? Metadata { get; set; }
}

/// <summary>
/// Result of combined safety analysis.
/// </summary>
public class AnalyzeResult
{
    public RiskLevel RiskLevel { get; set; }
    public double RiskScore { get; set; }
    public string Summary { get; set; } = "";
    public BullyingResult? Bullying { get; set; }
    public UnsafeResult? Unsafe { get; set; }
    public string RecommendedAction { get; set; } = "";
    public string? ExternalId { get; set; }
    public string? CustomerId { get; set; }
    public Dictionary<string, object>? Metadata { get; set; }
}

/// <summary>
/// Result of emotion analysis.
/// </summary>
public class EmotionsResult
{
    [JsonPropertyName("dominant_emotions")]
    public List<string> DominantEmotions { get; set; } = new();

    [JsonPropertyName("emotion_scores")]
    public Dictionary<string, double>? EmotionScores { get; set; }

    [JsonPropertyName("trend")]
    public string TrendRaw { get; set; } = "stable";

    [JsonIgnore]
    public EmotionTrend Trend => EnumExtensions.ParseEmotionTrend(TrendRaw);

    [JsonPropertyName("summary")]
    public string Summary { get; set; } = "";

    [JsonPropertyName("recommended_followup")]
    public string RecommendedFollowup { get; set; } = "";

    [JsonPropertyName("external_id")]
    public string? ExternalId { get; set; }

    [JsonPropertyName("customer_id")]
    public string? CustomerId { get; set; }

    [JsonPropertyName("metadata")]
    public Dictionary<string, object>? Metadata { get; set; }
}

/// <summary>
/// Result of action plan generation.
/// </summary>
public class ActionPlanResult
{
    [JsonPropertyName("audience")]
    public string AudienceRaw { get; set; } = "";

    [JsonPropertyName("steps")]
    public List<string> Steps { get; set; } = new();

    [JsonPropertyName("tone")]
    public string Tone { get; set; } = "";

    [JsonPropertyName("approx_reading_level")]
    public string? ReadingLevel { get; set; }

    [JsonPropertyName("external_id")]
    public string? ExternalId { get; set; }

    [JsonPropertyName("customer_id")]
    public string? CustomerId { get; set; }

    [JsonPropertyName("metadata")]
    public Dictionary<string, object>? Metadata { get; set; }
}

/// <summary>
/// Result of incident report generation.
/// </summary>
public class ReportResult
{
    [JsonPropertyName("summary")]
    public string Summary { get; set; } = "";

    [JsonPropertyName("risk_level")]
    public string RiskLevelRaw { get; set; } = "low";

    [JsonIgnore]
    public RiskLevel RiskLevel => EnumExtensions.ParseRiskLevel(RiskLevelRaw);

    [JsonPropertyName("categories")]
    public List<string> Categories { get; set; } = new();

    [JsonPropertyName("recommended_next_steps")]
    public List<string> RecommendedNextSteps { get; set; } = new();

    [JsonPropertyName("external_id")]
    public string? ExternalId { get; set; }

    [JsonPropertyName("customer_id")]
    public string? CustomerId { get; set; }

    [JsonPropertyName("metadata")]
    public Dictionary<string, object>? Metadata { get; set; }
}

// =============================================================================
// Account Management (GDPR)
// =============================================================================

/// <summary>
/// Result of account data deletion (GDPR Article 17 — Right to Erasure).
/// </summary>
public class AccountDeletionResult
{
    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

    [JsonPropertyName("deleted_count")]
    public int DeletedCount { get; set; }
}

/// <summary>
/// Result of account data export (GDPR Article 20 — Right to Data Portability).
/// </summary>
public class AccountExportResult
{
    [JsonPropertyName("userId")]
    public string UserId { get; set; } = "";

    [JsonPropertyName("exportedAt")]
    public string ExportedAt { get; set; } = "";

    [JsonPropertyName("data")]
    public Dictionary<string, object>? Data { get; set; }
}

// =============================================================================
// Consent Management (GDPR Article 7)
// =============================================================================

/// <summary>
/// A consent record.
/// </summary>
public class ConsentRecord
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("user_id")]
    public string UserId { get; set; } = "";

    [JsonPropertyName("consent_type")]
    public string ConsentType { get; set; } = "";

    [JsonPropertyName("status")]
    public string Status { get; set; } = "";

    [JsonPropertyName("version")]
    public string Version { get; set; } = "";

    [JsonPropertyName("created_at")]
    public string CreatedAt { get; set; } = "";
}

/// <summary>
/// Result from consent record/withdraw operations.
/// </summary>
public class ConsentActionResult
{
    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

    [JsonPropertyName("consent")]
    public ConsentRecord? Consent { get; set; }
}

/// <summary>
/// Result from consent status query.
/// </summary>
public class ConsentStatusResult
{
    [JsonPropertyName("consents")]
    public List<ConsentRecord> Consents { get; set; } = new();
}

/// <summary>
/// Input for recording consent.
/// </summary>
public class RecordConsentInput
{
    public string ConsentType { get; set; } = "";
    public string Version { get; set; } = "";
}

/// <summary>
/// Input for data rectification.
/// </summary>
public class RectifyDataInput
{
    public string Collection { get; set; } = "";
    public string DocumentId { get; set; } = "";
    public Dictionary<string, object> Fields { get; set; } = new();
}

/// <summary>
/// Result from data rectification.
/// </summary>
public class RectifyDataResult
{
    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

    [JsonPropertyName("updated_fields")]
    public List<string> UpdatedFields { get; set; } = new();
}

/// <summary>
/// An audit log entry.
/// </summary>
public class AuditLogEntry
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("user_id")]
    public string UserId { get; set; } = "";

    [JsonPropertyName("action")]
    public string Action { get; set; } = "";

    [JsonPropertyName("details")]
    public Dictionary<string, object>? Details { get; set; }

    [JsonPropertyName("created_at")]
    public string CreatedAt { get; set; } = "";
}

/// <summary>
/// Result from audit logs query.
/// </summary>
public class AuditLogsResult
{
    [JsonPropertyName("audit_logs")]
    public List<AuditLogEntry> AuditLogs { get; set; } = new();
}

// =============================================================================
// Usage & Rate Limit
// =============================================================================

/// <summary>
/// Monthly API usage information.
/// </summary>
public class Usage
{
    public int Limit { get; set; }
    public int Used { get; set; }
    public int Remaining { get; set; }
}

/// <summary>
/// Rate limit information for the current minute.
/// </summary>
public class RateLimitInfo
{
    public int Limit { get; set; }
    public int Remaining { get; set; }
    public long? Reset { get; set; }
}

// =============================================================================
// Breach Management (GDPR Article 33/34)
// =============================================================================

/// <summary>
/// Input for logging a new data breach.
/// </summary>
public class LogBreachInput
{
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public string Severity { get; set; } = "low";
    public List<string> AffectedUserIds { get; set; } = new();
    public List<string> DataCategories { get; set; } = new();
    public string ReportedBy { get; set; } = "";
}

/// <summary>
/// Input for updating a breach.
/// </summary>
public class UpdateBreachInput
{
    public string Status { get; set; } = "";
    public string? NotificationStatus { get; set; }
    public string? Notes { get; set; }
}

/// <summary>
/// A breach record.
/// </summary>
public class BreachRecord
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("title")]
    public string Title { get; set; } = "";

    [JsonPropertyName("description")]
    public string Description { get; set; } = "";

    [JsonPropertyName("severity")]
    public string Severity { get; set; } = "";

    [JsonPropertyName("status")]
    public string Status { get; set; } = "";

    [JsonPropertyName("notification_status")]
    public string NotificationStatus { get; set; } = "";

    [JsonPropertyName("affected_user_ids")]
    public List<string> AffectedUserIds { get; set; } = new();

    [JsonPropertyName("data_categories")]
    public List<string> DataCategories { get; set; } = new();

    [JsonPropertyName("reported_by")]
    public string ReportedBy { get; set; } = "";

    [JsonPropertyName("notification_deadline")]
    public string NotificationDeadline { get; set; } = "";

    [JsonPropertyName("created_at")]
    public string CreatedAt { get; set; } = "";

    [JsonPropertyName("updated_at")]
    public string UpdatedAt { get; set; } = "";
}

/// <summary>
/// Result from logging a breach.
/// </summary>
public class LogBreachResult
{
    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

    [JsonPropertyName("breach")]
    public BreachRecord? Breach { get; set; }
}

/// <summary>
/// Result from listing breaches.
/// </summary>
public class BreachListResult
{
    [JsonPropertyName("breaches")]
    public List<BreachRecord> Breaches { get; set; } = new();
}

/// <summary>
/// Result from getting/updating a breach.
/// </summary>
public class BreachResult
{
    [JsonPropertyName("breach")]
    public BreachRecord? Breach { get; set; }
}

// =============================================================================
// Voice Analysis
// =============================================================================

/// <summary>
/// A segment of a voice transcription with timing information.
/// </summary>
public class TranscriptionSegment
{
    [JsonPropertyName("start")]
    public double Start { get; set; }

    [JsonPropertyName("end")]
    public double End { get; set; }

    [JsonPropertyName("text")]
    public string Text { get; set; } = "";
}

/// <summary>
/// Result of a voice transcription.
/// </summary>
public class TranscriptionResult
{
    [JsonPropertyName("text")]
    public string Text { get; set; } = "";

    [JsonPropertyName("language")]
    public string? Language { get; set; }

    [JsonPropertyName("duration")]
    public double? Duration { get; set; }

    [JsonPropertyName("segments")]
    public List<TranscriptionSegment>? Segments { get; set; }
}

/// <summary>
/// Result of voice safety analysis.
/// </summary>
public class VoiceAnalysisResult
{
    [JsonPropertyName("file_id")]
    public string? FileId { get; set; }

    [JsonPropertyName("transcription")]
    public TranscriptionResult? Transcription { get; set; }

    [JsonPropertyName("analysis")]
    public JsonElement? Analysis { get; set; }

    [JsonPropertyName("overall_risk_score")]
    public double? OverallRiskScore { get; set; }

    [JsonPropertyName("overall_severity")]
    public string? OverallSeverity { get; set; }

    [JsonPropertyName("external_id")]
    public string? ExternalId { get; set; }

    [JsonPropertyName("customer_id")]
    public string? CustomerId { get; set; }

    [JsonPropertyName("metadata")]
    public JsonElement? Metadata { get; set; }
}

// =============================================================================
// Image Analysis
// =============================================================================

/// <summary>
/// Vision analysis result for an image.
/// </summary>
public class VisionResult
{
    [JsonPropertyName("extracted_text")]
    public string? ExtractedText { get; set; }

    [JsonPropertyName("visual_categories")]
    public List<string>? VisualCategories { get; set; }

    [JsonPropertyName("visual_severity")]
    public string? VisualSeverity { get; set; }

    [JsonPropertyName("visual_confidence")]
    public double? VisualConfidence { get; set; }

    [JsonPropertyName("visual_description")]
    public string? VisualDescription { get; set; }

    [JsonPropertyName("contains_text")]
    public bool? ContainsText { get; set; }

    [JsonPropertyName("contains_faces")]
    public bool? ContainsFaces { get; set; }
}

/// <summary>
/// Result of image safety analysis.
/// </summary>
public class ImageAnalysisResult
{
    [JsonPropertyName("file_id")]
    public string? FileId { get; set; }

    [JsonPropertyName("vision")]
    public VisionResult? Vision { get; set; }

    [JsonPropertyName("text_analysis")]
    public JsonElement? TextAnalysis { get; set; }

    [JsonPropertyName("overall_risk_score")]
    public double? OverallRiskScore { get; set; }

    [JsonPropertyName("overall_severity")]
    public string? OverallSeverity { get; set; }

    [JsonPropertyName("external_id")]
    public string? ExternalId { get; set; }

    [JsonPropertyName("customer_id")]
    public string? CustomerId { get; set; }

    [JsonPropertyName("metadata")]
    public JsonElement? Metadata { get; set; }
}

// =============================================================================
// Webhooks
// =============================================================================

/// <summary>
/// A webhook configuration.
/// </summary>
public class WebhookInfo
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("url")]
    public string Url { get; set; } = "";

    [JsonPropertyName("events")]
    public List<string> Events { get; set; } = new();

    [JsonPropertyName("active")]
    public bool Active { get; set; }

    [JsonPropertyName("secret")]
    public string? Secret { get; set; }

    [JsonPropertyName("created_at")]
    public string? CreatedAt { get; set; }

    [JsonPropertyName("updated_at")]
    public string? UpdatedAt { get; set; }
}

/// <summary>
/// Result from listing webhooks.
/// </summary>
public class WebhookListResult
{
    [JsonPropertyName("webhooks")]
    public List<WebhookInfo> Webhooks { get; set; } = new();
}

/// <summary>
/// Input for creating a webhook.
/// </summary>
public class CreateWebhookInput
{
    public string Url { get; set; } = "";
    public List<string> Events { get; set; } = new();
    public bool Active { get; set; } = true;
}

/// <summary>
/// Result from creating a webhook.
/// </summary>
public class CreateWebhookResult
{
    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

    [JsonPropertyName("webhook")]
    public WebhookInfo Webhook { get; set; } = new();
}

/// <summary>
/// Input for updating a webhook.
/// </summary>
public class UpdateWebhookInput
{
    public string? Url { get; set; }
    public List<string>? Events { get; set; }
    public bool? Active { get; set; }
}

/// <summary>
/// Result from updating a webhook.
/// </summary>
public class UpdateWebhookResult
{
    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

    [JsonPropertyName("webhook")]
    public WebhookInfo Webhook { get; set; } = new();
}

/// <summary>
/// Result from deleting a webhook.
/// </summary>
public class DeleteWebhookResult
{
    [JsonPropertyName("message")]
    public string Message { get; set; } = "";
}

/// <summary>
/// Result from testing a webhook.
/// </summary>
public class TestWebhookResult
{
    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

    [JsonPropertyName("status_code")]
    public int? StatusCode { get; set; }
}

/// <summary>
/// Result from regenerating a webhook secret.
/// </summary>
public class RegenerateSecretResult
{
    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

    [JsonPropertyName("secret")]
    public string Secret { get; set; } = "";
}

// =============================================================================
// Pricing
// =============================================================================

/// <summary>
/// A pricing plan summary.
/// </summary>
public class PricingPlan
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("price")]
    public string Price { get; set; } = "";

    [JsonPropertyName("messages")]
    public string Messages { get; set; } = "";

    [JsonPropertyName("features")]
    public List<string> Features { get; set; } = new();
}

/// <summary>
/// Result from getting pricing plans.
/// </summary>
public class PricingResult
{
    [JsonPropertyName("plans")]
    public List<PricingPlan> Plans { get; set; } = new();
}

/// <summary>
/// A detailed pricing plan with tier information.
/// </summary>
public class PricingDetailPlan
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("tier")]
    public string Tier { get; set; } = "";

    [JsonPropertyName("price")]
    public JsonElement Price { get; set; }

    [JsonPropertyName("limits")]
    public JsonElement Limits { get; set; }

    [JsonPropertyName("features")]
    public JsonElement Features { get; set; }

    [JsonPropertyName("endpoints")]
    public List<string> Endpoints { get; set; } = new();
}

/// <summary>
/// Result from getting detailed pricing information.
/// </summary>
public class PricingDetailsResult
{
    [JsonPropertyName("plans")]
    public List<PricingDetailPlan> Plans { get; set; } = new();
}

// =============================================================================
// Usage
// =============================================================================

/// <summary>
/// A single day of usage data.
/// </summary>
public class UsageDay
{
    [JsonPropertyName("date")]
    public string Date { get; set; } = "";

    [JsonPropertyName("total_requests")]
    public int TotalRequests { get; set; }

    [JsonPropertyName("success_requests")]
    public int SuccessRequests { get; set; }

    [JsonPropertyName("error_requests")]
    public int ErrorRequests { get; set; }
}

/// <summary>
/// Result from getting usage history.
/// </summary>
public class UsageHistoryResult
{
    [JsonPropertyName("api_key_id")]
    public string ApiKeyId { get; set; } = "";

    [JsonPropertyName("days")]
    public List<UsageDay> Days { get; set; } = new();
}

/// <summary>
/// Result from getting usage grouped by tool/endpoint.
/// </summary>
public class UsageByToolResult
{
    [JsonPropertyName("date")]
    public string Date { get; set; } = "";

    [JsonPropertyName("tools")]
    public Dictionary<string, int> Tools { get; set; } = new();

    [JsonPropertyName("endpoints")]
    public Dictionary<string, int> Endpoints { get; set; } = new();
}

/// <summary>
/// Result from getting monthly usage summary.
/// </summary>
public class UsageMonthlyResult
{
    [JsonPropertyName("tier")]
    public string Tier { get; set; } = "";

    [JsonPropertyName("tier_display_name")]
    public string TierDisplayName { get; set; } = "";

    [JsonPropertyName("billing")]
    public JsonElement Billing { get; set; }

    [JsonPropertyName("usage")]
    public JsonElement Usage { get; set; }

    [JsonPropertyName("rate_limit")]
    public JsonElement RateLimit { get; set; }

    [JsonPropertyName("recommendations")]
    public JsonElement? Recommendations { get; set; }

    [JsonPropertyName("links")]
    public JsonElement Links { get; set; }
}
