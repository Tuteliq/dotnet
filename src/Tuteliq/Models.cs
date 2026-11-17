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

    [JsonPropertyName("language")]
    public string? Language { get; set; }

    [JsonPropertyName("language_status")]
    public string? LanguageStatusRaw { get; set; }

    [JsonPropertyName("credits_used")]
    public int? CreditsUsed { get; set; }
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

    [JsonPropertyName("language")]
    public string? Language { get; set; }

    [JsonPropertyName("language_status")]
    public string? LanguageStatusRaw { get; set; }

    [JsonPropertyName("message_analysis")]
    public List<MessageAnalysis>? MessageAnalysis { get; set; }

    [JsonPropertyName("credits_used")]
    public int? CreditsUsed { get; set; }
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

    [JsonPropertyName("language")]
    public string? Language { get; set; }

    [JsonPropertyName("language_status")]
    public string? LanguageStatusRaw { get; set; }

    [JsonPropertyName("credits_used")]
    public int? CreditsUsed { get; set; }
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

    [JsonPropertyName("credits_used")]
    public int? CreditsUsed { get; set; }
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

    [JsonPropertyName("credits_used")]
    public int? CreditsUsed { get; set; }
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

    [JsonPropertyName("credits_used")]
    public int? CreditsUsed { get; set; }
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

    [JsonPropertyName("credits_used")]
    public int? CreditsUsed { get; set; }
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

    [JsonPropertyName("credits_used")]
    public int? CreditsUsed { get; set; }
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

    [JsonPropertyName("credits_used")]
    public int? CreditsUsed { get; set; }
}

// =============================================================================
// Detection (Fraud & Extended Safety)
// =============================================================================

/// <summary>
/// Input for fraud and extended safety detection endpoints.
/// </summary>
public class DetectionInput
{
    /// <summary>Text content to analyze.</summary>
    public required string Content { get; init; }
    public AnalysisContext? Context { get; init; }
    public bool IncludeEvidence { get; init; }
    /// <summary>Your unique identifier for correlation with your systems (max 255 chars).</summary>
    public string? ExternalId { get; init; }
    /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
    public string? CustomerId { get; init; }
    public Dictionary<string, object>? Metadata { get; init; }
}

/// <summary>
/// Input for multi-endpoint analysis.
/// </summary>
public class AnalyseMultiInput
{
    /// <summary>Text content to analyze.</summary>
    public required string Content { get; init; }
    /// <summary>List of detection endpoints to run.</summary>
    public required List<Detection> Detections { get; init; }
    public AnalysisContext? Context { get; init; }
    public bool IncludeEvidence { get; init; }
    /// <summary>Your unique identifier for correlation with your systems (max 255 chars).</summary>
    public string? ExternalId { get; init; }
    /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
    public string? CustomerId { get; init; }
    public Dictionary<string, object>? Metadata { get; init; }
}

/// <summary>
/// Per-message analysis from conversation-aware detection.
/// </summary>
public class MessageAnalysis
{
    [JsonPropertyName("message_index")]
    public int MessageIndex { get; init; }

    [JsonPropertyName("risk_score")]
    public double RiskScore { get; init; }

    [JsonPropertyName("flags")]
    public List<string> Flags { get; init; } = new();

    [JsonPropertyName("summary")]
    public string Summary { get; init; } = "";
}

/// <summary>
/// A category detected in fraud/safety analysis.
/// </summary>
public class DetectionCategory
{
    [JsonPropertyName("tag")]
    public string Tag { get; init; } = "";

    [JsonPropertyName("label")]
    public string Label { get; init; } = "";

    [JsonPropertyName("confidence")]
    public double Confidence { get; init; }
}

/// <summary>
/// Evidence detail for a detection result.
/// </summary>
public class DetectionEvidence
{
    [JsonPropertyName("text")]
    public string Text { get; init; } = "";

    [JsonPropertyName("tactic")]
    public string Tactic { get; init; } = "";

    [JsonPropertyName("weight")]
    public double Weight { get; init; }
}

/// <summary>
/// Age calibration information applied to a detection.
/// </summary>
public class AgeCalibration
{
    [JsonPropertyName("applied")]
    public bool Applied { get; init; }

    [JsonPropertyName("age_group")]
    public string? AgeGroup { get; init; }

    [JsonPropertyName("multiplier")]
    public double? Multiplier { get; init; }
}

/// <summary>
/// Result of a fraud or extended safety detection.
/// </summary>
public class DetectionResult
{
    [JsonPropertyName("endpoint")]
    public string Endpoint { get; init; } = "";

    [JsonPropertyName("detected")]
    public bool Detected { get; init; }

    [JsonPropertyName("severity")]
    public double Severity { get; init; }

    [JsonPropertyName("confidence")]
    public double Confidence { get; init; }

    [JsonPropertyName("risk_score")]
    public double RiskScore { get; init; }

    [JsonPropertyName("level")]
    public string Level { get; init; } = "";

    [JsonPropertyName("categories")]
    public List<DetectionCategory> Categories { get; init; } = new();

    [JsonPropertyName("recommended_action")]
    public string RecommendedAction { get; init; } = "";

    [JsonPropertyName("rationale")]
    public string Rationale { get; init; } = "";

    [JsonPropertyName("language")]
    public string Language { get; init; } = "";

    [JsonPropertyName("language_status")]
    public string LanguageStatus { get; init; } = "";

    [JsonPropertyName("evidence")]
    public List<DetectionEvidence>? Evidence { get; init; }

    [JsonPropertyName("age_calibration")]
    public AgeCalibration? AgeCalibration { get; init; }

    [JsonPropertyName("message_analysis")]
    public List<MessageAnalysis>? MessageAnalysis { get; init; }

    [JsonPropertyName("credits_used")]
    public int? CreditsUsed { get; init; }

    [JsonPropertyName("processing_time_ms")]
    public double? ProcessingTimeMs { get; init; }

    [JsonPropertyName("external_id")]
    public string? ExternalId { get; init; }

    [JsonPropertyName("customer_id")]
    public string? CustomerId { get; init; }

    [JsonPropertyName("metadata")]
    public Dictionary<string, object>? Metadata { get; init; }
}

/// <summary>
/// Summary of a multi-endpoint analysis.
/// </summary>
public class AnalyseMultiSummary
{
    [JsonPropertyName("total_endpoints")]
    public int TotalEndpoints { get; init; }

    [JsonPropertyName("detected_count")]
    public int DetectedCount { get; init; }

    [JsonPropertyName("highest_risk")]
    public Dictionary<string, object>? HighestRisk { get; init; }

    [JsonPropertyName("overall_risk_level")]
    public string OverallRiskLevel { get; init; } = "";
}

/// <summary>
/// Result of a multi-endpoint analysis.
/// </summary>
public class AnalyseMultiResult
{
    [JsonPropertyName("results")]
    public List<DetectionResult> Results { get; init; } = new();

    [JsonPropertyName("summary")]
    public AnalyseMultiSummary Summary { get; init; } = new();

    [JsonPropertyName("cross_endpoint_modifier")]
    public double? CrossEndpointModifier { get; init; }

    [JsonPropertyName("credits_used")]
    public int? CreditsUsed { get; init; }

    [JsonPropertyName("external_id")]
    public string? ExternalId { get; init; }

    [JsonPropertyName("customer_id")]
    public string? CustomerId { get; init; }

    [JsonPropertyName("metadata")]
    public Dictionary<string, object>? Metadata { get; init; }
}

// =============================================================================
// Video Analysis
// =============================================================================

/// <summary>
/// A safety finding from video frame analysis.
/// </summary>
public class VideoSafetyFinding
{
    [JsonPropertyName("frame_index")]
    public int FrameIndex { get; init; }

    [JsonPropertyName("timestamp")]
    public double Timestamp { get; init; }

    [JsonPropertyName("description")]
    public string Description { get; init; } = "";

    [JsonPropertyName("categories")]
    public List<string> Categories { get; init; } = new();

    [JsonPropertyName("severity")]
    public double Severity { get; init; }
}

/// <summary>
/// Result of video safety analysis.
/// </summary>
public class VideoAnalysisResult
{
    [JsonPropertyName("file_id")]
    public string? FileId { get; init; }

    [JsonPropertyName("frames_analyzed")]
    public int FramesAnalyzed { get; init; }

    [JsonPropertyName("safety_findings")]
    public List<VideoSafetyFinding> SafetyFindings { get; init; } = new();

    [JsonPropertyName("overall_risk_score")]
    public double OverallRiskScore { get; init; }

    [JsonPropertyName("overall_severity")]
    public string OverallSeverity { get; init; } = "";

    [JsonPropertyName("credits_used")]
    public int? CreditsUsed { get; init; }

    [JsonPropertyName("external_id")]
    public string? ExternalId { get; init; }

    [JsonPropertyName("customer_id")]
    public string? CustomerId { get; init; }

    [JsonPropertyName("metadata")]
    public Dictionary<string, object>? Metadata { get; init; }
}

// =============================================================================
// Verification
// =============================================================================

/// <summary>
/// Input for creating a verification session.
/// </summary>
public class CreateVerificationSessionInput
{
    private const string NotSent = "The API does not accept this field and the SDK no longer sends it.";

    /// <summary>Type of verification to perform.</summary>
    public VerificationMode Mode { get; set; }
    /// <summary>Preferred document type (optional hint).</summary>
    public DocumentType? DocumentType { get; set; }
    /// <summary>How a passport or ID card chip read counts as document evidence. The API defaults to <see cref="Tuteliq.ChipPolicy.Optional"/>.</summary>
    public ChipPolicy? ChipPolicy { get; set; }
    /// <summary>
    /// Whether the hosted page takes the document photo itself once the document is framed, steady and sharp.
    /// The API defaults to <c>true</c>; with <c>false</c> the user taps Capture.
    /// </summary>
    public bool? AutoCapture { get; set; }
    /// <summary>Not sent. Set the redirect URL in the dashboard verification settings instead.</summary>
    [Obsolete(NotSent + " Set the redirect URL in the dashboard verification settings instead.")]
    public string? RedirectUrl { get; set; }
    /// <summary>Not sent.</summary>
    [Obsolete(NotSent)]
    public string? ExternalId { get; set; }
    /// <summary>Not sent.</summary>
    [Obsolete(NotSent)]
    public string? CustomerId { get; set; }
    /// <summary>Not sent.</summary>
    [Obsolete(NotSent)]
    public Dictionary<string, object>? Metadata { get; set; }
}

/// <summary>
/// Result from creating a verification session.
/// </summary>
public class VerificationSessionResponse
{
    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = "";

    [JsonPropertyName("mobile_url")]
    public string MobileUrl { get; set; } = "";

    /// <summary>Epoch milliseconds at which the session expires.</summary>
    [JsonPropertyName("expires_at")]
    public long ExpiresAt { get; set; }

    [JsonPropertyName("mode")]
    public string ModeRaw { get; set; } = "";

    [JsonIgnore]
    public VerificationMode Mode => EnumExtensions.ParseVerificationMode(ModeRaw);

    /// <summary>URL to open for the user to complete verification (mapped from mobile_url).</summary>
    [JsonIgnore]
    public string Url => MobileUrl;

    /// <summary>
    /// The check configured for this key (<c>full</c> or <c>liveness_only</c>). For age sessions it may
    /// still be resolved per market on the user's device; the poll reports the check the result rests on.
    /// </summary>
    [JsonPropertyName("verification_mode")]
    public string? VerificationCheck { get; set; }

    /// <summary>How a chip read counts as document evidence (<c>optional</c>, <c>required</c> or <c>instead_of_photo</c>).</summary>
    [JsonPropertyName("chip_policy")]
    public string? ChipPolicy { get; set; }

    /// <summary>Whether the hosted page takes the document photo itself.</summary>
    [JsonPropertyName("auto_capture")]
    public bool? AutoCapture { get; set; }

    /// <summary>
    /// Width in pixels the capture step should request from the camera. Small print on a document only
    /// survives at this resolution, so pass it through rather than picking your own.
    /// </summary>
    [JsonPropertyName("recommended_image_width")]
    public int? RecommendedImageWidth { get; set; }
}

/// <summary>
/// Face comparison results.
/// </summary>
public class FaceMatchResult
{
    [JsonPropertyName("matched")]
    public bool Matched { get; set; }

    /// <summary>Distance between the two faces (lower is more similar). Webhook deliveries only.</summary>
    [JsonPropertyName("distance")]
    public double? Distance { get; set; }

    /// <summary>1 minus the face distance. Kept for compatibility; prefer <see cref="MatchScore"/>.</summary>
    [JsonPropertyName("confidence")]
    public double Confidence { get; set; }

    /// <summary>
    /// How strongly the faces match (0-1): 0.5 at the match decision, high for a clear match,
    /// near 0 for different people. Absent from API versions before it was added.
    /// </summary>
    [JsonPropertyName("match_score")]
    public double? MatchScore { get; set; }
}

/// <summary>
/// Liveness check results.
/// </summary>
public class LivenessResult
{
    [JsonPropertyName("valid")]
    public bool Valid { get; set; }

    [JsonPropertyName("reason")]
    public string? Reason { get; set; }
}

/// <summary>
/// Age verification result.
/// </summary>
public class AgeVerificationResult
{
    [JsonPropertyName("verification_id")]
    public string VerificationId { get; set; } = "";

    [JsonPropertyName("status")]
    public string StatusRaw { get; set; } = "";

    [JsonIgnore]
    public VerificationStatus Status => EnumExtensions.ParseVerificationStatus(StatusRaw);

    [JsonPropertyName("age_bracket")]
    public string? AgeBracket { get; set; }

    [JsonPropertyName("is_minor")]
    public bool? IsMinor { get; set; }

    [JsonPropertyName("face_match")]
    public FaceMatchResult? FaceMatch { get; set; }

    [JsonPropertyName("liveness")]
    public LivenessResult? Liveness { get; set; }

    [JsonPropertyName("failure_reasons")]
    public List<string> FailureReasons { get; set; } = new();

    [JsonPropertyName("credits_used")]
    public int CreditsUsed { get; set; }
}

/// <summary>
/// Identity verification result.
/// </summary>
public class IdentityVerificationResult
{
    [JsonPropertyName("verification_id")]
    public string VerificationId { get; set; } = "";

    [JsonPropertyName("status")]
    public string StatusRaw { get; set; } = "";

    [JsonIgnore]
    public VerificationStatus Status => EnumExtensions.ParseVerificationStatus(StatusRaw);

    [JsonPropertyName("full_name")]
    public string? FullName { get; set; }

    [JsonPropertyName("date_of_birth")]
    public string? DateOfBirth { get; set; }

    [JsonPropertyName("document_type")]
    public string? DocumentTypeRaw { get; set; }

    [JsonPropertyName("country_code")]
    public string? CountryCode { get; set; }

    [JsonPropertyName("face_match")]
    public FaceMatchResult? FaceMatch { get; set; }

    [JsonPropertyName("liveness")]
    public LivenessResult? Liveness { get; set; }

    [JsonPropertyName("failure_reasons")]
    public List<string> FailureReasons { get; set; } = new();

    [JsonPropertyName("credits_used")]
    public int CreditsUsed { get; set; }
}

/// <summary>
/// Result from polling a verification session.
/// </summary>
public class VerificationSessionResult
{
    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = "";

    [JsonPropertyName("status")]
    public string StatusRaw { get; set; } = "";

    [JsonIgnore]
    public VerificationSessionStatus Status => EnumExtensions.ParseVerificationSessionStatus(StatusRaw);

    [JsonPropertyName("mode")]
    public string ModeRaw { get; set; } = "";

    [JsonIgnore]
    public VerificationMode Mode => EnumExtensions.ParseVerificationMode(ModeRaw);

    /// <summary>Raw verification result (null until there is one). <see cref="GetResult"/> reads it as a typed object.</summary>
    [JsonPropertyName("result")]
    public JsonElement? Result { get; set; }

    /// <summary>Present once there is a result: the check it rests on (<c>full</c> or <c>liveness_only</c>).</summary>
    [JsonPropertyName("verification_mode")]
    public string? VerificationCheck { get; set; }

    /// <summary>Present when the result rests on a document: <c>photo</c>, <c>chip</c> or <c>photo_and_chip</c>.</summary>
    [JsonPropertyName("document_evidence")]
    public string? DocumentEvidence { get; set; }

    /// <summary>Name of the step the user has reached, for progress UI. Not a closed list.</summary>
    [JsonPropertyName("step_progress")]
    public string? StepProgress { get; set; }

    /// <summary>How a chip read counts as document evidence, as set at creation.</summary>
    [JsonPropertyName("chip_policy")]
    public string? ChipPolicy { get; set; }

    /// <summary>How the uploads were captured, as the capture client reported it. Released once, with the result.</summary>
    [JsonPropertyName("capture")]
    public JsonElement? Capture { get; set; }

    /// <summary>Epoch milliseconds when the session was created.</summary>
    [JsonPropertyName("created_at")]
    public long? CreatedAt { get; set; }

    /// <summary>Epoch milliseconds when the session expires.</summary>
    [JsonPropertyName("expires_at")]
    public long? ExpiresAt { get; set; }

    /// <summary>
    /// The verification result as a typed object, or null until there is one. The extracted document fields,
    /// date of birth and failure reasons are released once, on the first poll after the session completes or fails;
    /// persist them on that read or subscribe to the verification.completed webhook.
    /// </summary>
    public VerificationResult? GetResult()
    {
        if (Result is not { ValueKind: JsonValueKind.Object } element) return null;
        return element.Deserialize<VerificationResult>();
    }
}

/// <summary>
/// Range the true age likely falls in, when the age came from the selfie alone.
/// </summary>
public class AgeRange
{
    [JsonPropertyName("low")]
    public double Low { get; set; }

    [JsonPropertyName("high")]
    public double High { get; set; }
}

/// <summary>
/// A national identity number found on the document.
/// </summary>
public class NationalIdResult
{
    [JsonPropertyName("value")]
    public string Value { get; set; } = "";

    /// <summary>Whether the number passed its country's validation.</summary>
    [JsonPropertyName("valid")]
    public bool Valid { get; set; }

    /// <summary>Kind of number (country-specific).</summary>
    [JsonPropertyName("type")]
    public string Type { get; set; } = "";

    [JsonPropertyName("country_code")]
    public string CountryCode { get; set; } = "";
}

/// <summary>
/// Document extraction and validation details. Only <see cref="OcrConfidence"/> is always present;
/// the extracted fields are released once.
/// </summary>
public class DocumentDetails
{
    /// <summary>OCR confidence (0-100).</summary>
    [JsonPropertyName("ocr_confidence")]
    public double OcrConfidence { get; set; }

    [JsonPropertyName("name_extracted")]
    public string? NameExtracted { get; set; }

    [JsonPropertyName("first_name")]
    public string? FirstName { get; set; }

    [JsonPropertyName("last_name")]
    public string? LastName { get; set; }

    [JsonPropertyName("dob_extracted")]
    public string? DobExtracted { get; set; }

    [JsonPropertyName("document_number")]
    public string? DocumentNumber { get; set; }

    [JsonPropertyName("document_number_valid")]
    public bool? DocumentNumberValid { get; set; }

    [JsonPropertyName("sex")]
    public string? Sex { get; set; }

    [JsonPropertyName("country_code")]
    public string? CountryCode { get; set; }

    [JsonPropertyName("country_name")]
    public string? CountryName { get; set; }

    [JsonPropertyName("document_type")]
    public string? DocumentType { get; set; }

    [JsonPropertyName("expiration_date")]
    public string? ExpirationDate { get; set; }

    [JsonPropertyName("expired")]
    public bool? Expired { get; set; }

    [JsonPropertyName("issue_date")]
    public string? IssueDate { get; set; }

    [JsonPropertyName("height_cm")]
    public double? HeightCm { get; set; }

    [JsonPropertyName("place_of_birth")]
    public string? PlaceOfBirth { get; set; }

    [JsonPropertyName("nationality")]
    public string? Nationality { get; set; }

    [JsonPropertyName("issuing_authority")]
    public string? IssuingAuthority { get; set; }

    /// <summary>The document data came from the document's chip and passed its integrity check.</summary>
    [JsonPropertyName("chip_verified")]
    public bool? ChipVerified { get; set; }

    /// <summary>The chip's signer chains to a trusted issuing country. Null when not used or not checkable.</summary>
    [JsonPropertyName("chip_issuer_trusted")]
    public bool? ChipIssuerTrusted { get; set; }

    [JsonPropertyName("national_id")]
    public NationalIdResult? NationalId { get; set; }
}

/// <summary>
/// Verification result carried by a session poll.
/// </summary>
public class VerificationResult
{
    [JsonPropertyName("status")]
    public string StatusRaw { get; set; } = "";

    [JsonIgnore]
    public VerificationStatus Status => EnumExtensions.ParseVerificationStatus(StatusRaw);

    /// <summary>Calculated age (null if not determined).</summary>
    [JsonPropertyName("age")]
    public double? Age { get; set; }

    /// <summary>When the age came from the selfie alone: the range the true age likely falls in.</summary>
    [JsonPropertyName("age_range")]
    public AgeRange? AgeRange { get; set; }

    /// <summary>Date of birth (YYYY-MM-DD). Released once.</summary>
    [JsonPropertyName("date_of_birth")]
    public string? DateOfBirth { get; set; }

    [JsonPropertyName("is_minor")]
    public bool? IsMinor { get; set; }

    /// <summary>What the document evidence was, when the result rests on a document.</summary>
    [JsonPropertyName("document_evidence")]
    public string? DocumentEvidence { get; set; }

    /// <summary>Document details (null when no document was used).</summary>
    [JsonPropertyName("document")]
    public DocumentDetails? Document { get; set; }

    [JsonPropertyName("face_match")]
    public FaceMatchResult? FaceMatch { get; set; }

    [JsonPropertyName("liveness")]
    public LivenessResult? Liveness { get; set; }

    /// <summary>Reasons for any failures. Free text, not a closed list. Released once.</summary>
    [JsonPropertyName("failure_reasons")]
    public List<string>? FailureReasons { get; set; }
}

/// <summary>
/// Result from retrieving a past age verification.
/// </summary>
public class VerificationRetrieveResult
{
    [JsonPropertyName("verification_id")]
    public string VerificationId { get; set; } = "";

    [JsonPropertyName("status")]
    public string StatusRaw { get; set; } = "";

    [JsonIgnore]
    public VerificationStatus Status => EnumExtensions.ParseVerificationStatus(StatusRaw);

    [JsonPropertyName("age")]
    public int? Age { get; set; }

    [JsonPropertyName("is_minor")]
    public bool? IsMinor { get; set; }

    [JsonPropertyName("face_matched")]
    public bool? FaceMatched { get; set; }

    [JsonPropertyName("face_confidence")]
    public double? FaceConfidence { get; set; }

    [JsonPropertyName("liveness_valid")]
    public bool LivenessValid { get; set; }

    [JsonPropertyName("failure_reasons")]
    public List<string> FailureReasons { get; set; } = new();

    [JsonPropertyName("created_at")]
    public string CreatedAt { get; set; } = "";
}

/// <summary>
/// Result from retrieving a past identity verification.
/// </summary>
public class IdentityRetrieveResult
{
    [JsonPropertyName("verification_id")]
    public string VerificationId { get; set; } = "";

    [JsonPropertyName("status")]
    public string StatusRaw { get; set; } = "";

    [JsonIgnore]
    public VerificationStatus Status => EnumExtensions.ParseVerificationStatus(StatusRaw);

    [JsonPropertyName("full_name")]
    public string? FullName { get; set; }

    [JsonPropertyName("date_of_birth")]
    public string? DateOfBirth { get; set; }

    [JsonPropertyName("document_type")]
    public string? DocumentTypeRaw { get; set; }

    [JsonPropertyName("country_code")]
    public string? CountryCode { get; set; }

    [JsonPropertyName("face_matched")]
    public bool? FaceMatched { get; set; }

    [JsonPropertyName("face_confidence")]
    public double? FaceConfidence { get; set; }

    [JsonPropertyName("liveness_valid")]
    public bool LivenessValid { get; set; }

    [JsonPropertyName("failure_reasons")]
    public List<string> FailureReasons { get; set; } = new();

    [JsonPropertyName("created_at")]
    public string CreatedAt { get; set; } = "";
}

/// <summary>
/// Result from cancelling a verification session.
/// </summary>
public class CancelVerificationSessionResult
{
    [JsonPropertyName("ok")]
    public bool Ok { get; set; }
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

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("url")]
    public string Url { get; set; } = "";

    [JsonPropertyName("events")]
    public List<string> Events { get; set; } = new();

    [JsonPropertyName("is_active")]
    public bool IsActive { get; set; }

    /// <summary>Obsolete alias of <see cref="IsActive"/>.</summary>
    [JsonIgnore]
    [Obsolete("Use IsActive.")]
    public bool Active { get => IsActive; set => IsActive = value; }

    [JsonPropertyName("failure_count")]
    public int FailureCount { get; set; }

    [JsonPropertyName("last_triggered_at")]
    public string? LastTriggeredAt { get; set; }

    [JsonPropertyName("last_error")]
    public string? LastError { get; set; }

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
/// Input for creating a webhook. New webhooks are always active.
/// </summary>
public class CreateWebhookInput
{
    /// <summary>Display name (1-100 characters). Required.</summary>
    public string Name { get; set; } = "";
    /// <summary>HTTPS endpoint that receives the events.</summary>
    public string Url { get; set; } = "";
    /// <summary>1 to 5 event names; see <see cref="WebhookEvents"/>.</summary>
    public List<string> Events { get; set; } = new();
    /// <summary>Extra headers sent with each delivery.</summary>
    public Dictionary<string, string>? Headers { get; set; }
}

/// <summary>
/// Result from creating a webhook. <see cref="Secret"/> is only returned here.
/// </summary>
public class CreateWebhookResult
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("url")]
    public string Url { get; set; } = "";

    /// <summary>Signing secret. Store it now: it is not returned again.</summary>
    [JsonPropertyName("secret")]
    public string Secret { get; set; } = "";

    [JsonPropertyName("events")]
    public List<string> Events { get; set; } = new();

    [JsonPropertyName("is_active")]
    public bool IsActive { get; set; }

    [JsonPropertyName("created_at")]
    public string? CreatedAt { get; set; }
}

/// <summary>
/// Input for updating a webhook. Only the fields you set are sent.
/// </summary>
public class UpdateWebhookInput
{
    public string? Name { get; set; }
    public string? Url { get; set; }
    public List<string>? Events { get; set; }
    /// <summary>Turns deliveries on or off. Re-activating resets the failure count.</summary>
    public bool? IsActive { get; set; }
    public Dictionary<string, string>? Headers { get; set; }

    /// <summary>Obsolete alias of <see cref="IsActive"/>.</summary>
    [Obsolete("Use IsActive.")]
    public bool? Active { get => IsActive; set => IsActive = value; }
}

/// <summary>
/// Result from updating a webhook.
/// </summary>
public class UpdateWebhookResult
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("url")]
    public string Url { get; set; } = "";

    [JsonPropertyName("events")]
    public List<string> Events { get; set; } = new();

    [JsonPropertyName("is_active")]
    public bool IsActive { get; set; }

    [JsonPropertyName("updated_at")]
    public string? UpdatedAt { get; set; }
}

/// <summary>
/// Result from deleting a webhook.
/// </summary>
public class DeleteWebhookResult
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("message")]
    public string Message { get; set; } = "";
}

/// <summary>
/// Result from testing a webhook.
/// </summary>
public class TestWebhookResult
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("status_code")]
    public int? StatusCode { get; set; }

    [JsonPropertyName("latency_ms")]
    public double? LatencyMs { get; set; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }
}

/// <summary>
/// Result from regenerating a webhook secret.
/// </summary>
public class RegenerateSecretResult
{
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

/// <summary>
/// Daily usage summary for the current API key.
/// </summary>
public class UsageSummaryResult
{
    [JsonPropertyName("apiKeyId")]
    public string ApiKeyId { get; set; } = "";

    [JsonPropertyName("tier")]
    public string Tier { get; set; } = "";

    [JsonPropertyName("date")]
    public string Date { get; set; } = "";

    [JsonPropertyName("usage")]
    public UsageSummaryCounts Usage { get; set; } = new();

    [JsonPropertyName("quota")]
    public UsageSummaryQuota Quota { get; set; } = new();
}

/// <summary>
/// Request counts for one day.
/// </summary>
public class UsageSummaryCounts
{
    [JsonPropertyName("totalRequests")]
    public long TotalRequests { get; set; }

    [JsonPropertyName("successRequests")]
    public long SuccessRequests { get; set; }

    [JsonPropertyName("errorRequests")]
    public long ErrorRequests { get; set; }
}

/// <summary>
/// Tier limits in a usage summary. -1 means no limit.
/// </summary>
public class UsageSummaryQuota
{
    [JsonPropertyName("requestsPerMinute")]
    public long RequestsPerMinute { get; set; }

    /// <summary>Monthly allowance of the tier. -1 means no limit.</summary>
    [JsonPropertyName("requestsPerMonth")]
    public long RequestsPerMonth { get; set; }

    /// <summary>-1 for a paid tier, which has no daily limit.</summary>
    [JsonPropertyName("requestsPerDay")]
    public long RequestsPerDay { get; set; }

    /// <summary>-1 for a paid tier, which has no daily limit.</summary>
    [JsonPropertyName("remainingToday")]
    public long RemainingToday { get; set; }
}

/// <summary>
/// Real-time rate limit and quota status.
/// </summary>
public class UsageQuotaResult
{
    [JsonPropertyName("apiKeyId")]
    public string ApiKeyId { get; set; } = "";

    [JsonPropertyName("tier")]
    public string Tier { get; set; } = "";

    /// <summary>Seconds until the per-minute rate limit window resets.</summary>
    [JsonPropertyName("resetsInSeconds")]
    public double? ResetsInSeconds { get; set; }

    [JsonPropertyName("limits")]
    public UsageQuotaLimits Limits { get; set; } = new();

    [JsonPropertyName("current")]
    public UsageQuotaCounts Current { get; set; } = new();

    [JsonPropertyName("remaining")]
    public UsageQuotaCounts Remaining { get; set; } = new();
}

/// <summary>
/// Tier limits in a quota status. -1 means no limit.
/// </summary>
public class UsageQuotaLimits
{
    [JsonPropertyName("requestsPerMinute")]
    public long RequestsPerMinute { get; set; }

    [JsonPropertyName("requestsPerMonth")]
    public long RequestsPerMonth { get; set; }

    [JsonPropertyName("requestsPerDay")]
    public long RequestsPerDay { get; set; }
}

/// <summary>
/// Request counts in a quota status.
/// </summary>
public class UsageQuotaCounts
{
    [JsonPropertyName("requestsThisMinute")]
    public long RequestsThisMinute { get; set; }

    [JsonPropertyName("requestsToday")]
    public long RequestsToday { get; set; }
}

// =============================================================================
// Distress Signals
// =============================================================================

/// <summary>
/// Result of distress signal detection.
/// </summary>
public class DistressSignalsResult : DetectionResult
{
    /// <summary>
    /// How the distress words are used: <c>literal_present</c>, <c>about_other</c>, <c>past_resolved</c>,
    /// <c>figurative</c>, <c>quoted</c> or <c>none</c>.
    /// </summary>
    [JsonPropertyName("distress_reading")]
    public string? DistressReading { get; init; }

    /// <summary>Who the distress is about: <c>speaker</c> or <c>other_party</c>.</summary>
    [JsonPropertyName("distress_subject")]
    public string? DistressSubject { get; init; }

    /// <summary>True when a supportive check-in is suggested rather than a moderation case.</summary>
    [JsonPropertyName("support_suggested")]
    public bool? SupportSuggested { get; init; }
}

// =============================================================================
// Incidents
// =============================================================================

/// <summary>
/// Filters and paging for listing incidents. Every filter is optional.
/// </summary>
public class ListIncidentsInput
{
    /// <summary>Filter by risk category (e.g. "bullying", "grooming").</summary>
    public string? Category { get; set; }
    /// <summary>Filter by risk level: low, moderate (or medium), high, critical.</summary>
    public string? Severity { get; set; }
    /// <summary>Filter by moderation status: new, reviewed, escalated, resolved, dismissed.</summary>
    public string? Status { get; set; }
    /// <summary>Filter by source: text, voice, image, video, video_stream.</summary>
    public string? Source { get; set; }
    /// <summary>ISO 8601 inclusive lower bound on created_at.</summary>
    public string? From { get; set; }
    /// <summary>ISO 8601 exclusive upper bound on created_at.</summary>
    public string? To { get; set; }
    public string? Platform { get; set; }
    public string? ExternalId { get; set; }
    public string? CustomerId { get; set; }
    /// <summary>1 to 100 rows per page (API default 25).</summary>
    public int? Limit { get; set; }
    /// <summary>The previous page's <see cref="ListIncidentsResult.NextCursor"/>.</summary>
    public string? Cursor { get; set; }
    /// <summary>Include the decrypted summary on each row. Costs an extra credit per row.</summary>
    public bool IncludeSummary { get; set; }
}

/// <summary>
/// One incident in a listing.
/// </summary>
public class IncidentSummary
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("risk_category")]
    public string RiskCategory { get; set; } = "";

    /// <summary>Stored risk level: low, moderate, high or critical.</summary>
    [JsonPropertyName("risk_level")]
    public string RiskLevel { get; set; } = "";

    [JsonPropertyName("confidence_score")]
    public double? ConfidenceScore { get; set; }

    [JsonPropertyName("detected_patterns")]
    public List<string> DetectedPatterns { get; set; } = new();

    [JsonPropertyName("recommended_actions")]
    public List<string> RecommendedActions { get; set; } = new();

    [JsonPropertyName("platform")]
    public string? Platform { get; set; }

    [JsonPropertyName("language")]
    public string? Language { get; set; }

    [JsonPropertyName("source")]
    public string Source { get; set; } = "";

    [JsonPropertyName("file_id")]
    public string? FileId { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = "";

    /// <summary>Your policy rules' verdict on this incident; null when no rule matched.</summary>
    [JsonPropertyName("policy_action")]
    public JsonElement? PolicyAction { get; set; }

    /// <summary>Advisory next status for a moderator. Never applied automatically.</summary>
    [JsonPropertyName("recommended_status")]
    public string? RecommendedStatus { get; set; }

    [JsonPropertyName("speaker_stance")]
    public string? SpeakerStance { get; set; }

    /// <summary>True when the incident came from a non-production API key.</summary>
    [JsonPropertyName("is_test")]
    public bool? IsTest { get; set; }

    [JsonPropertyName("external_id")]
    public string? ExternalId { get; set; }

    [JsonPropertyName("customer_id")]
    public string? CustomerId { get; set; }

    [JsonPropertyName("created_at")]
    public string CreatedAt { get; set; } = "";

    /// <summary>Summary text, or an encrypted envelope for accounts with their own key. Present when requested.</summary>
    [JsonPropertyName("summary")]
    public JsonElement? Summary { get; set; }

    /// <summary>Fields returned as envelopes you decrypt with your registered private key.</summary>
    [JsonPropertyName("_e2e_envelope_fields")]
    public List<string>? E2eEnvelopeFields { get; set; }
}

/// <summary>
/// A page of incidents, newest first.
/// </summary>
public class ListIncidentsResult
{
    [JsonPropertyName("incidents")]
    public List<IncidentSummary> Incidents { get; set; } = new();

    /// <summary>Pass back as <see cref="ListIncidentsInput.Cursor"/>; null when there are no more pages.</summary>
    [JsonPropertyName("next_cursor")]
    public string? NextCursor { get; set; }

    [JsonPropertyName("total_returned")]
    public int TotalReturned { get; set; }
}

/// <summary>
/// Risk score and flags for one message of a multi-turn incident.
/// </summary>
public class IncidentMessageAnalysis
{
    [JsonPropertyName("message_index")]
    public int MessageIndex { get; set; }

    [JsonPropertyName("risk_score")]
    public double RiskScore { get; set; }

    [JsonPropertyName("flags")]
    public List<string> Flags { get; set; } = new();
}

/// <summary>
/// Full detail of one incident.
/// </summary>
public class IncidentDetail : IncidentSummary
{
    [JsonPropertyName("metadata")]
    public JsonElement? Metadata { get; set; }

    [JsonPropertyName("source_data")]
    public JsonElement? SourceData { get; set; }

    [JsonPropertyName("visual_categories")]
    public List<string>? VisualCategories { get; set; }

    [JsonPropertyName("visual_severity")]
    public string? VisualSeverity { get; set; }

    [JsonPropertyName("visual_confidence")]
    public double? VisualConfidence { get; set; }

    [JsonPropertyName("emotional_indicators")]
    public List<string>? EmotionalIndicators { get; set; }

    [JsonPropertyName("review")]
    public JsonElement? Review { get; set; }

    /// <summary>Per-message trajectory for multi-turn incidents; null for single-turn ones.</summary>
    [JsonPropertyName("message_analysis")]
    public List<IncidentMessageAnalysis>? MessageAnalysis { get; set; }
}

/// <summary>
/// A time window.
/// </summary>
public class IncidentTimeframe
{
    [JsonPropertyName("from")]
    public string From { get; set; } = "";

    [JsonPropertyName("to")]
    public string To { get; set; } = "";
}

/// <summary>
/// Incident count for one platform.
/// </summary>
public class IncidentPlatformCount
{
    [JsonPropertyName("platform")]
    public string Platform { get; set; } = "";

    [JsonPropertyName("count")]
    public int Count { get; set; }
}

/// <summary>
/// Incident KPIs over a time window (default: the last 30 days).
/// </summary>
public class IncidentsOverview
{
    [JsonPropertyName("timeframe")]
    public IncidentTimeframe Timeframe { get; set; } = new();

    [JsonPropertyName("total_incidents")]
    public int TotalIncidents { get; set; }

    /// <summary>High and critical incidents nobody has acted on yet.</summary>
    [JsonPropertyName("requires_review_count")]
    public int RequiresReviewCount { get; set; }

    [JsonPropertyName("last_24h_count")]
    public int Last24hCount { get; set; }

    [JsonPropertyName("last_7d_count")]
    public int Last7dCount { get; set; }

    [JsonPropertyName("last_30d_count")]
    public int Last30dCount { get; set; }

    [JsonPropertyName("counts_by_category")]
    public Dictionary<string, int> CountsByCategory { get; set; } = new();

    [JsonPropertyName("counts_by_severity")]
    public Dictionary<string, int> CountsBySeverity { get; set; } = new();

    [JsonPropertyName("counts_by_source")]
    public Dictionary<string, int> CountsBySource { get; set; } = new();

    [JsonPropertyName("counts_by_status")]
    public Dictionary<string, int> CountsByStatus { get; set; } = new();

    /// <summary>Top 5 platforms by incident count, descending.</summary>
    [JsonPropertyName("top_platforms")]
    public List<IncidentPlatformCount> TopPlatforms { get; set; } = new();
}

/// <summary>
/// One bucket of an incident trend series.
/// </summary>
public class IncidentTrendsBucket
{
    [JsonPropertyName("bucket_start")]
    public string BucketStart { get; set; } = "";

    [JsonPropertyName("total")]
    public int Total { get; set; }

    [JsonPropertyName("by_severity")]
    public Dictionary<string, int> BySeverity { get; set; } = new();
}

/// <summary>
/// Time-bucketed incident counts.
/// </summary>
public class IncidentTrends
{
    /// <summary>hour, day or week.</summary>
    [JsonPropertyName("bucket_size")]
    public string BucketSize { get; set; } = "";

    [JsonPropertyName("timeframe")]
    public IncidentTimeframe Timeframe { get; set; } = new();

    [JsonPropertyName("series")]
    public List<IncidentTrendsBucket> Series { get; set; } = new();
}

/// <summary>
/// A moderator review of an incident.
/// </summary>
public class ReviewIncidentInput
{
    public ModeratorAction Action { get; set; }
    public ModeratorReasonCode ReasonCode { get; set; }
    /// <summary>Free-form comment (max 4000 characters).</summary>
    public string? ReasonComment { get; set; }
    /// <summary>New risk level: required for downgrade and escalate.</summary>
    public string? NewRiskLevel { get; set; }
    /// <summary>New category: required for reclassify.</summary>
    public string? NewRiskCategory { get; set; }
    /// <summary>
    /// Stable identifier of the moderator making the decision. Required, so the audit trail can attribute it.
    /// Use a per-moderator identifier, not the account owner.
    /// </summary>
    public string ModeratorExternalId { get; set; } = "";
    /// <summary>Retention class for the audit receipt: biometric-high-risk, safety-high-risk, limited-risk (default) or minimal-risk.</summary>
    public string? RetentionClass { get; set; }
}

/// <summary>
/// The same moderator review applied to up to 100 incidents.
/// </summary>
public class BatchReviewIncidentsInput : ReviewIncidentInput
{
    /// <summary>1 to 100 incident IDs.</summary>
    public List<string> IncidentIds { get; set; } = new();
}

/// <summary>
/// An incident's category and level at one point in time.
/// </summary>
public class IncidentClassification
{
    [JsonPropertyName("risk_category")]
    public string RiskCategory { get; set; } = "";

    [JsonPropertyName("risk_level")]
    public string RiskLevel { get; set; } = "";
}

/// <summary>
/// Reference to the signed audit receipt for a review.
/// </summary>
public class AuditReceiptReference
{
    [JsonPropertyName("request_id")]
    public string RequestId { get; set; } = "";

    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = "";

    [JsonPropertyName("signature")]
    public string Signature { get; set; } = "";
}

/// <summary>
/// Result of reviewing one incident.
/// </summary>
public class ReviewIncidentResult
{
    [JsonPropertyName("incident_id")]
    public string IncidentId { get; set; } = "";

    [JsonPropertyName("original")]
    public IncidentClassification? Original { get; set; }

    [JsonPropertyName("revised")]
    public IncidentClassification? Revised { get; set; }

    /// <summary>Null if the receipt write failed but the review succeeded.</summary>
    [JsonPropertyName("audit_receipt")]
    public AuditReceiptReference? AuditReceipt { get; set; }
}

/// <summary>
/// Outcome for one incident in a batch review.
/// </summary>
public class BatchReviewItemResult : ReviewIncidentResult
{
    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    /// <summary>Present when <see cref="Ok"/> is false.</summary>
    [JsonPropertyName("error")]
    public string? Error { get; set; }
}

/// <summary>
/// Result of a batch review.
/// </summary>
public class BatchReviewIncidentsResult
{
    [JsonPropertyName("total")]
    public int Total { get; set; }

    [JsonPropertyName("succeeded")]
    public int Succeeded { get; set; }

    [JsonPropertyName("failed")]
    public int Failed { get; set; }

    /// <summary>Per-incident outcome in input order.</summary>
    [JsonPropertyName("results")]
    public List<BatchReviewItemResult> Results { get; set; } = new();
}

// =============================================================================
// Image Verification
// =============================================================================

/// <summary>
/// Input for image verification. Images are processed in memory and never stored.
/// </summary>
public class VerifyImageMatchInput
{
    /// <summary>The image to check.</summary>
    public required byte[] Image { get; init; }
    /// <summary>A reference image for face matching. The face match check only runs when this is set.</summary>
    public byte[]? ReferenceImage { get; init; }
    /// <summary>Checks to run. All of them when omitted.</summary>
    public List<ImageMatchCheck>? Checks { get; init; }
}

/// <summary>
/// Face match between the image and the reference image.
/// </summary>
public class ImageFaceMatch
{
    [JsonPropertyName("matched")]
    public bool Matched { get; set; }

    /// <summary>1 minus the face distance. Prefer <see cref="MatchScore"/>.</summary>
    [JsonPropertyName("similarity")]
    public double? Similarity { get; set; }

    /// <summary>How strongly the faces match (0-1): 0.5 at the match decision.</summary>
    [JsonPropertyName("match_score")]
    public double? MatchScore { get; set; }

    /// <summary>Why matching failed (e.g. "no_face_detected").</summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; set; }
}

/// <summary>
/// Estimated age of the detected face.
/// </summary>
public class ImageAgeEstimate
{
    [JsonPropertyName("estimated_age")]
    public double EstimatedAge { get; set; }

    /// <summary>Face detection confidence (0-1).</summary>
    [JsonPropertyName("confidence")]
    public double Confidence { get; set; }
}

/// <summary>
/// Explicit content and skin exposure checks.
/// </summary>
public class ImageForensics
{
    [JsonPropertyName("nsfw")]
    public bool Nsfw { get; set; }

    [JsonPropertyName("nsfw_confidence")]
    public double? NsfwConfidence { get; set; }

    /// <summary>low, moderate or high.</summary>
    [JsonPropertyName("skin_exposure_level")]
    public string? SkinExposureLevel { get; set; }
}

/// <summary>
/// Synthetic image checks, including content provenance.
/// </summary>
public class ImageSyntheticCheck
{
    [JsonPropertyName("is_synthetic")]
    public bool? IsSynthetic { get; set; }

    [JsonPropertyName("synthetic_probability")]
    public double? SyntheticProbability { get; set; }

    /// <summary>A C2PA (Content Credentials) manifest is embedded.</summary>
    [JsonPropertyName("has_c2pa")]
    public bool? HasC2pa { get; set; }

    /// <summary>The C2PA manifest declares AI generation.</summary>
    [JsonPropertyName("is_ai_generated")]
    public bool? IsAiGenerated { get; set; }
}

/// <summary>
/// Result of image verification. Each check's field is null when that check did not run.
/// </summary>
public class VerifyImageMatchResult
{
    [JsonPropertyName("schema_version")]
    public string SchemaVersion { get; set; } = "";

    /// <summary>The checks that ran. face_match is left out when no reference image was sent.</summary>
    [JsonPropertyName("checks_run")]
    public List<string> ChecksRun { get; set; } = new();

    [JsonPropertyName("face_match")]
    public ImageFaceMatch? FaceMatch { get; set; }

    /// <summary>Null when the age check ran but found no face.</summary>
    [JsonPropertyName("age")]
    public ImageAgeEstimate? Age { get; set; }

    [JsonPropertyName("forensic")]
    public ImageForensics? Forensic { get; set; }

    [JsonPropertyName("synthetic")]
    public ImageSyntheticCheck? Synthetic { get; set; }

    [JsonPropertyName("credits_used")]
    public int CreditsUsed { get; set; }

    [JsonPropertyName("processing_ms")]
    public double ProcessingMs { get; set; }
}

// =============================================================================
// Privacy
// =============================================================================

/// <summary>
/// Input for personal data redaction. Send exactly one of <see cref="Text"/> or <see cref="Messages"/>.
/// </summary>
public class RedactInput
{
    /// <summary>One text to redact (max 10,000 characters).</summary>
    public string? Text { get; init; }
    /// <summary>The messages of one conversation, in order (1 to 100). The same value gets the same placeholder in every message.</summary>
    public List<string>? Messages { get; init; }
    /// <summary>Two-letter language code, when known.</summary>
    public string? Language { get; init; }
    /// <summary>Redaction mode. The API defaults to <see cref="RedactMode.Protective"/>.</summary>
    public RedactMode? Mode { get; init; }
    /// <summary>
    /// Also removes age, school year, gender, nationality, everyday places and health details.
    /// Safety analysis reads these, so use it only for text shared after analysis.
    /// </summary>
    public bool? StrictAnonymisation { get; init; }
}

/// <summary>
/// Result of personal data redaction.
/// </summary>
public class RedactResult
{
    /// <summary>The redacted text, when <see cref="RedactInput.Text"/> was sent.</summary>
    [JsonPropertyName("text")]
    public string? Text { get; set; }

    /// <summary>The redacted messages, when <see cref="RedactInput.Messages"/> was sent.</summary>
    [JsonPropertyName("messages")]
    public List<string>? Messages { get; set; }

    /// <summary>Replaced occurrences per type.</summary>
    [JsonPropertyName("counts")]
    public Dictionary<string, int> Counts { get; set; } = new();

    [JsonPropertyName("entities_total")]
    public int EntitiesTotal { get; set; }

    [JsonPropertyName("mode")]
    public string Mode { get; set; } = "";

    [JsonPropertyName("strict_anonymisation")]
    public bool StrictAnonymisation { get; set; }

    /// <summary>True when full name and place recognition ran. When false, names and places are still removed, with lower coverage.</summary>
    [JsonPropertyName("model_applied")]
    public bool ModelApplied { get; set; }

    [JsonPropertyName("credits_used")]
    public int CreditsUsed { get; set; }
}

// =============================================================================
// Document Analysis
// =============================================================================

/// <summary>
/// Valid endpoint names for document analysis.
/// </summary>
public static class DocumentEndpointName
{
    public const string Unsafe = "unsafe";
    public const string Bullying = "bullying";
    public const string Grooming = "grooming";
    public const string SocialEngineering = "social-engineering";
    public const string CoerciveControl = "coercive-control";
    public const string Radicalisation = "radicalisation";
    public const string RomanceScam = "romance-scam";
    public const string MuleRecruitment = "mule-recruitment";

    /// <summary>Returns all valid endpoint names.</summary>
    public static readonly string[] All = new[]
    {
        Unsafe, Bullying, Grooming, SocialEngineering,
        CoerciveControl, Radicalisation, RomanceScam, MuleRecruitment
    };
}

/// <summary>
/// Input for document safety analysis. Accepts a PDF or a single PNG, JPEG or WebP image.
/// </summary>
public class AnalyzeDocumentInput
{
    /// <summary>PDF or image file contents.</summary>
    public required byte[] File { get; init; }

    /// <summary>Original filename (e.g., "report.pdf").</summary>
    public required string Filename { get; init; }

    /// <summary>Detection endpoints to run on each page. Defaults to unsafe, coercive-control, radicalisation.</summary>
    public List<string>? Endpoints { get; init; }

    /// <summary>Customer-provided file reference ID (echoed in response).</summary>
    public string? FileId { get; init; }

    /// <summary>Age group for calibrated analysis (e.g. "7-10", "11-13", "14-17").</summary>
    public string? AgeGroup { get; init; }

    /// <summary>Language hint (ISO 639-1). Auto-detected if omitted.</summary>
    public string? Language { get; init; }

    /// <summary>Platform name.</summary>
    public string? Platform { get; init; }

    /// <summary>Minimum severity to include crisis helplines: low, medium, high (default) or critical.</summary>
    public string? SupportThreshold { get; init; }

    /// <summary>Images only: split a messaging screenshot into messages with a side attributed to each. Costs one additional call.</summary>
    public bool SplitBySender { get; init; }

    /// <summary>Your unique identifier for correlation with your systems (max 255 chars).</summary>
    public string? ExternalId { get; init; }

    /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
    public string? CustomerId { get; init; }

    /// <summary>Arbitrary key-value pairs for your own use.</summary>
    public Dictionary<string, object>? Metadata { get; init; }
}

/// <summary>
/// Breakdown of how text was extracted from the document pages.
/// </summary>
public class DocumentExtractionSummary
{
    /// <summary>Pages where text was extracted from the PDF text layer.</summary>
    [JsonPropertyName("text_layer_pages")]
    public int TextLayerPages { get; set; }

    /// <summary>Pages where OCR was used.</summary>
    [JsonPropertyName("ocr_pages")]
    public int OcrPages { get; set; }

    /// <summary>Pages with insufficient text for analysis.</summary>
    [JsonPropertyName("failed_pages")]
    public int FailedPages { get; set; }

    /// <summary>Average OCR confidence (0.0-1.0) across OCR pages.</summary>
    [JsonPropertyName("average_ocr_confidence")]
    public double AverageOcrConfidence { get; set; }
}

/// <summary>
/// Detection result for a single endpoint on a single page.
/// </summary>
public class DocumentPageEndpointResult
{
    /// <summary>Endpoint name.</summary>
    [JsonPropertyName("endpoint")]
    public string Endpoint { get; set; } = "";

    /// <summary>Whether a threat was detected.</summary>
    [JsonPropertyName("detected")]
    public bool Detected { get; set; }

    /// <summary>Severity score (0-1).</summary>
    [JsonPropertyName("severity")]
    public double Severity { get; set; }

    /// <summary>Confidence score (0-1).</summary>
    [JsonPropertyName("confidence")]
    public double Confidence { get; set; }

    /// <summary>Risk score (0-1).</summary>
    [JsonPropertyName("risk_score")]
    public double RiskScore { get; set; }

    /// <summary>Risk level.</summary>
    [JsonPropertyName("level")]
    public string Level { get; set; } = "";

    /// <summary>Detected categories.</summary>
    [JsonPropertyName("categories")]
    public List<DetectionCategory> Categories { get; set; } = new();

    /// <summary>Evidence excerpts.</summary>
    [JsonPropertyName("evidence")]
    public List<DetectionEvidence> Evidence { get; set; } = new();

    /// <summary>Recommended action.</summary>
    [JsonPropertyName("recommended_action")]
    public string RecommendedAction { get; set; } = "";

    /// <summary>Human-readable rationale.</summary>
    [JsonPropertyName("rationale")]
    public string Rationale { get; set; } = "";
}

/// <summary>
/// Analysis result for a single page of a document.
/// </summary>
public class DocumentPageResult
{
    /// <summary>Page number (1-indexed).</summary>
    [JsonPropertyName("page_number")]
    public int PageNumber { get; set; }

    /// <summary>First 200 characters of page text.</summary>
    [JsonPropertyName("text_preview")]
    public string TextPreview { get; set; } = "";

    /// <summary>How text was extracted (text_layer or ocr).</summary>
    [JsonPropertyName("extraction_method")]
    public string ExtractionMethod { get; set; } = "";

    /// <summary>OCR confidence if applicable.</summary>
    [JsonPropertyName("ocr_confidence")]
    public double? OcrConfidence { get; set; }

    /// <summary>Detection results per endpoint.</summary>
    [JsonPropertyName("results")]
    public List<DocumentPageEndpointResult> Results { get; set; } = new();

    /// <summary>Highest risk score on this page.</summary>
    [JsonPropertyName("page_risk_score")]
    public double PageRiskScore { get; set; }

    /// <summary>Page severity level.</summary>
    [JsonPropertyName("page_severity")]
    public string PageSeverity { get; set; } = "";
}

/// <summary>
/// A flagged page with elevated risk.
/// </summary>
public class DocumentFlaggedPage
{
    /// <summary>Page number.</summary>
    [JsonPropertyName("page_number")]
    public int PageNumber { get; set; }

    /// <summary>Risk score.</summary>
    [JsonPropertyName("risk_score")]
    public double RiskScore { get; set; }

    /// <summary>Severity level.</summary>
    [JsonPropertyName("severity")]
    public string Severity { get; set; } = "";

    /// <summary>Endpoints that detected threats on this page.</summary>
    [JsonPropertyName("detected_endpoints")]
    public List<string> DetectedEndpoints { get; set; } = new();
}

/// <summary>
/// Result of document safety analysis.
/// </summary>
public class DocumentAnalysisResult
{
    /// <summary>Customer-provided file reference (if provided).</summary>
    [JsonPropertyName("file_id")]
    public string? FileId { get; set; }

    /// <summary>SHA-256 hash of the uploaded file for chain-of-custody verification.</summary>
    [JsonPropertyName("document_hash")]
    public string DocumentHash { get; set; } = "";

    /// <summary>Total pages in the document.</summary>
    [JsonPropertyName("total_pages")]
    public int TotalPages { get; set; }

    /// <summary>Pages with extractable text that were analyzed.</summary>
    [JsonPropertyName("pages_analyzed")]
    public int PagesAnalyzed { get; set; }

    /// <summary>Breakdown of text extraction results.</summary>
    [JsonPropertyName("extraction_summary")]
    public DocumentExtractionSummary ExtractionSummary { get; set; } = new();

    /// <summary>Per-page detection results.</summary>
    [JsonPropertyName("page_results")]
    public List<DocumentPageResult> PageResults { get; set; } = new();

    /// <summary>Highest risk score across all pages (0-1).</summary>
    [JsonPropertyName("overall_risk_score")]
    public double OverallRiskScore { get; set; }

    /// <summary>Overall severity level: none, low, medium, high or critical.</summary>
    [JsonPropertyName("overall_severity")]
    public string OverallSeverity { get; set; } = "";

    /// <summary>Unique list of endpoints that detected threats.</summary>
    [JsonPropertyName("detected_endpoints")]
    public List<string> DetectedEndpoints { get; set; } = new();

    /// <summary>Pages with elevated risk.</summary>
    [JsonPropertyName("flagged_pages")]
    public List<DocumentFlaggedPage> FlaggedPages { get; set; } = new();

    /// <summary>Dynamic credit cost based on pages analyzed and endpoints used.</summary>
    [JsonPropertyName("credits_used")]
    public int CreditsUsed { get; set; }

    /// <summary>Processing time in milliseconds.</summary>
    [JsonPropertyName("processing_time_ms")]
    public long ProcessingTimeMs { get; set; }

    /// <summary>Detected language.</summary>
    [JsonPropertyName("language")]
    public string? Language { get; set; }

    /// <summary>Language support status.</summary>
    [JsonPropertyName("language_status")]
    public string? LanguageStatus { get; set; }

    /// <summary>Crisis support resources (if triggered).</summary>
    [JsonPropertyName("support")]
    public JsonElement? Support { get; set; }

    /// <summary>Echo of provided external_id.</summary>
    [JsonPropertyName("external_id")]
    public string? ExternalId { get; set; }

    /// <summary>Echo of provided customer_id.</summary>
    [JsonPropertyName("customer_id")]
    public string? CustomerId { get; set; }

    /// <summary>Echo of provided metadata.</summary>
    [JsonPropertyName("metadata")]
    public JsonElement? Metadata { get; set; }
}
