namespace Tuteliq;

/// <summary>
/// Severity levels for safety detections.
/// </summary>
public enum Severity
{
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Grooming risk assessment levels.
/// </summary>
public enum GroomingRisk
{
    None,
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Overall risk level for combined analysis.
/// </summary>
public enum RiskLevel
{
    Safe,
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Categories of safety risks.
/// </summary>
public enum RiskCategory
{
    Bullying,
    Grooming,
    Unsafe,
    SelfHarm,
    Other
}

/// <summary>
/// Types of safety analysis.
/// </summary>
public enum AnalysisType
{
    Bullying,
    Grooming,
    Unsafe,
    Emotions
}

/// <summary>
/// Emotional trend direction.
/// </summary>
public enum EmotionTrend
{
    Improving,
    Stable,
    Worsening
}

/// <summary>
/// Target audience for action plans.
/// </summary>
public enum Audience
{
    Child,
    Parent,
    Educator,
    Platform
}

/// <summary>
/// Incident tracking status.
/// </summary>
public enum IncidentStatus
{
    New,
    Reviewed,
    Resolved
}

/// <summary>
/// Role of a message sender in grooming detection.
/// </summary>
public enum MessageRole
{
    Adult,
    Child,
    Unknown
}

/// <summary>
/// Webhook event types.
/// </summary>
public enum WebhookEventType
{
    IncidentCritical,
    IncidentHigh,
    GroomingDetected,
    SelfHarmDetected,
    BullyingSevere
}

/// <summary>
/// Supported languages for analysis.
/// </summary>
public enum Language
{
    En, Es, Pt, Uk, Sv, No, Da, Fi, De, Fr
}

/// <summary>
/// Language support stability status.
/// </summary>
public enum LanguageStatus
{
    Stable,
    Beta
}

/// <summary>
/// Detection endpoint types for fraud and extended safety analysis.
/// </summary>
public enum Detection
{
    Bullying,
    Grooming,
    Unsafe,
    SocialEngineering,
    AppFraud,
    RomanceScam,
    MuleRecruitment,
    GamblingHarm,
    CoerciveControl,
    VulnerabilityExploitation,
    Radicalisation
}

/// <summary>
/// Account tier levels.
/// </summary>
public enum Tier
{
    Starter,
    Indie,
    Pro,
    Business,
    Enterprise
}

internal static class EnumExtensions
{
    public static string ToApiString(this Severity value) => value switch
    {
        Severity.Low => "low",
        Severity.Medium => "medium",
        Severity.High => "high",
        Severity.Critical => "critical",
        _ => "low"
    };

    public static string ToApiString(this GroomingRisk value) => value switch
    {
        GroomingRisk.None => "none",
        GroomingRisk.Low => "low",
        GroomingRisk.Medium => "medium",
        GroomingRisk.High => "high",
        GroomingRisk.Critical => "critical",
        _ => "none"
    };

    public static string ToApiString(this RiskLevel value) => value switch
    {
        RiskLevel.Safe => "safe",
        RiskLevel.Low => "low",
        RiskLevel.Medium => "medium",
        RiskLevel.High => "high",
        RiskLevel.Critical => "critical",
        _ => "safe"
    };

    public static string ToApiString(this Audience value) => value switch
    {
        Audience.Child => "child",
        Audience.Parent => "parent",
        Audience.Educator => "educator",
        Audience.Platform => "platform",
        _ => "parent"
    };

    public static string ToApiString(this MessageRole value) => value switch
    {
        MessageRole.Adult => "adult",
        MessageRole.Child => "child",
        MessageRole.Unknown => "unknown",
        _ => "unknown"
    };

    public static string ToApiString(this WebhookEventType value) => value switch
    {
        WebhookEventType.IncidentCritical => "incident.critical",
        WebhookEventType.IncidentHigh => "incident.high",
        WebhookEventType.GroomingDetected => "grooming.detected",
        WebhookEventType.SelfHarmDetected => "self_harm.detected",
        WebhookEventType.BullyingSevere => "bullying.severe",
        _ => "incident.critical"
    };

    public static string ToApiString(this Detection value) => value switch
    {
        Detection.Bullying => "bullying",
        Detection.Grooming => "grooming",
        Detection.Unsafe => "unsafe",
        Detection.SocialEngineering => "social-engineering",
        Detection.AppFraud => "app-fraud",
        Detection.RomanceScam => "romance-scam",
        Detection.MuleRecruitment => "mule-recruitment",
        Detection.GamblingHarm => "gambling-harm",
        Detection.CoerciveControl => "coercive-control",
        Detection.VulnerabilityExploitation => "vulnerability-exploitation",
        Detection.Radicalisation => "radicalisation",
        _ => "bullying"
    };

    public static string ToApiString(this Language value) => value switch
    {
        Language.En => "en",
        Language.Es => "es",
        Language.Pt => "pt",
        Language.Uk => "uk",
        Language.Sv => "sv",
        Language.No => "no",
        Language.Da => "da",
        Language.Fi => "fi",
        Language.De => "de",
        Language.Fr => "fr",
        _ => "en"
    };

    public static string ToApiString(this LanguageStatus value) => value switch
    {
        LanguageStatus.Stable => "stable",
        LanguageStatus.Beta => "beta",
        _ => "stable"
    };

    public static string ToApiString(this Tier value) => value switch
    {
        Tier.Starter => "starter",
        Tier.Indie => "indie",
        Tier.Pro => "pro",
        Tier.Business => "business",
        Tier.Enterprise => "enterprise",
        _ => "starter"
    };

    public static Severity ParseSeverity(string? value) => value?.ToLowerInvariant() switch
    {
        "low" => Severity.Low,
        "medium" => Severity.Medium,
        "high" => Severity.High,
        "critical" => Severity.Critical,
        _ => Severity.Low
    };

    public static GroomingRisk ParseGroomingRisk(string? value) => value?.ToLowerInvariant() switch
    {
        "none" => GroomingRisk.None,
        "low" => GroomingRisk.Low,
        "medium" => GroomingRisk.Medium,
        "high" => GroomingRisk.High,
        "critical" => GroomingRisk.Critical,
        _ => GroomingRisk.None
    };

    public static RiskLevel ParseRiskLevel(string? value) => value?.ToLowerInvariant() switch
    {
        "safe" => RiskLevel.Safe,
        "low" => RiskLevel.Low,
        "medium" or "moderate" => RiskLevel.Medium,
        "high" => RiskLevel.High,
        "critical" => RiskLevel.Critical,
        _ => RiskLevel.Safe
    };

    public static EmotionTrend ParseEmotionTrend(string? value) => value?.ToLowerInvariant() switch
    {
        "improving" => EmotionTrend.Improving,
        "stable" => EmotionTrend.Stable,
        "worsening" => EmotionTrend.Worsening,
        _ => EmotionTrend.Stable
    };

    public static LanguageStatus ParseLanguageStatus(string? value) => value?.ToLowerInvariant() switch
    {
        "stable" => LanguageStatus.Stable,
        "beta" => LanguageStatus.Beta,
        _ => LanguageStatus.Stable
    };
}
