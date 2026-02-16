using System.Text.Json.Serialization;

namespace Tuteliq
{
    public class VoiceStreamConfig
    {
        [JsonPropertyName("interval_seconds")]
        public int? IntervalSeconds { get; set; }

        [JsonPropertyName("analysis_types")]
        public List<string>? AnalysisTypes { get; set; }

        [JsonPropertyName("context")]
        public VoiceStreamContext? Context { get; set; }
    }

    public class VoiceStreamContext
    {
        [JsonPropertyName("language")]
        public string? Language { get; set; }

        [JsonPropertyName("age_group")]
        public string? AgeGroup { get; set; }

        [JsonPropertyName("relationship")]
        public string? Relationship { get; set; }

        [JsonPropertyName("platform")]
        public string? Platform { get; set; }
    }

    public class VoiceReadyEvent
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = "";

        [JsonPropertyName("session_id")]
        public string SessionId { get; set; } = "";

        [JsonPropertyName("config")]
        public VoiceStreamConfigInfo? Config { get; set; }
    }

    public class VoiceStreamConfigInfo
    {
        [JsonPropertyName("interval_seconds")]
        public int IntervalSeconds { get; set; }

        [JsonPropertyName("analysis_types")]
        public List<string> AnalysisTypes { get; set; } = new();
    }

    public class VoiceTranscriptionSegment
    {
        [JsonPropertyName("start")]
        public double Start { get; set; }

        [JsonPropertyName("end")]
        public double End { get; set; }

        [JsonPropertyName("text")]
        public string Text { get; set; } = "";
    }

    public class VoiceTranscriptionEvent
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = "";

        [JsonPropertyName("text")]
        public string Text { get; set; } = "";

        [JsonPropertyName("segments")]
        public List<VoiceTranscriptionSegment> Segments { get; set; } = new();

        [JsonPropertyName("flush_index")]
        public int FlushIndex { get; set; }
    }

    public class VoiceAlertEvent
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = "";

        [JsonPropertyName("category")]
        public string Category { get; set; } = "";

        [JsonPropertyName("severity")]
        public string Severity { get; set; } = "";

        [JsonPropertyName("risk_score")]
        public double RiskScore { get; set; }

        [JsonPropertyName("details")]
        public Dictionary<string, object>? Details { get; set; }

        [JsonPropertyName("flush_index")]
        public int FlushIndex { get; set; }
    }

    public class VoiceSessionSummaryEvent
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = "";

        [JsonPropertyName("session_id")]
        public string SessionId { get; set; } = "";

        [JsonPropertyName("duration_seconds")]
        public double DurationSeconds { get; set; }

        [JsonPropertyName("overall_risk")]
        public string OverallRisk { get; set; } = "";

        [JsonPropertyName("overall_risk_score")]
        public double OverallRiskScore { get; set; }

        [JsonPropertyName("total_flushes")]
        public int TotalFlushes { get; set; }

        [JsonPropertyName("transcript")]
        public string Transcript { get; set; } = "";
    }

    public class VoiceConfigUpdatedEvent
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = "";

        [JsonPropertyName("config")]
        public VoiceStreamConfigInfo? Config { get; set; }
    }

    public class VoiceErrorEvent
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = "";

        [JsonPropertyName("code")]
        public string Code { get; set; } = "";

        [JsonPropertyName("message")]
        public string Message { get; set; } = "";
    }

    public class VoiceStreamHandlers
    {
        public Action<VoiceReadyEvent>? OnReady { get; set; }
        public Action<VoiceTranscriptionEvent>? OnTranscription { get; set; }
        public Action<VoiceAlertEvent>? OnAlert { get; set; }
        public Action<VoiceSessionSummaryEvent>? OnSessionSummary { get; set; }
        public Action<VoiceConfigUpdatedEvent>? OnConfigUpdated { get; set; }
        public Action<VoiceErrorEvent>? OnError { get; set; }
        public Action<int, string>? OnClose { get; set; }
    }
}
