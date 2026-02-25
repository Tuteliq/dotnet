<p align="center">
  <img src="./assets/logo.png" alt="Tuteliq" width="200" />
</p>

<h1 align="center">Tuteliq .NET SDK</h1>

<p align="center">
  <strong>Official .NET SDK for the Tuteliq API</strong><br>
  AI-powered child safety analysis for C#/.NET applications
</p>

<p align="center">
  <a href="https://www.nuget.org/packages/Tuteliq"><img src="https://img.shields.io/nuget/v/Tuteliq.svg" alt="NuGet version"></a>
  <a href="https://www.nuget.org/packages/Tuteliq"><img src="https://img.shields.io/nuget/dt/Tuteliq.svg" alt="NuGet downloads"></a>
  <a href="https://github.com/Tuteliq/dotnet/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Tuteliq/dotnet" alt="license"></a>
  <a href="https://github.com/Tuteliq/dotnet/actions"><img src="https://img.shields.io/github/actions/workflow/status/Tuteliq/dotnet/ci.yml" alt="build status"></a>
</p>

<p align="center">
  <a href="https://docs.tuteliq.ai">Documentation</a> •
  <a href="https://tuteliq.ai/dashboard">Dashboard</a> •
  <a href="https://trust.tuteliq.ai">Trust</a> •
  <a href="https://discord.gg/7kbTeRYRXD">Discord</a> •
  <a href="https://twitter.com/tuteliqdev">Twitter</a>
</p>

---

## Overview

Tuteliq provides AI-powered content analysis to help protect children in digital environments. This SDK makes it easy to integrate Tuteliq's capabilities into your .NET applications — ASP.NET Core APIs, background services, Blazor apps, console tools, and more.

### Key Features

- **Bullying Detection** — Identify verbal abuse, exclusion, and harassment patterns
- **Grooming Risk Analysis** — Detect predatory behavior across conversation threads
- **Unsafe Content Detection** — Flag self-harm, violence, hate speech, and age-inappropriate content
- **Emotional State Analysis** — Understand emotional signals and concerning trends
- **Action Guidance** — Generate age-appropriate response recommendations
- **Incident Reports** — Create professional summaries for review

### Why Tuteliq?

| Feature | Description |
|---------|-------------|
| **Privacy-First** | Stateless analysis, no mandatory data storage |
| **Human-in-the-Loop** | Designed to assist, not replace, human judgment |
| **Clear Rationale** | Every decision includes explainable reasoning |
| **Safe Defaults** | Conservative escalation, no automated responses to children |

---

## Installation

```bash
# .NET CLI
dotnet add package Tuteliq

# Package Manager
Install-Package Tuteliq

# PackageReference
<PackageReference Include="Tuteliq" Version="1.0.0" />
```

### Requirements

- .NET 6.0, 7.0, or 8.0+
- A Tuteliq API key ([get one here](https://tuteliq.ai/dashboard))

---

## Quick Start

```csharp
using Tuteliq;

var client = new TuteliqClient("your-api-key");

// Detect bullying
var result = await client.DetectBullyingAsync(new DetectBullyingInput
{
    Content = "you're so stupid, nobody likes you"
});

if (result.IsBullying)
{
    Console.WriteLine($"Severity: {result.Severity}");       // High
    Console.WriteLine($"Risk Score: {result.RiskScore}");     // 0.85
    Console.WriteLine($"Rationale: {result.Rationale}");
    Console.WriteLine($"Action: {result.RecommendedAction}"); // flag_for_moderator
}
```

---

## API Reference

### Initialization

```csharp
// Basic
var client = new TuteliqClient("your-api-key");

// With options
var client = new TuteliqClient("your-api-key", new TuteliqOptions
{
    Timeout = 15_000,   // 15s (default: 30s, range: 1-120s)
    Retries = 5,        // retry attempts (default: 3, range: 0-10)
    RetryDelay = 2_000, // initial delay (default: 1s)
    BaseUrl = "https://api.tuteliq.ai"
});

// With dependency injection (ASP.NET Core)
builder.Services.AddHttpClient<TuteliqClient>(client =>
{
    client.BaseAddress = new Uri("https://api.tuteliq.ai");
});
builder.Services.AddSingleton(sp =>
{
    var httpClient = sp.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(TuteliqClient));
    return new TuteliqClient("your-api-key", httpClient);
});
```

### Bullying Detection

```csharp
var result = await client.DetectBullyingAsync(new DetectBullyingInput
{
    Content = "text to analyze",
    Context = new AnalysisContext
    {
        Language = "en",
        AgeGroup = "11-13",
        Platform = "chat"
    },
    ExternalId = "msg-123",
    CustomerId = "tenant-456",
    Metadata = new Dictionary<string, object> { ["channel"] = "general" }
});

// BullyingResult
result.IsBullying       // bool
result.BullyingType     // List<string> — verbal, social, etc.
result.Confidence       // double (0-1)
result.Severity         // Severity enum — Low, Medium, High, Critical
result.RiskScore        // double (0-1)
result.Rationale        // string
result.RecommendedAction // string — none, monitor, flag_for_moderator, immediate_intervention
result.ExternalId       // string? — echoed back
result.CustomerId       // string? — echoed back
```

### Grooming Detection

```csharp
var result = await client.DetectGroomingAsync(new DetectGroomingInput
{
    Messages = new List<GroomingMessage>
    {
        new(MessageRole.Unknown, "hey, how old are you?"),
        new(MessageRole.Child, "I'm 12"),
        new(MessageRole.Unknown, "cool, do you have instagram?"),
    },
    ChildAge = 12,
    Context = new AnalysisContext { Platform = "Discord" }
});

// GroomingResult
result.GroomingRisk        // GroomingRisk enum — None, Low, Medium, High, Critical
result.Flags               // List<string> — age_inquiry, isolation_attempt, etc.
result.Confidence          // double (0-1)
result.RiskScore           // double (0-1)
result.Rationale           // string
result.RecommendedAction   // string
result.MessageAnalysis     // List<MessageAnalysis>? — per-message breakdown (conversation-aware endpoints)

// Per-message breakdown
if (result.MessageAnalysis is not null)
{
    foreach (var m in result.MessageAnalysis)
        Console.WriteLine($"Message {m.MessageIndex}: risk={m.RiskScore}, flags=[{string.Join(", ", m.Flags)}], summary={m.Summary}");
}
```

### Unsafe Content Detection

```csharp
var result = await client.DetectUnsafeAsync(new DetectUnsafeInput
{
    Content = "text to analyze"
});

// UnsafeResult
result.Unsafe              // bool
result.Categories          // List<string> — violence, self_harm, hate_speech, etc.
result.Severity            // Severity enum
result.Confidence          // double (0-1)
result.RiskScore           // double (0-1)
result.RecommendedAction   // string
```

### Combined Analysis

Runs bullying and unsafe detection in parallel and returns a unified result:

```csharp
// Quick form
var result = await client.AnalyzeAsync("text to check");

// Full form
var result = await client.AnalyzeAsync(new AnalyzeInput
{
    Content = "text to check",
    Include = new List<string> { "bullying", "unsafe" },
    ExternalId = "msg-123",
    CustomerId = "tenant-456"
});

// AnalyzeResult
result.RiskLevel           // RiskLevel enum — Safe, Low, Medium, High, Critical
result.RiskScore           // double (0-1)
result.Summary             // string
result.Bullying            // BullyingResult?
result.Unsafe              // UnsafeResult?
result.RecommendedAction   // string
```

### Emotion Analysis

```csharp
// Single text
var result = await client.AnalyzeEmotionsAsync(new AnalyzeEmotionsInput
{
    Content = "I feel really sad today, nothing is going right"
});

// Conversation
var result = await client.AnalyzeEmotionsAsync(new AnalyzeEmotionsInput
{
    Messages = new List<EmotionMessage>
    {
        new("alice", "I had a terrible day at school"),
        new("bob", "What happened?"),
        new("alice", "Everyone was laughing at me")
    }
});

// EmotionsResult
result.DominantEmotions      // List<string>
result.EmotionScores         // Dictionary<string, double>?
result.Trend                 // EmotionTrend enum — Improving, Stable, Worsening
result.Summary               // string
result.RecommendedFollowup   // string
```

### Action Plan

```csharp
var result = await client.GetActionPlanAsync(new GetActionPlanInput
{
    Situation = "Child is being cyberbullied through group chat",
    ChildAge = 13,
    Audience = Audience.Parent,
    Severity = Severity.High
});

// ActionPlanResult
result.Steps          // List<string>
result.Tone           // string
result.ReadingLevel   // string?
```

### Incident Report

```csharp
var result = await client.GenerateReportAsync(new GenerateReportInput
{
    Messages = new List<ReportMessage>
    {
        new("bully", "You're so ugly"),
        new("victim", "Stop it please")
    },
    ChildAge = 11,
    IncidentType = "harassment"
});

// ReportResult
result.Summary               // string
result.RiskLevel             // RiskLevel enum
result.Categories            // List<string>
result.RecommendedNextSteps  // List<string>
```

### Voice Streaming

Real-time voice analysis over WebSocket:

```csharp
await using var session = client.CreateVoiceStream(
    config: new VoiceStreamConfig
    {
        IntervalSeconds = 10,
        AnalysisTypes = new List<string> { "bullying", "unsafe" }
    },
    handlers: new VoiceStreamHandlers
    {
        OnReady = e => Console.WriteLine($"Session ready: {e.SessionId}"),
        OnTranscription = e => Console.WriteLine($"Transcription: {e.Text}"),
        OnAlert = e => Console.WriteLine($"Alert: {e.Category} ({e.Severity})"),
        OnSessionSummary = e => Console.WriteLine($"Summary: Risk {e.OverallRisk}")
    }
);

await session.ConnectAsync();

// Send audio data
await session.SendAudioAsync(audioBytes);

// End session and get summary
var summary = await session.EndAsync();
```

### Credits Used

All analysis result types include a `CreditsUsed` property that indicates how many API credits were consumed by the request:

```csharp
var result = await client.DetectBullyingAsync(new DetectBullyingInput
{
    Content = "text to analyze"
});

Console.WriteLine($"Credits used: {result.CreditsUsed}");
```

---

## Tracking Fields

All endpoints support optional tracking fields for correlation and multi-tenant routing:

| Field | Type | Description |
|-------|------|-------------|
| `ExternalId` | `string?` | Your unique ID to correlate Tuteliq results with your systems (max 255 chars) |
| `CustomerId` | `string?` | Your end-customer ID for multi-tenant / B2B2C routing (max 255 chars) |
| `Metadata` | `Dictionary<string, object>?` | Arbitrary key-value pairs for your own use |

All tracking fields are echoed back in the response and included in webhook payloads.

```csharp
var result = await client.DetectBullyingAsync(new DetectBullyingInput
{
    Content = "text",
    ExternalId = "msg-abc-123",
    CustomerId = "tenant-456",
    Metadata = new Dictionary<string, object>
    {
        ["channel"] = "general",
        ["server_id"] = "srv-789"
    }
});

// result.ExternalId == "msg-abc-123"
// result.CustomerId == "tenant-456"
```

---

## Usage & Rate Limit Info

After each API call, usage and rate limit data is available on the client:

```csharp
var result = await client.DetectBullyingAsync(input);

// Monthly usage
Console.WriteLine($"Used: {client.Usage?.Used}/{client.Usage?.Limit}");
Console.WriteLine($"Remaining: {client.Usage?.Remaining}");

// Rate limit (per minute)
Console.WriteLine($"Rate limit: {client.RateLimit?.Remaining}/{client.RateLimit?.Limit}");

// Diagnostics
Console.WriteLine($"Request ID: {client.LastRequestId}");
Console.WriteLine($"Latency: {client.LastLatencyMs}ms");

// Warning if over 80% usage
if (client.UsageWarning != null)
    Console.WriteLine($"Warning: {client.UsageWarning}");
```

---

## Error Handling

The SDK throws typed exceptions for different error categories:

```csharp
try
{
    var result = await client.DetectBullyingAsync(input);
}
catch (AuthenticationException ex)
{
    // 401 — Invalid or missing API key
    Console.WriteLine($"Auth error: {ex.Message} ({ex.Code})");
}
catch (ValidationException ex)
{
    // 400 — Invalid request parameters
    Console.WriteLine($"Validation error: {ex.Message}");
}
catch (RateLimitException ex)
{
    // 429 — Too many requests
    Console.WriteLine($"Rate limited. Retry after {ex.RetryAfterSeconds}s");
}
catch (TierAccessException ex)
{
    // 403 — Feature not available on current tier
    Console.WriteLine($"Upgrade required: {ex.Message}");
}
catch (ServerException ex)
{
    // 5xx — Server error (auto-retried)
    Console.WriteLine($"Server error ({ex.StatusCode}): {ex.Message}");
}
catch (Tuteliq.TimeoutException ex)
{
    // Request timed out (auto-retried)
    Console.WriteLine($"Timeout: {ex.Message}");
}
catch (NetworkException ex)
{
    // Connection failed (auto-retried)
    Console.WriteLine($"Network error: {ex.Message}");
}
```

### Automatic Retries

The SDK automatically retries on:
- **5xx server errors** — with exponential backoff
- **429 rate limits** — respects `Retry-After` header
- **Network errors** — connection failures, DNS issues
- **Timeouts** — configurable timeout per request

Non-retryable errors (400, 401, 403, 404) fail immediately.

---

## ASP.NET Core Integration

```csharp
// Program.cs
builder.Services.AddSingleton<TuteliqClient>(_ =>
    new TuteliqClient(
        builder.Configuration["Tuteliq:ApiKey"]!,
        new TuteliqOptions { Timeout = 15_000 }
    ));

// Controller or Minimal API
app.MapPost("/api/moderate", async (TuteliqClient tuteliq, ModerateRequest req) =>
{
    var result = await tuteliq.DetectBullyingAsync(new DetectBullyingInput
    {
        Content = req.Message,
        CustomerId = req.TenantId
    });

    return result.IsBullying
        ? Results.Ok(new { blocked = true, severity = result.Severity.ToString() })
        : Results.Ok(new { blocked = false });
});
```

---

## Enums

```csharp
// Severity: Low, Medium, High, Critical
// GroomingRisk: None, Low, Medium, High, Critical
// RiskLevel: Safe, Low, Medium, High, Critical
// EmotionTrend: Improving, Stable, Worsening
// Audience: Child, Parent, Educator, Platform
// MessageRole: Adult, Child, Unknown
```

---

## Best Practices

### Message Batching

The **bullying** and **unsafe content** methods analyze a single `text` field per request. If your app receives messages one at a time, concatenate a **sliding window of recent messages** into one string before calling the API. Single words or short fragments lack context for accurate detection and can be exploited to bypass safety filters.

```csharp
// Bad — each message analyzed in isolation, easily evaded
foreach (var msg in messages)
{
    await client.DetectBullyingAsync(text: msg);
}

// Good — recent messages analyzed together
var window = string.Join(" ", recentMessages.TakeLast(10));
await client.DetectBullyingAsync(text: window);
```

The **grooming** method already accepts a `messages` list and analyzes the full conversation in context.

### PII Redaction

Enable `PII_REDACTION_ENABLED=true` on your Tuteliq API to automatically strip emails, phone numbers, URLs, social handles, IPs, and other PII from detection summaries and webhook payloads. The original text is still analyzed in full — only stored outputs are scrubbed.

---

## License

MIT — see [LICENSE](./LICENSE) for details.

---

## Get Certified — Free

Tuteliq offers a **free certification program** for anyone who wants to deepen their understanding of online child safety. Complete a track, pass the quiz, and earn your official Tuteliq certificate — verified and shareable.

**Three tracks available:**

| Track | Who it's for | Duration |
|-------|-------------|----------|
| **Parents & Caregivers** | Parents, guardians, grandparents, teachers, coaches | ~90 min |
| **Young People (10–16)** | Young people who want to learn to spot manipulation | ~60 min |
| **Companies & Platforms** | Product managers, trust & safety teams, CTOs, compliance officers | ~120 min |

**Start here →** [tuteliq.ai/certify](https://tuteliq.ai/certify)

- 100% Free — no login required
- Verifiable certificate on completion
- Covers grooming recognition, sextortion, cyberbullying, regulatory obligations (KOSA, EU DSA), and more

---

## The Mission: Why This Matters

Before you decide to contribute or sponsor, read these numbers. They are not projections. They are not estimates from a pitch deck. They are verified statistics from the University of Edinburgh, UNICEF, NCMEC, and Interpol.

- **302 million** children are victims of online sexual exploitation and abuse every year. That is **10 children every second**. *(Childlight / University of Edinburgh, 2024)*
- **1 in 8** children globally have been victims of non-consensual sexual imagery in the past year. *(Childlight, 2024)*
- **370 million** girls and women alive today experienced rape or sexual assault in childhood. An estimated **240–310 million** boys and men experienced the same. *(UNICEF, 2024)*
- **29.2 million** incidents of suspected child sexual exploitation were reported to NCMEC's CyberTipline in 2024 alone — containing **62.9 million files** (images, videos). *(NCMEC, 2025)*
- **546,000** reports of online enticement (adults grooming children) in 2024 — a **192% increase** from the year before. *(NCMEC, 2025)*
- **1,325% increase** in AI-generated child sexual abuse material reports between 2023 and 2024. The technology that should protect children is being weaponized against them. *(NCMEC, 2025)*
- **100 sextortion reports per day** to NCMEC. Since 2021, at least **36 teenage boys** have taken their own lives because they were victimized by sextortion. *(NCMEC, 2025)*
- **84%** of reports resolve outside the United States. This is not an American problem. This is a **global emergency**. *(NCMEC, 2025)*

End-to-end encryption is making platforms blind. In 2024, platforms reported **7 million fewer incidents** than the year before — not because abuse stopped, but because they can no longer see it. The tools that catch known images are failing. The systems that rely on human moderators are overwhelmed. The technology to detect behavior — grooming patterns, escalation, manipulation — in real-time text conversations **exists right now**. It is running at [api.tuteliq.ai](https://api.tuteliq.ai).

The question is not whether this technology is possible. The question is whether we build the company to put it everywhere it needs to be.

**Every second we wait, another child is harmed.**

We have the technology. We need the support.

If this mission matters to you, consider [sponsoring our open-source work](https://github.com/sponsors/Tuteliq) so we can keep building the tools that protect children — and keep them free and accessible for everyone.

---

<p align="center">
  <sub>Built with care for child safety by the <a href="https://tuteliq.ai">Tuteliq</a> team</sub>
</p>
