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

Tuteliq provides AI-powered content analysis to help protect children in digital environments. This SDK makes it easy to integrate Tuteliq's capabilities into your .NET applications: ASP.NET Core APIs, background services, Blazor apps, console tools, and more.

### Key Features

- **Bullying Detection**: Identify verbal abuse, exclusion, and harassment patterns
- **Grooming Risk Analysis**: Detect predatory behavior across conversation threads
- **Unsafe Content Detection**: Flag self-harm, violence, hate speech, and age-inappropriate content
- **Emotional State Analysis**: Understand emotional signals and concerning trends
- **Action Guidance**: Generate age-appropriate response recommendations
- **Incident Reports**: Create professional summaries for review
- **Fraud and Extended Safety**: Social engineering, scams, coercive control, radicalisation, distress signals and more
- **Document, Image, Voice and Video Analysis**: Per-page document results, media safety checks and real-time voice streaming
- **Age and Identity Verification**: Hosted verification sessions your users complete on their own device
- **Incident Management**: List, review and track incidents with signed audit receipts
- **Privacy Redaction**: Remove personal data from a text or a conversation

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
<PackageReference Include="Tuteliq" Version="2.5.0" />
```

### Requirements

- .NET 8.0 or later
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
result.BullyingType     // List<string>: verbal, social, etc.
result.Confidence       // double (0-1)
result.Severity         // Severity enum: Low, Medium, High, Critical
result.RiskScore        // double (0-1)
result.Rationale        // string
result.RecommendedAction // string: none, monitor, flag_for_moderator, immediate_intervention
result.ExternalId       // string?: echoed back
result.CustomerId       // string?: echoed back
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
result.GroomingRisk        // GroomingRisk enum: None, Low, Medium, High, Critical
result.Flags               // List<string>: age_inquiry, isolation_attempt, etc.
result.Confidence          // double (0-1)
result.RiskScore           // double (0-1)
result.Rationale           // string
result.RecommendedAction   // string
result.MessageAnalysis     // List<MessageAnalysis>?: per-message breakdown (conversation-aware endpoints)

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
result.Categories          // List<string>: violence, self_harm, hate_speech, etc.
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
result.RiskLevel           // RiskLevel enum: Safe, Low, Medium, High, Critical
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
result.Trend                 // EmotionTrend enum: Improving, Stable, Worsening
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

### Distress Signals

```csharp
var result = await client.DetectDistressSignalsAsync(new DetectionInput
{
    Content = "text to analyze"
});

// DistressSignalsResult (extends DetectionResult)
result.Detected           // bool
result.RiskScore          // double (0-1)
result.DistressReading    // string? (literal_present, about_other, past_resolved, figurative, quoted, none)
result.SupportSuggested   // bool? (true when a supportive check-in fits better than a moderation case)
```

The other fraud and extended safety methods (`DetectSocialEngineeringAsync`, `DetectAppFraudAsync`, `DetectRomanceScamAsync`, `DetectMuleRecruitmentAsync`, `DetectGamblingHarmAsync`, `DetectCoerciveControlAsync`, `DetectVulnerabilityExploitationAsync`, `DetectRadicalisationAsync`) take the same `DetectionInput` and return a `DetectionResult`.

### Document Analysis

Analyze a PDF or a single PNG, JPEG or WebP image. Each page runs through the detection endpoints you choose.

```csharp
var result = await client.AnalyzeDocumentAsync(new AnalyzeDocumentInput
{
    File = await File.ReadAllBytesAsync("report.pdf"),
    Filename = "report.pdf",
    Endpoints = new List<string> { DocumentEndpointName.Unsafe, DocumentEndpointName.Grooming },
});

Console.WriteLine(result.OverallSeverity);      // none, low, medium, high or critical
Console.WriteLine(result.FlaggedPages.Count);
Console.WriteLine(result.DocumentHash);         // SHA-256 of the uploaded file
```

### Age and Identity Verification

Verification runs in a hosted session: create a session, open its URL on the user's device (a new tab or a web view), then read the result by polling or from the `verification.completed` webhook. Verification is available on the Pro plan and above; identity mode needs a plan that includes it.

```csharp
var session = await client.CreateVerificationSessionAsync(new CreateVerificationSessionInput
{
    Mode = VerificationMode.Age,               // or VerificationMode.Identity
    DocumentType = DocumentType.Passport,      // optional hint: Passport, NationalId, DriversLicense
    ChipPolicy = ChipPolicy.Optional,          // optional: Optional, Required, InsteadOfPhoto
});

Console.WriteLine(session.Url);                // open this for the user
Console.WriteLine(session.ExpiresAt);          // epoch milliseconds

// Poll until the session finishes
var poll = await client.GetVerificationSessionAsync(session.SessionId);
if (poll.Status is VerificationSessionStatus.Completed or VerificationSessionStatus.Failed)
{
    var result = poll.GetResult();
    Console.WriteLine(result?.Status);               // Verified, Failed or NeedsReview
    Console.WriteLine(result?.IsMinor);
    Console.WriteLine(result?.FaceMatch?.MatchScore); // 0-1, 0.5 at the match decision
}

// Cancel a session you no longer need
await client.CancelVerificationSessionAsync(session.SessionId);
```

The extracted document fields, date of birth and failure reasons are released once: only the first poll after the session completes or fails carries them. Store them on that read, or subscribe to the `verification.completed` webhook.

`VerificationSessionStatus.DocumentRequired` means the session needs a document photo before it can continue.

### Image Verification

Face match against a reference image, age estimation, explicit content and synthetic image checks in one call. Images are processed in memory and never stored.

```csharp
var result = await client.VerifyImageMatchAsync(new VerifyImageMatchInput
{
    Image = await File.ReadAllBytesAsync("selfie.jpg"),
    ReferenceImage = await File.ReadAllBytesAsync("profile.jpg"),
    Checks = new List<ImageMatchCheck> { ImageMatchCheck.FaceMatch, ImageMatchCheck.Age },
});

Console.WriteLine(result.FaceMatch?.Matched);
Console.WriteLine(result.Age?.EstimatedAge);
```

### Incidents

```csharp
// List, newest first, with cursor paging
string? cursor = null;
do
{
    var page = await client.ListIncidentsAsync(new ListIncidentsInput
    {
        Category = "grooming",
        Severity = "high",
        Status = "new",
        Limit = 50,
        Cursor = cursor,
    });
    foreach (var incident in page.Incidents)
        Console.WriteLine($"{incident.Id} {incident.RiskLevel} {incident.CreatedAt}");
    cursor = page.NextCursor;
} while (cursor != null);

// Detail, overview and trends
var detail = await client.GetIncidentAsync("incident-id");
var overview = await client.GetIncidentsOverviewAsync();
var trends = await client.GetIncidentTrendsAsync(bucket: "week");

// Record a moderator decision (each one gets a signed audit receipt)
var review = await client.ReviewIncidentAsync("incident-id", new ReviewIncidentInput
{
    Action = ModeratorAction.Dismiss,
    ReasonCode = ModeratorReasonCode.FalsePositive,
    ModeratorExternalId = "moderator-42",
});

// The same decision for up to 100 incidents
var batch = await client.BatchReviewIncidentsAsync(new BatchReviewIncidentsInput
{
    IncidentIds = new List<string> { "incident-1", "incident-2" },
    Action = ModeratorAction.Confirm,
    ReasonCode = ModeratorReasonCode.ConfirmedAccurate,
    ModeratorExternalId = "moderator-42",
});
Console.WriteLine($"{batch.Succeeded}/{batch.Total} reviewed");
```

`ModeratorExternalId` is required: use a stable identifier per moderator so the audit trail can attribute each decision.

### Privacy Redaction

```csharp
var result = await client.RedactAsync(new RedactInput
{
    Messages = new List<string> { "hi, I'm Sam", "text me on 000 000 0000" },
});

Console.WriteLine(string.Join("\n", result.Messages!)); // the same value gets the same placeholder in every message
Console.WriteLine(result.EntitiesTotal);
```

Send exactly one of `Text` or `Messages`. `Mode = RedactMode.Precise` leaves near misses such as a mistyped phone number in place; the default, `Protective`, removes them.

### Webhooks

```csharp
var created = await client.CreateWebhookAsync(new CreateWebhookInput
{
    Name = "Moderation alerts",
    Url = "https://example.com/tuteliq/webhook",
    Events = new List<string> { WebhookEvents.IncidentCritical, WebhookEvents.VerificationCompleted },
});
Console.WriteLine(created.Secret); // only returned on creation; store it to verify deliveries

var list = await client.ListWebhooksAsync();
foreach (var hook in list.Webhooks)
    Console.WriteLine($"{hook.Name} active={hook.IsActive} failures={hook.FailureCount}");

await client.UpdateWebhookAsync(created.Id, new UpdateWebhookInput { IsActive = false });
var test = await client.TestWebhookAsync(created.Id);
Console.WriteLine($"{test.Success} {test.StatusCode} {test.LatencyMs}ms");
var rotated = await client.RegenerateWebhookSecretAsync(created.Id);
await client.DeleteWebhookAsync(created.Id);
```

Event names: `incident.critical`, `incident.high`, `grooming.detected`, `self_harm.detected`, `bullying.severe`, `verification.completed`, `minor.detected`, `csam.detected`, `csam.critical` (constants on `WebhookEvents`). A webhook takes 1 to 5 events.

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

The stream connects to `/api/v1/safety/voice/stream` on the client's base URL and authenticates with your API key in the `Authorization` header.

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

// Daily counts and real-time quota
var summary = await client.GetUsageSummaryAsync();
var quota = await client.GetQuotaAsync();
Console.WriteLine($"Remaining this minute: {quota.Remaining.RequestsThisMinute}");

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
    // 401: Invalid or missing API key
    Console.WriteLine($"Auth error: {ex.Message} ({ex.Code})");
}
catch (ValidationException ex)
{
    // 400: Invalid request parameters
    Console.WriteLine($"Validation error: {ex.Message}");
}
catch (RateLimitException ex)
{
    // 429: Too many requests
    Console.WriteLine($"Rate limited. Retry after {ex.RetryAfterSeconds}s");
}
catch (TierAccessException ex)
{
    // 403: Feature not available on current tier
    Console.WriteLine($"Upgrade required: {ex.Message}");
}
catch (ServerException ex)
{
    // 5xx: Server error (auto-retried)
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
- **5xx server errors**: with exponential backoff
- **429 rate limits**: respects `Retry-After` header
- **Network errors**: connection failures, DNS issues
- **Timeouts**: configurable timeout per request

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
// VerificationMode: Age, Identity
// DocumentType: Passport, NationalId, DriversLicense
// ChipPolicy: Optional, Required, InsteadOfPhoto
// VerificationSessionStatus: Pending, InProgress, Completed, Failed, Expired, Cancelled, DocumentRequired
// ModeratorAction: Confirm, Downgrade, Escalate, Reclassify, Dismiss, Resolve, Reopen
// ModeratorReasonCode: ConfirmedAccurate, FalsePositive, OutOfContext, InsufficientSeverity,
//                      IncorrectCategory, RequiresLawEnforcement, ParentNotified, Other
// WebhookEventType: IncidentCritical, IncidentHigh, GroomingDetected, SelfHarmDetected, BullyingSevere,
//                   VerificationCompleted, MinorDetected, CsamDetected, CsamCritical
// Language: the 32 supported language codes (En, Es, Pt, ... Ru)
```

---

## Best Practices

### Message Batching

The **bullying** and **unsafe content** methods analyze a single `text` field per request. If your app receives messages one at a time, concatenate a **sliding window of recent messages** into one string before calling the API. Single words or short fragments lack context for accurate detection and can be exploited to bypass safety filters.

```csharp
// Bad: each message analyzed in isolation, easily evaded
foreach (var msg in messages)
{
    await client.DetectBullyingAsync(new DetectBullyingInput { Content = msg });
}

// Good: recent messages analyzed together
var window = string.Join(" ", recentMessages.TakeLast(10));
await client.DetectBullyingAsync(new DetectBullyingInput { Content = window });
```

The **grooming** method already accepts a `messages` list and analyzes the full conversation in context.

### Redact After Analysis

Safety analysis reads context such as ages and places, so analyze the original text first and call `RedactAsync` only on text you share or store afterwards.

---

## Supported Languages

Tuteliq supports **32 languages** with automatic detection, no configuration required.

**English** (stable) and **31 beta languages**: Spanish, Portuguese, Ukrainian, Swedish, Norwegian, Danish, Finnish, German, French, Dutch, Polish, Italian, Turkish, Romanian, Greek, Czech, Hungarian, Bulgarian, Croatian, Slovak, Lithuanian, Latvian, Estonian, Slovenian, Maltese, Irish, Chinese, Japanese, Korean, Arabic, and Russian.

All 24 EU official languages plus Ukrainian, Norwegian, Turkish, Chinese, Japanese, Korean, Arabic, and Russian. Each language includes culture-specific safety guidelines. The `Language` enum lists the codes.

See the [Language Support docs](https://docs.tuteliq.ai/languages) for details.

---

## License

MIT. See [LICENSE](./LICENSE) for details.

---

## Get Certified for Free

Tuteliq offers a **free certification program** for anyone who wants to deepen their understanding of online child safety. Complete a track, pass the quiz, and earn your official Tuteliq certificate, verified and shareable.

**Three tracks available:**

| Track | Who it's for | Duration |
|-------|-------------|----------|
| **Parents & Caregivers** | Parents, guardians, grandparents, teachers, coaches | ~90 min |
| **Young People (10–16)** | Young people who want to learn to spot manipulation | ~60 min |
| **Companies & Platforms** | Product managers, trust & safety teams, CTOs, compliance officers | ~120 min |

**Start here →** [tuteliq.ai/certify](https://tuteliq.ai/certify)

- 100% free, no login required
- Verifiable certificate on completion
- Covers grooming recognition, sextortion, cyberbullying, regulatory obligations (KOSA, EU DSA), and more

---

## The Mission: Why This Matters

Before you decide to contribute or sponsor, read these numbers. They are not projections. They are not estimates from a pitch deck. They are verified statistics from the University of Edinburgh, UNICEF, NCMEC, and Interpol.

- **302 million** children are victims of online sexual exploitation and abuse every year. That is **10 children every second**. *(Childlight / University of Edinburgh, 2024)*
- **1 in 8** children globally have been victims of non-consensual sexual imagery in the past year. *(Childlight, 2024)*
- **370 million** girls and women alive today experienced rape or sexual assault in childhood. An estimated **240–310 million** boys and men experienced the same. *(UNICEF, 2024)*
- **29.2 million** incidents of suspected child sexual exploitation were reported to NCMEC's CyberTipline in 2024 alone, containing **62.9 million files** (images, videos). *(NCMEC, 2025)*
- **546,000** reports of online enticement (adults grooming children) in 2024, a **192% increase** from the year before. *(NCMEC, 2025)*
- **1,325% increase** in AI-generated child sexual abuse material reports between 2023 and 2024. The technology that should protect children is being weaponized against them. *(NCMEC, 2025)*
- **100 sextortion reports per day** to NCMEC. Since 2021, at least **36 teenage boys** have taken their own lives because they were victimized by sextortion. *(NCMEC, 2025)*
- **84%** of reports resolve outside the United States. This is not an American problem. This is a **global emergency**. *(NCMEC, 2025)*

End-to-end encryption is making platforms blind. In 2024, platforms reported **7 million fewer incidents** than the year before, not because abuse stopped, but because they can no longer see it. The tools that catch known images are failing. The systems that rely on human moderators are overwhelmed. The technology to detect behavior (grooming patterns, escalation, manipulation) in real-time text conversations **exists right now**. It is running at [api.tuteliq.ai](https://api.tuteliq.ai).

The question is not whether this technology is possible. The question is whether we build the company to put it everywhere it needs to be.

**Every second we wait, another child is harmed.**

We have the technology. We need the support.

If this mission matters to you, consider [sponsoring our open-source work](https://github.com/sponsors/Tuteliq) so we can keep building the tools that protect children, and keep them free and accessible for everyone.

---

<p align="center">
  <sub>Built with care for child safety by the <a href="https://tuteliq.ai">Tuteliq</a> team</sub>
</p>
