using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

namespace Tuteliq
{
    public class VoiceStreamSession : IAsyncDisposable
    {
        private const string VoiceStreamUrl = "wss://api.tuteliq.ai/voice/stream";

        private readonly string _apiKey;
        private readonly VoiceStreamConfig? _config;
        private readonly VoiceStreamHandlers? _handlers;
        private readonly JsonSerializerOptions _jsonOptions;
        private ClientWebSocket? _ws;
        private CancellationTokenSource? _cts;
        private Task? _receiveTask;
        private TaskCompletionSource<VoiceSessionSummaryEvent>? _summaryTcs;

        public string? SessionId { get; private set; }
        public bool IsActive { get; private set; }

        internal VoiceStreamSession(string apiKey, VoiceStreamConfig? config, VoiceStreamHandlers? handlers)
        {
            _apiKey = apiKey;
            _config = config;
            _handlers = handlers;
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
                PropertyNameCaseInsensitive = true
            };
        }

        public async Task ConnectAsync(CancellationToken ct = default)
        {
            _ws = new ClientWebSocket();
            _ws.Options.SetRequestHeader("Authorization", $"Bearer {_apiKey}");
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

            await _ws.ConnectAsync(new Uri(VoiceStreamUrl), _cts.Token);
            IsActive = true;

            if (_config != null)
            {
                var configMsg = new Dictionary<string, object?> { ["type"] = "config" };
                if (_config.IntervalSeconds.HasValue) configMsg["interval_seconds"] = _config.IntervalSeconds.Value;
                if (_config.AnalysisTypes != null) configMsg["analysis_types"] = _config.AnalysisTypes;
                if (_config.Context != null) configMsg["context"] = _config.Context;
                await SendJsonAsync(configMsg);
            }

            var readyTcs = new TaskCompletionSource<bool>();
            _receiveTask = ReceiveLoopAsync(readyTcs);
            await readyTcs.Task;
        }

        private async Task ReceiveLoopAsync(TaskCompletionSource<bool> readyTcs)
        {
            var buffer = new byte[8192];
            var messageBuffer = new List<byte>();

            try
            {
                while (_ws?.State == WebSocketState.Open && !(_cts?.Token.IsCancellationRequested ?? true))
                {
                    var result = await _ws.ReceiveAsync(new ArraySegment<byte>(buffer), _cts!.Token);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        IsActive = false;
                        _handlers?.OnClose?.Invoke((int)(result.CloseStatus ?? WebSocketCloseStatus.NormalClosure),
                            result.CloseStatusDescription ?? "");
                        _summaryTcs?.TrySetException(new InvalidOperationException("Connection closed before session summary"));
                        break;
                    }

                    messageBuffer.AddRange(new ArraySegment<byte>(buffer, 0, result.Count));

                    if (result.EndOfMessage)
                    {
                        var text = Encoding.UTF8.GetString(messageBuffer.ToArray());
                        messageBuffer.Clear();
                        HandleMessage(text, readyTcs);
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                IsActive = false;
                _handlers?.OnError?.Invoke(new VoiceErrorEvent
                {
                    Type = "error",
                    Code = "CONNECTION_ERROR",
                    Message = ex.Message
                });
                readyTcs.TrySetException(ex);
            }
        }

        private void HandleMessage(string text, TaskCompletionSource<bool> readyTcs)
        {
            try
            {
                using var doc = JsonDocument.Parse(text);
                var type = doc.RootElement.GetProperty("type").GetString();

                switch (type)
                {
                    case "ready":
                        var ready = JsonSerializer.Deserialize<VoiceReadyEvent>(text, _jsonOptions)!;
                        SessionId = ready.SessionId;
                        _handlers?.OnReady?.Invoke(ready);
                        readyTcs.TrySetResult(true);
                        break;
                    case "transcription":
                        var trans = JsonSerializer.Deserialize<VoiceTranscriptionEvent>(text, _jsonOptions)!;
                        _handlers?.OnTranscription?.Invoke(trans);
                        break;
                    case "alert":
                        var alert = JsonSerializer.Deserialize<VoiceAlertEvent>(text, _jsonOptions)!;
                        _handlers?.OnAlert?.Invoke(alert);
                        break;
                    case "session_summary":
                        var summary = JsonSerializer.Deserialize<VoiceSessionSummaryEvent>(text, _jsonOptions)!;
                        _handlers?.OnSessionSummary?.Invoke(summary);
                        _summaryTcs?.TrySetResult(summary);
                        break;
                    case "config_updated":
                        var configUpdated = JsonSerializer.Deserialize<VoiceConfigUpdatedEvent>(text, _jsonOptions)!;
                        _handlers?.OnConfigUpdated?.Invoke(configUpdated);
                        break;
                    case "error":
                        var error = JsonSerializer.Deserialize<VoiceErrorEvent>(text, _jsonOptions)!;
                        _handlers?.OnError?.Invoke(error);
                        break;
                }
            }
            catch { }
        }

        public async Task SendAudioAsync(byte[] data, CancellationToken ct = default)
        {
            if (_ws?.State != WebSocketState.Open)
                throw new InvalidOperationException("Voice stream is not connected");
            await _ws.SendAsync(new ArraySegment<byte>(data), WebSocketMessageType.Binary, true, ct);
        }

        public async Task UpdateConfigAsync(VoiceStreamConfig config, CancellationToken ct = default)
        {
            if (_ws?.State != WebSocketState.Open)
                throw new InvalidOperationException("Voice stream is not connected");
            var configMsg = new Dictionary<string, object?> { ["type"] = "config" };
            if (config.IntervalSeconds.HasValue) configMsg["interval_seconds"] = config.IntervalSeconds.Value;
            if (config.AnalysisTypes != null) configMsg["analysis_types"] = config.AnalysisTypes;
            if (config.Context != null) configMsg["context"] = config.Context;
            await SendJsonAsync(configMsg, ct);
        }

        public async Task<VoiceSessionSummaryEvent> EndAsync(CancellationToken ct = default)
        {
            if (_ws?.State != WebSocketState.Open)
                throw new InvalidOperationException("Voice stream is not connected");
            _summaryTcs = new TaskCompletionSource<VoiceSessionSummaryEvent>();
            await SendJsonAsync(new { type = "end" }, ct);
            return await _summaryTcs.Task;
        }

        public void Close()
        {
            IsActive = false;
            _cts?.Cancel();
            _ws?.Dispose();
            _ws = null;
        }

        private async Task SendJsonAsync(object data, CancellationToken ct = default)
        {
            var json = JsonSerializer.Serialize(data, _jsonOptions);
            var bytes = Encoding.UTF8.GetBytes(json);
            await _ws!.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, ct);
        }

        public async ValueTask DisposeAsync()
        {
            Close();
            if (_receiveTask != null)
            {
                try { await _receiveTask; } catch { }
            }
            GC.SuppressFinalize(this);
        }
    }
}
