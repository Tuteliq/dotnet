namespace Tuteliq;

/// <summary>
/// Base exception for all Tuteliq SDK errors.
/// </summary>
public class TuteliqException : Exception
{
    /// <summary>HTTP status code, if applicable.</summary>
    public int? StatusCode { get; }

    /// <summary>Error code from the API (e.g. AUTH_1001).</summary>
    public string? Code { get; }

    /// <summary>Additional error details from the API.</summary>
    public object? Details { get; }

    /// <summary>Suggested action to resolve the error.</summary>
    public string? Suggestion { get; }

    public TuteliqException(string message, int? statusCode = null, string? code = null, object? details = null, string? suggestion = null)
        : base(message)
    {
        StatusCode = statusCode;
        Code = code;
        Details = details;
        Suggestion = suggestion;
    }

    public TuteliqException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Thrown when authentication fails (HTTP 401).
/// </summary>
public class AuthenticationException : TuteliqException
{
    public AuthenticationException(string message, string? code = null, object? details = null, string? suggestion = null)
        : base(message, 401, code, details, suggestion) { }
}

/// <summary>
/// Thrown when the request is invalid (HTTP 400).
/// </summary>
public class ValidationException : TuteliqException
{
    public ValidationException(string message, string? code = null, object? details = null, string? suggestion = null)
        : base(message, 400, code, details, suggestion) { }
}

/// <summary>
/// Thrown when a resource is not found (HTTP 404).
/// </summary>
public class NotFoundException : TuteliqException
{
    public NotFoundException(string message, string? code = null, object? details = null, string? suggestion = null)
        : base(message, 404, code, details, suggestion) { }
}

/// <summary>
/// Thrown when the rate limit is exceeded (HTTP 429).
/// </summary>
public class RateLimitException : TuteliqException
{
    /// <summary>Number of seconds to wait before retrying.</summary>
    public int? RetryAfterSeconds { get; }

    public RateLimitException(string message, int? retryAfterSeconds = null, string? code = null, object? details = null, string? suggestion = null)
        : base(message, 429, code, details, suggestion)
    {
        RetryAfterSeconds = retryAfterSeconds;
    }
}

/// <summary>
/// Thrown when the tier does not have access (HTTP 403).
/// </summary>
public class TierAccessException : TuteliqException
{
    public TierAccessException(string message, string? code = null, object? details = null, string? suggestion = null)
        : base(message, 403, code, details, suggestion) { }
}

/// <summary>
/// Thrown when the server returns a 5xx error.
/// </summary>
public class ServerException : TuteliqException
{
    public ServerException(string message, int statusCode, string? code = null, object? details = null, string? suggestion = null)
        : base(message, statusCode, code, details, suggestion) { }
}

/// <summary>
/// Thrown when a request times out.
/// </summary>
public class TimeoutException : TuteliqException
{
    public TimeoutException(string message)
        : base(message) { }

    public TimeoutException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// Thrown when a network error occurs.
/// </summary>
public class NetworkException : TuteliqException
{
    public NetworkException(string message)
        : base(message) { }

    public NetworkException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// Thrown when the monthly quota has been exceeded.
/// </summary>
public class QuotaExceededException : TuteliqException
{
    public QuotaExceededException(string message, string? code = null, object? details = null, string? suggestion = null)
        : base(message, 429, code, details, suggestion) { }
}
