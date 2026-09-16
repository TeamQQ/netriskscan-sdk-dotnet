using NetRiskScan.Models;

namespace NetRiskScan.Exceptions;

/// <summary>
/// HTTP <c>429</c> <c>rate_limit_exceeded</c> -- a short-lived, per-minute throughput limit. This
/// clears quickly; see <see cref="RetryAfter"/>.
///
/// Reaching this means the SDK's own automatic retries (see README "Automatic retries") were already
/// exhausted, or the server asked for a longer wait than <see cref="NetRiskScanOptions.MaxRetryDelay"/>
/// allows.
/// </summary>
public class NetRiskScanRateLimitException : NetRiskScanException
{
    /// <summary>How long to wait before retrying, from the server's <c>Retry-After</c> header.
    /// <see langword="null"/> when the header was absent.</summary>
    public TimeSpan? RetryAfter { get; }

    /// <summary>Rate-limit snapshot from the rejecting response's <c>X-RateLimit-*</c> headers.</summary>
    public RateLimitInfo RateLimit { get; }

    internal NetRiskScanRateLimitException(
        string message,
        int? statusCode = null,
        string? code = null,
        string? requestId = null,
        TimeSpan? retryAfter = null,
        RateLimitInfo? rateLimit = null)
        : base(message, statusCode, code, requestId)
    {
        RetryAfter = retryAfter;
        RateLimit = rateLimit ?? new RateLimitInfo();
    }
}
