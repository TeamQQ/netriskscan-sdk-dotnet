using NetRiskScan.Models;

namespace NetRiskScan.Exceptions;

/// <summary>
/// HTTP <c>429</c> <c>quota_exceeded</c> (billing-period unit quota exhausted) or
/// <c>anonymous_daily_limit_reached</c> (anonymous daily allowance exhausted).
///
/// Unlike a plain <see cref="NetRiskScanRateLimitException"/>, this does not necessarily clear once
/// <see cref="NetRiskScanRateLimitException.RetryAfter"/> elapses -- a billing-period quota or a daily
/// anonymous allowance can still be exhausted at that time. Waiting for <c>RetryAfter</c> is a floor,
/// not a guarantee. A plain <c>catch (NetRiskScanRateLimitException)</c> also catches this, since it is
/// a subclass.
/// </summary>
public sealed class NetRiskScanQuotaExceededException : NetRiskScanRateLimitException
{
    /// <summary>Quota snapshot from the rejecting response's <c>X-Quota-*</c> headers.</summary>
    public QuotaInfo Quota { get; }

    /// <summary>
    /// The configured daily allowance. Populated only for the anonymous-tier variant of this error
    /// (<c>code == "anonymous_daily_limit_reached"</c>); <see langword="null"/> for a billing-period
    /// <c>quota_exceeded</c> response, which reports its limits through <see cref="Quota"/> instead.
    /// </summary>
    public long? DailyLimit { get; }

    /// <summary>Anonymous requests used today, counting this one. Populated only for the anonymous-tier
    /// variant -- see <see cref="DailyLimit"/>.</summary>
    public long? Used { get; }

    /// <summary>Anonymous requests remaining today. Populated only for the anonymous-tier variant --
    /// see <see cref="DailyLimit"/>.</summary>
    public long? Remaining { get; }

    /// <summary>When the daily allowance resets, as the server's ISO-8601 string. Populated only for
    /// the anonymous-tier variant -- see <see cref="DailyLimit"/>.</summary>
    public string? ResetAt { get; }

    /// <summary>Where to sign up for an API key. Populated only for the anonymous-tier variant -- see
    /// <see cref="DailyLimit"/>.</summary>
    public string? SignupUrl { get; }

    internal NetRiskScanQuotaExceededException(
        string message,
        int? statusCode = null,
        string? code = null,
        string? requestId = null,
        TimeSpan? retryAfter = null,
        RateLimitInfo? rateLimit = null,
        QuotaInfo? quota = null,
        long? dailyLimit = null,
        long? used = null,
        long? remaining = null,
        string? resetAt = null,
        string? signupUrl = null)
        : base(message, statusCode, code, requestId, retryAfter, rateLimit)
    {
        Quota = quota ?? new QuotaInfo();
        DailyLimit = dailyLimit;
        Used = used;
        Remaining = remaining;
        ResetAt = resetAt;
        SignupUrl = signupUrl;
    }
}
