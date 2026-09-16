namespace NetRiskScan.Models;

/// <summary>
/// Out-of-band metadata for one HTTP response: rate-limit/quota snapshots and trace identifiers read
/// from response headers, not from the JSON body.
///
/// Populated by <see cref="NetRiskScanClient"/> on every successful call and exposed via the
/// <c>Meta</c> property on <see cref="IpRiskResult"/> and <see cref="UsageResult"/>. A field is
/// <see langword="null"/> when the server did not send the corresponding header -- never coerced to
/// <c>0</c>, which would be a real (very low) limit.
/// </summary>
public sealed record ResponseMetadata
{
    /// <summary>The HTTP status code of the response this metadata was read from.</summary>
    public required int StatusCode { get; init; }

    /// <summary>Trace ID for this request (<c>X-Request-Id</c>). Quote it in a support request.</summary>
    public string? RequestId { get; init; }

    /// <summary>Which scoring algorithm produced this response (<c>X-NetRiskScan-Scoring-Version</c>),
    /// e.g. <c>risk-v4.35</c>. Not promised to be numerically stable across versions.</summary>
    public string? ScoringVersion { get; init; }

    /// <summary>Parsed <c>X-RateLimit-*</c> headers: the per-minute throughput limit.</summary>
    public RateLimitInfo RateLimit { get; init; } = new();

    /// <summary>Parsed <c>X-Quota-*</c> headers: the billing-period unit quota.</summary>
    public QuotaInfo Quota { get; init; } = new();
}

/// <summary>Parsed <c>X-RateLimit-*</c> response headers.</summary>
public sealed record RateLimitInfo
{
    /// <summary>Requests allowed per minute on the current plan (<c>X-RateLimit-Limit</c>).</summary>
    public int? Limit { get; init; }

    /// <summary>Requests left in the current one-minute window (<c>X-RateLimit-Remaining</c>).</summary>
    public int? Remaining { get; init; }

    /// <summary>Unix timestamp (seconds) when the current window resets (<c>X-RateLimit-Reset</c>).</summary>
    public long? Reset { get; init; }
}

/// <summary>Parsed <c>X-Quota-*</c> response headers.</summary>
public sealed record QuotaInfo
{
    /// <summary>Query units the plan allows for the current billing period (<c>X-Quota-Limit</c>).</summary>
    public long? Limit { get; init; }

    /// <summary>Query units consumed in the current billing period (<c>X-Quota-Used</c>).</summary>
    public long? Used { get; init; }

    /// <summary>Query units left in the current billing period (<c>X-Quota-Remaining</c>).</summary>
    public long? Remaining { get; init; }
}
