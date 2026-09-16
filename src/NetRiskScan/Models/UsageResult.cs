using System.Text.Json.Serialization;

namespace NetRiskScan.Models;

/// <summary>
/// The full response of <c>GET /v1/usage</c>. Requires an API key -- there is no anonymous account to
/// report usage for; see <see cref="NetRiskScanClient.GetUsageAsync"/>.
/// </summary>
public sealed record UsageResult
{
    /// <summary>The plan code currently in effect, e.g. <c>growth</c>.</summary>
    [JsonPropertyName("plan")]
    public required string Plan { get; init; }

    /// <summary>The current billing period.</summary>
    [JsonPropertyName("period")]
    public required UsagePeriod Period { get; init; }

    /// <summary>Query units consumed / allowed / remaining for the current billing period.</summary>
    [JsonPropertyName("units")]
    public required UsageUnits Units { get; init; }

    /// <summary>The plan's per-minute throughput limit.</summary>
    [JsonPropertyName("rateLimit")]
    public required UsageRateLimit RateLimit { get; init; }

    /// <summary>
    /// Rate-limit/quota headers and the request id for the HTTP response this result was parsed from.
    /// Populated by <see cref="NetRiskScanClient"/>; never present on a value you construct yourself.
    /// </summary>
    [JsonIgnore]
    public ResponseMetadata? Meta { get; internal set; }
}

/// <summary>The current billing period's start and end.</summary>
public sealed record UsagePeriod
{
    /// <summary>Billing period start.</summary>
    [JsonPropertyName("start")]
    public required DateTimeOffset Start { get; init; }

    /// <summary>Billing period end.</summary>
    [JsonPropertyName("end")]
    public required DateTimeOffset End { get; init; }
}

/// <summary>Query-unit consumption for the current billing period.</summary>
public sealed record UsageUnits
{
    /// <summary>Query units consumed so far this billing period.</summary>
    [JsonPropertyName("used")]
    public required long Used { get; init; }

    /// <summary>Query units the plan allows for the billing period.</summary>
    [JsonPropertyName("limit")]
    public required long Limit { get; init; }

    /// <summary>Query units left this billing period.</summary>
    [JsonPropertyName("remaining")]
    public required long Remaining { get; init; }
}

/// <summary>The plan's per-minute throughput limit.</summary>
public sealed record UsageRateLimit
{
    /// <summary>Requests allowed per minute on the current plan.</summary>
    [JsonPropertyName("requestsPerMinute")]
    public required int RequestsPerMinute { get; init; }
}
