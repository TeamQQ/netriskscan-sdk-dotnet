using System.Net;

namespace NetRiskScan.Internal;

/// <summary>
/// Retry/backoff decisions, matching the official JS and Python SDKs' policy so behavior is consistent
/// across every official NetRiskScan client.
///
/// Every method this SDK exposes is a <c>GET</c>, so nothing here needs to reason about which HTTP
/// methods are safe to retry -- unlike the JS/Python SDKs, which share request plumbing with
/// hypothetical future non-GET calls.
/// </summary>
internal static class RetryPolicy
{
    /// <summary>
    /// 502/504 are not currently observed from the NetRiskScan application itself (only 503
    /// <c>temporarily_unavailable</c> is documented/implemented), but are included defensively for the
    /// reverse-proxy/gateway layer in front of it.
    /// </summary>
    private static readonly HashSet<HttpStatusCode> RetryableStatusCodes =
    [
        (HttpStatusCode)429,
        HttpStatusCode.BadGateway,
        HttpStatusCode.ServiceUnavailable,
        HttpStatusCode.GatewayTimeout,
    ];

    private const double BaseDelayMs = 250;
    private const double JitterRatio = 0.25;

    public static bool IsRetryableStatus(HttpStatusCode status) => RetryableStatusCodes.Contains(status);

    /// <summary>
    /// Exponential backoff with jitter, used when the server did not send a usable <c>Retry-After</c>.
    /// <paramref name="attempt"/> is 0-indexed (0 = delay before the first retry).
    /// </summary>
    public static TimeSpan ComputeBackoff(int attempt)
    {
        var stepMs = BaseDelayMs * Math.Pow(2, attempt);
        var jitterMs = Random.Shared.NextDouble() * stepMs * JitterRatio;
        return TimeSpan.FromMilliseconds(stepMs + jitterMs);
    }
}
