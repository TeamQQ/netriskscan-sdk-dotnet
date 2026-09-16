namespace NetRiskScan.Exceptions;

/// <summary>
/// The per-attempt timeout budget (<see cref="NetRiskScanOptions.Timeout"/>) elapsed before the server
/// responded.
///
/// Distinct from a caller-cancelled request, which throws <see cref="OperationCanceledException"/> from
/// the <see cref="CancellationToken"/> you passed in, and from <see cref="NetRiskScanNetworkException"/>,
/// which means the request failed for a transport reason other than time. Never retried automatically.
/// </summary>
public sealed class NetRiskScanTimeoutException : NetRiskScanException
{
    /// <summary>The per-attempt budget that elapsed.</summary>
    public TimeSpan Timeout { get; }

    internal NetRiskScanTimeoutException(string message, TimeSpan timeout)
        : base(message)
    {
        Timeout = timeout;
    }
}
