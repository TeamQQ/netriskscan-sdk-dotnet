namespace NetRiskScan.Exceptions;

/// <summary>
/// Catch-all for any other non-2xx response, including HTTP <c>503</c> <c>temporarily_unavailable</c>
/// and any error code not yet known to this SDK version -- forward compatible with new server-side
/// codes and status combinations.
/// </summary>
public sealed class NetRiskScanApiException : NetRiskScanException
{
    internal NetRiskScanApiException(string message, int? statusCode = null, string? code = null, string? requestId = null)
        : base(message, statusCode, code, requestId)
    {
    }
}
