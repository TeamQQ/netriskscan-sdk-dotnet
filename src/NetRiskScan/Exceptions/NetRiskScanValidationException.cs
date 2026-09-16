namespace NetRiskScan.Exceptions;

/// <summary>
/// Invalid input. Raised either client-side, before a request is sent (no query unit is spent -- for
/// example calling <see cref="NetRiskScanClient.GetUsageAsync"/> with no API key configured), or
/// returned by the server as HTTP <c>400</c>.
///
/// Server-side codes mapped here: <c>invalid_ip</c>, <c>invalid_request</c>,
/// <c>unsupported_parameter</c>.
/// </summary>
public sealed class NetRiskScanValidationException : NetRiskScanException
{
    internal NetRiskScanValidationException(string message, int? statusCode = null, string? code = null, string? requestId = null)
        : base(message, statusCode, code, requestId)
    {
    }
}
