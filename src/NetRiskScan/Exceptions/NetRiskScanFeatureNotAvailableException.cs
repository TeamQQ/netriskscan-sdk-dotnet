namespace NetRiskScan.Exceptions;

/// <summary>
/// HTTP <c>404</c> <c>feature_not_available</c> -- a documented but not-yet-enabled capability (for
/// example a future batch endpoint).
/// </summary>
public sealed class NetRiskScanFeatureNotAvailableException : NetRiskScanException
{
    internal NetRiskScanFeatureNotAvailableException(string message, int? statusCode = null, string? code = null, string? requestId = null)
        : base(message, statusCode, code, requestId)
    {
    }
}
