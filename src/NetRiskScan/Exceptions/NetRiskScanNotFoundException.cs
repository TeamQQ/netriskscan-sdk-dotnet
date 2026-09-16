namespace NetRiskScan.Exceptions;

/// <summary>HTTP <c>404</c> <c>not_found</c> -- no such route.</summary>
public sealed class NetRiskScanNotFoundException : NetRiskScanException
{
    internal NetRiskScanNotFoundException(string message, int? statusCode = null, string? code = null, string? requestId = null)
        : base(message, statusCode, code, requestId)
    {
    }
}
