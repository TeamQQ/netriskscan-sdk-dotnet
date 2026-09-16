namespace NetRiskScan.Exceptions;

/// <summary>
/// HTTP <c>401</c> or <c>403</c> -- the API key is missing, invalid, disabled, revoked, expired, or
/// lacks the scope the endpoint requires (<c>ip-risk:read</c>, <c>usage:read</c>).
///
/// Server-side codes mapped here: <c>invalid_api_key</c> (401), <c>api_key_disabled</c> (403),
/// <c>scope_not_allowed</c> (403). Never retried automatically: retrying cannot make a rejected
/// credential valid.
/// </summary>
public sealed class NetRiskScanAuthenticationException : NetRiskScanException
{
    internal NetRiskScanAuthenticationException(string message, int? statusCode = null, string? code = null, string? requestId = null)
        : base(message, statusCode, code, requestId)
    {
    }
}
