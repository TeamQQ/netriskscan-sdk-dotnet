namespace NetRiskScan.Exceptions;

/// <summary>
/// Base class for every error this SDK throws for a request that reached, or attempted to reach, the
/// NetRiskScan API. <c>catch (NetRiskScanException)</c> separates SDK/API failures from bugs in your
/// own code; catch a specific subclass for fine-grained handling.
///
/// The <c>/v1</c> API returns a flat error envelope (<c>{"error": {"code", "message", "requestId"}}</c>)
/// with an open-ended <see cref="Code"/> vocabulary -- the server may add new codes over time. Switch on
/// <see cref="Code"/> for fine-grained handling, or on the exception type for coarse handling.
///
/// Never carries the API key, the <c>Authorization</c> header, or any other sensitive request detail.
/// </summary>
public abstract class NetRiskScanException : Exception
{
    /// <summary>The HTTP status code of the response, when this exception came from one.</summary>
    public int? StatusCode { get; }

    /// <summary>
    /// The server's machine-readable <c>error.code</c>, when one was returned -- e.g.
    /// <c>invalid_ip</c>, <c>rate_limit_exceeded</c>, <c>quota_exceeded</c>. Treat this as an open
    /// value set: a future server release may return a code this SDK version does not yet know about.
    /// </summary>
    public string? Code { get; }

    /// <summary>Trace ID for the failed request (<c>req_…</c>). Include this when reporting an issue.</summary>
    public string? RequestId { get; }

    private protected NetRiskScanException(
        string message,
        int? statusCode = null,
        string? code = null,
        string? requestId = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        StatusCode = statusCode;
        Code = code;
        RequestId = requestId;
    }
}
