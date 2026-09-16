namespace NetRiskScan.Exceptions;

/// <summary>
/// The request never produced a usable HTTP response -- DNS failure, connection reset, TLS error, or a
/// response body that was not valid JSON / not the expected shape.
///
/// The originating exception, when there is one, is available via <see cref="Exception.InnerException"/>.
/// </summary>
public sealed class NetRiskScanNetworkException : NetRiskScanException
{
    internal NetRiskScanNetworkException(string message, Exception? innerException = null)
        : base(message, innerException: innerException)
    {
    }
}
