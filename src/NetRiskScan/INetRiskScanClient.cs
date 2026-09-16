using NetRiskScan.Models;

namespace NetRiskScan;

/// <summary>
/// Typed client for the NetRiskScan Developer API. Register this interface with dependency injection
/// (see <c>AddNetRiskScan</c>) so consumers depend on the abstraction rather than the concrete
/// <see cref="NetRiskScanClient"/>, which makes unit testing a consumer straightforward.
/// </summary>
public interface INetRiskScanClient
{
    /// <summary>
    /// <c>GET /v1/ip-risk/{ip}</c>. Works with or without an API key.
    ///
    /// An address that cannot be scored (private, loopback, reserved, ...) is a normal, successful
    /// response with <see cref="RiskInfo.Index"/> <see langword="null"/> -- it is not raised as an
    /// exception.
    /// </summary>
    /// <param name="ip">An IPv4 or IPv6 address. The server is the sole authority on what is a valid
    /// address; this SDK does not reject an address the server would accept.</param>
    /// <param name="cancellationToken">Propagated to the underlying HTTP call.</param>
    Task<IpRiskResult> GetIpRiskAsync(string ip, CancellationToken cancellationToken = default);

    /// <summary>
    /// <c>GET /v1/usage</c>. Requires an API key -- there is no anonymous account to report usage for.
    /// </summary>
    /// <param name="cancellationToken">Propagated to the underlying HTTP call.</param>
    Task<UsageResult> GetUsageAsync(CancellationToken cancellationToken = default);
}
