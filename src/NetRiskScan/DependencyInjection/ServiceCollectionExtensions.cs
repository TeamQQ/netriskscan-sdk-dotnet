using Microsoft.Extensions.Options;
using NetRiskScan;

// Deliberately in Microsoft.Extensions.DependencyInjection, the ASP.NET Core convention for
// IServiceCollection extension methods -- a Program.cs that already has `using
// Microsoft.Extensions.DependencyInjection;` (virtually every one does) finds AddNetRiskScan() without
// an extra using directive.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers <see cref="INetRiskScanClient"/> for dependency injection, wired through
/// <c>IHttpClientFactory</c> so the underlying <see cref="HttpClient"/> gets correct handler pooling,
/// lifetime management, and DNS refresh -- never a fresh <see cref="HttpClient"/> per request, and never
/// one held forever with stale DNS.
/// </summary>
public static class NetRiskScanServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="INetRiskScanClient"/> with default options: anonymous access unless
    /// <c>NETRISKSCAN_API_KEY</c> is set in the environment, and the production API base URL.
    /// </summary>
    public static IHttpClientBuilder AddNetRiskScan(this IServiceCollection services) =>
        services.AddNetRiskScan(static _ => { });

    /// <summary>
    /// Registers <see cref="INetRiskScanClient"/>, configured via <paramref name="configureOptions"/>:
    ///
    /// <code>
    /// builder.Services.AddNetRiskScan(options =>
    /// {
    ///     options.ApiKey = builder.Configuration["NetRiskScan:ApiKey"];
    /// });
    /// </code>
    ///
    /// Returns the underlying <see cref="IHttpClientBuilder"/> so callers can chain further
    /// <c>IHttpClientFactory</c> configuration (a <c>Polly</c> handler, a custom
    /// <see cref="DelegatingHandler"/>, and so on) if they need to.
    /// </summary>
    public static IHttpClientBuilder AddNetRiskScan(
        this IServiceCollection services, Action<NetRiskScanOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        services.AddOptions<NetRiskScanOptions>()
            .Configure(configureOptions)
            .Validate(o => !string.IsNullOrWhiteSpace(o.BaseUrl), $"{nameof(NetRiskScanOptions.BaseUrl)} must not be empty.")
            .Validate(o => o.Timeout > TimeSpan.Zero, $"{nameof(NetRiskScanOptions.Timeout)} must be positive.")
            .Validate(o => o.MaxRetries >= 0, $"{nameof(NetRiskScanOptions.MaxRetries)} must be >= 0.")
            .Validate(o => o.MaxRetryDelay > TimeSpan.Zero, $"{nameof(NetRiskScanOptions.MaxRetryDelay)} must be positive.");

        // A typed client, built through an explicit factory rather than AddHttpClient<TClient,
        // TImplementation>()'s default ActivatorUtilities activation: NetRiskScanClient intentionally
        // exposes two (HttpClient, ...) constructors for two different callers (plain
        // NetRiskScanOptions for manual wiring, IOptions<NetRiskScanOptions> for DI), and
        // ActivatorUtilities cannot disambiguate between them from a single HttpClient argument. The
        // client never disposes this HttpClient -- IHttpClientFactory owns its lifetime.
        return services.AddHttpClient<INetRiskScanClient, NetRiskScanClient>(
            (httpClient, provider) => new NetRiskScanClient(httpClient, provider.GetRequiredService<IOptions<NetRiskScanOptions>>()));
    }
}
