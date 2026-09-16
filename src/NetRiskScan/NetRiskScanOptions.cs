namespace NetRiskScan;

/// <summary>Configuration for <see cref="NetRiskScanClient"/>.</summary>
public sealed class NetRiskScanOptions
{
    /// <summary>
    /// The NetRiskScan API key (<c>nrs_live_…</c>). Optional -- when not set here and the
    /// <c>NETRISKSCAN_API_KEY</c> environment variable is not set either, the client uses the
    /// anonymous tier, metered by the server. See <see cref="NetRiskScanClient"/> for the full
    /// precedence rules.
    ///
    /// Never placed in a URL, logged, or included in an exception message.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// The API base URL. Defaults to the production API; override for testing, staging, or a mock
    /// server.
    /// </summary>
    public string BaseUrl { get; set; } = "https://api.netriskscan.com";

    /// <summary>The per-attempt request timeout. Defaults to 10 seconds.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// How many times a failed request is retried automatically. Defaults to 2. Only <c>429</c>,
    /// <c>502</c>, <c>503</c>, <c>504</c>, and transient network failures are retried -- see the
    /// README "Automatic retries" section.
    /// </summary>
    public int MaxRetries { get; set; } = 2;

    /// <summary>
    /// The longest delay before a retry this client will wait for. A server <c>Retry-After</c> longer
    /// than this raises the corresponding exception immediately instead of blocking the caller.
    /// Defaults to 10 seconds.
    /// </summary>
    public TimeSpan MaxRetryDelay { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Overrides the default <c>User-Agent</c> header (<c>netriskscan-dotnet/&lt;version&gt;</c>).
    /// Most callers should not set this.
    /// </summary>
    public string? UserAgent { get; set; }
}
