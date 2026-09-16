using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Microsoft.Extensions.Options;
using NetRiskScan.Exceptions;
using NetRiskScan.Internal;
using NetRiskScan.Models;

namespace NetRiskScan;

/// <summary>
/// Client for the NetRiskScan Developer API.
///
/// Works without an API key -- the anonymous tier, metered by the server -- or with one passed
/// explicitly via <see cref="NetRiskScanOptions.ApiKey"/> or the <c>NETRISKSCAN_API_KEY</c> environment
/// variable. Precedence: explicit option, then the environment variable, then anonymous. See the
/// README for the full behavior of each mode.
///
/// This is a thin, typed HTTP client. It never computes, derives, or overrides a risk score, band, or
/// detection flag -- every value on the result models is exactly what the server returned.
/// </summary>
public sealed class NetRiskScanClient : INetRiskScanClient, IDisposable
{
    /// <summary>The environment variable read for the API key when
    /// <see cref="NetRiskScanOptions.ApiKey"/> is not set.</summary>
    public const string ApiKeyEnvironmentVariable = "NETRISKSCAN_API_KEY";

    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly string? _apiKey;
    private readonly string _baseUrl;
    private readonly TimeSpan _timeout;
    private readonly int _maxRetries;
    private readonly TimeSpan _maxRetryDelay;
    private readonly string _userAgent;
    private bool _disposed;

    /// <summary>
    /// Creates a client that owns its own <see cref="HttpClient"/> (disposed when this client is
    /// disposed). Suitable for a console app, a script, or a short-lived background job:
    ///
    /// <code>
    /// using var client = new NetRiskScanClient();
    /// var result = await client.GetIpRiskAsync("8.8.8.8");
    /// </code>
    ///
    /// In ASP.NET Core, prefer <c>AddNetRiskScan()</c> (see <c>ServiceCollectionExtensions</c>), which
    /// wires the client through <c>IHttpClientFactory</c> instead.
    /// </summary>
    public NetRiskScanClient(NetRiskScanOptions? options = null)
        : this(new HttpClient(), options, ownsHttpClient: true)
    {
    }

    /// <summary>
    /// Creates a client that uses the supplied <see cref="HttpClient"/> without taking ownership of it
    /// -- it is never disposed by this client. Use this to supply an <c>IHttpClientFactory</c>-managed
    /// client, or a client configured with a custom <see cref="HttpMessageHandler"/> (for example one
    /// that injects a mock transport in tests).
    /// </summary>
    public NetRiskScanClient(HttpClient httpClient, NetRiskScanOptions? options = null)
        : this(httpClient, options, ownsHttpClient: false)
    {
    }

    /// <summary>
    /// The dependency-injection constructor used by <c>AddNetRiskScan()</c>: an <c>IHttpClientFactory</c>
    /// managed <see cref="HttpClient"/>, paired with configuration bound through the standard
    /// <see cref="IOptions{TOptions}"/> pipeline (so it participates in configuration reload/validation
    /// like any other ASP.NET Core options type). Callers outside DI should use the
    /// <see cref="NetRiskScanClient(HttpClient, NetRiskScanOptions?)"/> overload instead.
    /// </summary>
    public NetRiskScanClient(HttpClient httpClient, IOptions<NetRiskScanOptions> options)
        : this(httpClient, (options ?? throw new ArgumentNullException(nameof(options))).Value, ownsHttpClient: false)
    {
    }

    private NetRiskScanClient(HttpClient httpClient, NetRiskScanOptions? options, bool ownsHttpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        options ??= new NetRiskScanOptions();

        _httpClient = httpClient;
        _ownsHttpClient = ownsHttpClient;
        _apiKey = ResolveApiKey(options.ApiKey);
        _baseUrl = NormalizeBaseUrl(options.BaseUrl);
        _timeout = ValidatePositive(options.Timeout, nameof(NetRiskScanOptions.Timeout));

        if (options.MaxRetries < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options), options.MaxRetries, $"{nameof(NetRiskScanOptions.MaxRetries)} must be >= 0.");
        }

        _maxRetries = options.MaxRetries;
        _maxRetryDelay = ValidatePositive(options.MaxRetryDelay, nameof(NetRiskScanOptions.MaxRetryDelay));
        _userAgent = string.IsNullOrWhiteSpace(options.UserAgent)
            ? $"netriskscan-dotnet/{SdkVersion.Value}"
            : options.UserAgent;
    }

    /// <inheritdoc />
    public async Task<IpRiskResult> GetIpRiskAsync(string ip, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            // Rejected locally -- an empty string can never be valid, and this avoids turning it into a
            // confusing `.../ip-risk/` request. Anything else is left to the server's own `400
            // invalid_ip` response: the server accepts some lenient/shorthand forms (for example octal
            // octets) a strict client-side parser would reject, and this SDK never disagrees with the
            // server about what counts as a valid address.
            throw new NetRiskScanValidationException("ip must not be empty.", code: "invalid_ip");
        }

        var path = $"/v1/ip-risk/{Uri.EscapeDataString(ip.Trim())}";
        var (result, meta) = await SendAsync(path, NetRiskScanJsonContext.Default.IpRiskResult, cancellationToken)
            .ConfigureAwait(false);
        result.Meta = meta;
        return result;
    }

    /// <inheritdoc />
    public async Task<UsageResult> GetUsageAsync(CancellationToken cancellationToken = default)
    {
        if (_apiKey is null)
        {
            throw new NetRiskScanValidationException(
                "GetUsageAsync requires an API key; anonymous access has no account to report usage for.",
                code: "invalid_api_key");
        }

        var (result, meta) = await SendAsync("/v1/usage", NetRiskScanJsonContext.Default.UsageResult, cancellationToken)
            .ConfigureAwait(false);
        result.Meta = meta;
        return result;
    }

    /// <summary>
    /// Runs one API call end to end: builds the request, applies the per-attempt timeout, retries
    /// transient failures with backoff, and either returns the deserialized result or throws the
    /// matching <see cref="NetRiskScanException"/>.
    /// </summary>
    private async Task<(T Data, ResponseMetadata Meta)> SendAsync<T>(
        string path, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
        where T : class
    {
        var url = $"{_baseUrl}{path}";

        for (var attempt = 0; ; attempt++)
        {
            using var timeoutCts = new CancellationTokenSource(_timeout);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

            HttpResponseMessage response;
            try
            {
                using var request = BuildRequest(url);
                response = await _httpClient
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linkedCts.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // The linked token fired and it was not the caller's own -- the per-attempt timeout
                // elapsed. A caller-cancelled request rethrows untouched: it is not this filter's case,
                // so it propagates past this catch as the OperationCanceledException the caller expects.
                throw new NetRiskScanTimeoutException(
                    $"NetRiskScan API request to {url} timed out after {_timeout.TotalSeconds:0.###}s.", _timeout);
            }
            catch (HttpRequestException ex)
            {
                if (attempt < _maxRetries)
                {
                    await Task.Delay(RetryPolicy.ComputeBackoff(attempt), cancellationToken).ConfigureAwait(false);
                    continue;
                }

                throw new NetRiskScanNetworkException($"Network error while requesting {url}: {ex.Message}", ex);
            }

            using (response)
            {
                if (response.IsSuccessStatusCode)
                {
                    var meta = HeaderParser.ParseResponseMetadata(response);
                    T data;
                    try
                    {
                        var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                        data = await JsonSerializer.DeserializeAsync(stream, typeInfo, cancellationToken).ConfigureAwait(false)
                            ?? throw new NetRiskScanNetworkException($"NetRiskScan API returned an empty response from {url}.");
                    }
                    catch (JsonException ex)
                    {
                        throw new NetRiskScanNetworkException(
                            $"NetRiskScan API returned a malformed JSON response from {url}.", ex);
                    }

                    return (data, meta);
                }

                var retryAfter = HeaderParser.ParseRetryAfter(response);
                if (attempt < _maxRetries && RetryPolicy.IsRetryableStatus(response.StatusCode))
                {
                    var delay = retryAfter ?? RetryPolicy.ComputeBackoff(attempt);
                    if (delay <= _maxRetryDelay)
                    {
                        await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                        continue;
                    }
                }

                throw await ApiErrorParser.ParseAsync(response, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private HttpRequestMessage BuildRequest(string url)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", _userAgent);
        if (_apiKey is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);
        }

        return request;
    }

    private static string? ResolveApiKey(string? explicitKey)
    {
        if (explicitKey is not null)
        {
            if (string.IsNullOrWhiteSpace(explicitKey))
            {
                // Almost always an unset environment variable interpolated into the argument by the
                // caller, not a deliberate request for anonymous access -- so this is a configuration
                // mistake, not silently downgraded to the anonymous tier.
                throw new ArgumentException(
                    "ApiKey must not be empty or consist only of whitespace. Leave it unset for anonymous access.",
                    "ApiKey");
            }

            return explicitKey;
        }

        var envValue = Environment.GetEnvironmentVariable(ApiKeyEnvironmentVariable);
        return string.IsNullOrWhiteSpace(envValue) ? null : envValue;
    }

    private static string NormalizeBaseUrl(string baseUrl)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            throw new ArgumentException("BaseUrl must not be empty.", "BaseUrl");
        }

        return baseUrl.TrimEnd('/');
    }

    private static TimeSpan ValidatePositive(TimeSpan value, string propertyName)
    {
        if (value <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(propertyName, value, $"{propertyName} must be a positive TimeSpan.");
        }

        return value;
    }

    /// <summary>Disposes the underlying <see cref="HttpClient"/> only when this client created it
    /// itself (the parameterless / options-only constructor). A caller-supplied <see cref="HttpClient"/>
    /// -- including one resolved from <c>IHttpClientFactory</c> -- is never disposed here.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }
}
