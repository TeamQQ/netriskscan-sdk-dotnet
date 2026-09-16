# NetRiskScan .NET SDK

[![NuGet version](https://img.shields.io/nuget/v/NetRiskScan.svg)](https://www.nuget.org/packages/NetRiskScan/)
[![CI](https://github.com/TeamQQ/netriskscan-sdk-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/TeamQQ/netriskscan-sdk-dotnet/actions/workflows/ci.yml)

Official .NET SDK for the [NetRiskScan](https://www.netriskscan.com/) IP Risk & Network Intelligence API: IP reputation, proxy/VPN/Tor detection, datacenter and search-crawler identification, and network intelligence, with first-class ASP.NET Core dependency injection support.

```bash
dotnet add package NetRiskScan
```

```csharp
using NetRiskScan;

using var client = new NetRiskScanClient(); // no signup, no API key required

var result = await client.GetIpRiskAsync("8.8.8.8");

Console.WriteLine(result.Risk.Index); // 0-100, higher = cleaner. Example output; live scores can change.
Console.WriteLine(result.Risk.Band);  // "excellent" | "good" | "fair" | "poor" | "high_risk" | "unknown"
```

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Anonymous usage](#anonymous-usage)
- [Authentication](#authentication)
- [IP risk lookup](#ip-risk-lookup)
- [Usage / quota](#usage--quota)
- [ASP.NET Core dependency injection](#aspnet-core-dependency-injection)
- [Error handling](#error-handling)
- [Rate limits and automatic retries](#rate-limits-and-automatic-retries)
- [Configuration](#configuration)
- [Nullable and tri-state semantics](#nullable-and-tri-state-semantics)
- [Use cases](#use-cases)
- [API documentation](#api-documentation)
- [NetRiskScan ecosystem](#netriskscan-ecosystem)
- [Samples](#samples)
- [Security](#security)
- [License](#license)

## Installation

Targets `net8.0` and `net10.0` (both current .NET LTS releases).

```bash
dotnet add package NetRiskScan
```

## Quick start

```csharp
using NetRiskScan;

using var client = new NetRiskScanClient();
var result = await client.GetIpRiskAsync("8.8.8.8");

Console.WriteLine($"{result.Risk.Index} {result.Risk.Band}");
Console.WriteLine($"{result.Network.Organization} {result.Network.Asn}");
Console.WriteLine($"{result.Flags.Proxy} {result.Flags.Vpn} {result.Flags.Tor}");
```

## Anonymous usage

The API can be called without an account, metered by the server (a daily allowance per source IP, currently 30 requests/day -- the SDK does not hardcode this limit; read it from the response):

```csharp
using var client = new NetRiskScanClient();
var result = await client.GetIpRiskAsync("8.8.8.8");

if (result.Usage is { } usage) // only present on anonymous calls
{
    Console.WriteLine($"{usage.Remaining} of {usage.DailyLimit} requests left today");
}
```

Anonymous quota, rate limits, and eligibility are decided entirely by the server -- the SDK never re-implements or assumes those business rules.

## Authentication

Pass an API key explicitly, or set the `NETRISKSCAN_API_KEY` environment variable. Precedence: explicit option, then environment variable, then anonymous.

```csharp
using var client = new NetRiskScanClient(new NetRiskScanOptions
{
    ApiKey = "nrs_live_xxxxxxxxxxxxxxxxxxxx",
});
```

```bash
export NETRISKSCAN_API_KEY="nrs_live_xxxxxxxxxxxxxxxxxxxx"
```

```csharp
using var client = new NetRiskScanClient(); // reads NETRISKSCAN_API_KEY if set, else anonymous
```

The key is always sent as `Authorization: Bearer <api-key>` -- never as a URL query parameter, never logged, and never included in exception messages. An explicitly-passed empty or whitespace-only key is rejected at construction time (almost always an unset environment variable interpolated into the argument by mistake) rather than silently downgraded to anonymous access.

Keep real keys out of source control -- see [Security](#security).

## IP risk lookup

```csharp
var result = await client.GetIpRiskAsync("8.8.8.8");

result.Risk.Index;            // int? -- 0-100 cleanliness score (higher = cleaner), null if unscoreable
result.Risk.Band;             // string? -- "excellent" | "good" | "fair" | "poor" | "high_risk" | "unknown"
result.Risk.AssessmentGrade;  // string -- "complete" | "partial" | "limited" | "insufficient"
result.Risk.Reasons;          // IReadOnlyList<RiskReason> -- may be empty, never a signal by itself

result.Network.Type;           // "residential" | "mobile" | "hosting" | "datacenter" | "public_infrastructure" | ...
result.Network.ConnectionType; // "direct" | "vpn" | "proxy" | "tor" | ...
result.Network.Asn;            // e.g. "AS15169"
result.Network.Organization;   // e.g. "Google LLC"

result.Flags.Proxy;             // bool? -- see "Nullable and tri-state semantics" below
result.Flags.ProxyType;         // populated only when Flags.Proxy is true
result.Flags.Vpn;               // bool?
result.Flags.Tor;               // bool? -- Tor *exit* node specifically
result.Flags.Datacenter;        // bool?
result.Flags.Scanner;           // bool? -- behavioral scanner/bot activity
result.Flags.Abuse;             // bool?
result.Flags.SearchCrawler;     // bool? -- verified search-engine crawler identity
result.Flags.SearchCrawlerName; // e.g. "Google", populated only when SearchCrawler is true

result.Location; // LocationInfo? -- network-level geolocation, not device GPS
result.Tor;       // TorInfo? -- present only when the address is an actual Tor relay
```

### The index is a cleanliness score, not a threat score

`Risk.Index` runs 0-100 where **higher means cleaner / more trustworthy**. It is not a fraud or threat score where higher is worse. Never invert or rescale it client-side.

### An unscoreable address is a success, not an error

Private, loopback, and other special-purpose addresses return `200 OK` with `Risk.Index is null`, `Risk.Band is null`, and `Risk.AssessmentGrade == "insufficient"` -- not an exception. Check for `null` explicitly rather than assuming every successful call returns a numeric score.

### Search crawler identity vs. scanner behavior

`Flags.SearchCrawler` answers a narrow question: is this address in a range list the search-engine operator itself publishes? It is independent of `Flags.Scanner`, which tracks behavioral scanning/bot activity. A verified crawler is not automatically "not a scanner," and vice versa -- read both.

## Usage / quota

Requires an API key (there is no anonymous account to report usage for):

```csharp
var usage = await client.GetUsageAsync();

Console.WriteLine(usage.Plan);
Console.WriteLine($"{usage.Units.Used} / {usage.Units.Limit}");
Console.WriteLine(usage.RateLimit.RequestsPerMinute);
```

Calling `GetUsageAsync()` without an API key throws `NetRiskScanValidationException` immediately, without a network call.

## ASP.NET Core dependency injection

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddNetRiskScan(options =>
{
    options.ApiKey = builder.Configuration["NetRiskScan:ApiKey"];
});
```

Then depend on `INetRiskScanClient`, not the concrete client:

```csharp
public sealed class RiskService(INetRiskScanClient client)
{
    public async Task<IpRiskResult> CheckAsync(string ip, CancellationToken cancellationToken) =>
        await client.GetIpRiskAsync(ip, cancellationToken);
}
```

`AddNetRiskScan()` registers the client through `IHttpClientFactory` (`services.AddHttpClient<INetRiskScanClient, NetRiskScanClient>()` under the hood), so the underlying `HttpClient` gets correct handler pooling, connection reuse, and DNS refresh -- never a fresh `HttpClient` per request, and never one held forever with stale DNS. It returns the `IHttpClientBuilder`, so you can chain further configuration:

```csharp
builder.Services.AddNetRiskScan(options => options.ApiKey = "nrs_live_...")
    .AddPolicyHandler(/* your own Polly policy, if you use one */);
```

Every method on `INetRiskScanClient` takes a `CancellationToken`, so ASP.NET Core's own request-abort token flows straight through:

```csharp
app.MapGet("/risk/{ip}", async (string ip, INetRiskScanClient client, CancellationToken cancellationToken) =>
    await client.GetIpRiskAsync(ip, cancellationToken));
```

### Outside ASP.NET Core

No DI container required -- construct the client directly:

```csharp
using var client = new NetRiskScanClient();
```

or supply your own `HttpClient` (a custom handler, a mock transport in tests, one you manage yourself):

```csharp
var httpClient = new HttpClient();
var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions { ApiKey = "nrs_live_..." });
```

`NetRiskScanClient` only disposes the `HttpClient` it created itself (the no-argument / options-only constructor); one you pass in -- including an `IHttpClientFactory`-managed one -- is never disposed by the client.

## Error handling

```csharp
using NetRiskScan.Exceptions;

try
{
    var result = await client.GetIpRiskAsync("8.8.8.8");
}
catch (NetRiskScanValidationException ex)
{
    // bad IP address / bad request (HTTP 400), or a local pre-flight check (e.g. GetUsageAsync with no key)
}
catch (NetRiskScanAuthenticationException ex)
{
    // missing, invalid, or disabled API key, or a missing scope (HTTP 401/403)
}
catch (NetRiskScanQuotaExceededException ex)
{
    // billing-period quota or anonymous daily limit exhausted (HTTP 429)
    Console.WriteLine(ex.RetryAfter);
}
catch (NetRiskScanRateLimitException ex)
{
    // short-lived per-minute rate limit (HTTP 429); ex.RetryAfter in seconds
}
catch (NetRiskScanNotFoundException or NetRiskScanFeatureNotAvailableException)
{
    // unknown route, or a documented capability not open yet (HTTP 404)
}
catch (NetRiskScanApiException ex)
{
    // any other non-2xx response, e.g. HTTP 503 temporarily_unavailable
}
catch (NetRiskScanTimeoutException ex)
{
    // request did not complete within the configured Timeout; never retried automatically
}
catch (NetRiskScanNetworkException ex)
{
    // DNS/connection failure, or a malformed response -- never reached the server, or its answer was unusable
}
```

Every exception derives from `NetRiskScanException` and carries `Message`, `StatusCode`, `Code` (the server's open-vocabulary error code), and `RequestId` where available -- include `RequestId` when reporting issues. `NetRiskScanQuotaExceededException` is a subclass of `NetRiskScanRateLimitException`, so `catch (NetRiskScanRateLimitException)` alone catches both.

| Exception | HTTP | Server `error.code` |
| --- | --- | --- |
| `NetRiskScanValidationException` | 400 | `invalid_ip`, `invalid_request`, `unsupported_parameter` |
| `NetRiskScanAuthenticationException` | 401 / 403 | `invalid_api_key`, `api_key_disabled`, `scope_not_allowed` |
| `NetRiskScanNotFoundException` | 404 | `not_found` |
| `NetRiskScanFeatureNotAvailableException` | 404 | `feature_not_available` |
| `NetRiskScanRateLimitException` | 429 | `rate_limit_exceeded` |
| `NetRiskScanQuotaExceededException` | 429 | `quota_exceeded`, `anonymous_daily_limit_reached` |
| `NetRiskScanApiException` | any other non-2xx | `temporarily_unavailable`, or any code not yet known to this SDK version |
| `NetRiskScanTimeoutException` | -- | per-attempt `Timeout` elapsed |
| `NetRiskScanNetworkException` | -- | DNS/connection failure, or an unparseable response |

Treat `Code` as an open value set -- a future server release may return a code this SDK version does not yet know about, and it still surfaces through `NetRiskScanApiException` rather than crashing.

## Rate limits and automatic retries

```csharp
var result = await client.GetIpRiskAsync("8.8.8.8");

if (result.Meta is { } meta)
{
    Console.WriteLine($"{meta.RateLimit.Remaining} / {meta.RateLimit.Limit}");
    Console.WriteLine($"{meta.Quota.Remaining} / {meta.Quota.Limit}");
    Console.WriteLine(meta.RequestId);
}
```

`Meta` is populated by the client from the response headers (`X-RateLimit-*`, `X-Quota-*`, `X-Request-Id`, `X-NetRiskScan-Scoring-Version`) on every successful call. A field is `null` when the server did not send the corresponding header -- never coerced to `0`.

Requests are retried automatically for HTTP `429`/`502`/`503`/`504` and for transient network failures, honoring the server's `Retry-After` header when present, otherwise using exponential backoff with jitter -- matching the retry policy of the official JS and Python SDKs. Retries are capped by `MaxRetries` (default `2`) and `MaxRetryDelay` (default 10 seconds); a `Retry-After` longer than `MaxRetryDelay` raises the exception immediately instead of blocking the caller. `400`/`401`/`403`/`404` responses and request timeouts are never retried.

## Configuration

```csharp
var client = new NetRiskScanClient(new NetRiskScanOptions
{
    ApiKey = "nrs_live_xxxxxxxxxxxxxxxxxxxx", // optional; falls back to NETRISKSCAN_API_KEY, then anonymous
    BaseUrl = "https://api.netriskscan.com",  // override for testing/staging/mocking
    Timeout = TimeSpan.FromSeconds(10),       // per attempt
    MaxRetries = 2,
    MaxRetryDelay = TimeSpan.FromSeconds(10),
});
```

Pass your own `HttpClient` (see [ASP.NET Core dependency injection](#aspnet-core-dependency-injection)) to control connection pooling, proxying, TLS options, or to inject a mock transport in tests.

## Nullable and tri-state semantics

This SDK never computes, derives, or overrides a risk score, band, or detection flag -- every value on the result models is exactly what the server returned. Two null-handling rules follow from that and are worth stating explicitly:

- **`null` is not `false`.** Every detection flag (`Proxy`, `Vpn`, `Tor`, `Datacenter`, `Scanner`, `Abuse`, `SearchCrawler`) is `bool?`: `true` (detected), `false` (checked, confirmed not detected), or `null` (unknown / not evaluated this round) -- three distinct outcomes. Treating `null` as `false` turns "we don't know" into "we checked and it's clean," a different and stronger claim than the data supports.
- **`null` is not `0`.** `Risk.Index` is `int?`. A `null` index means the address could not be scored at all; `0` is a real, valid, maximally-risky score. The two are never conflated.

Every model property has full nullable-reference-type annotations (`<Nullable>enable</Nullable>`), so the compiler -- not just the documentation -- tells you where a `null` check is required.

## Use cases

- Detect proxy, VPN, and Tor infrastructure before signup or login
- Evaluate IP reputation as one signal in a fraud-prevention pipeline
- Distinguish verified search-engine crawlers from generic bot/scanner traffic
- Inspect datacenter and hosting traffic separately from residential networks
- Add network intelligence (ASN, organization, connection type) to abuse-prevention systems in an ASP.NET Core backend or a Worker Service
- Gate CI/CD, infrastructure, or admission checks on a minimum risk index

## API documentation

Base URL: `https://api.netriskscan.com`

- `GET /v1/ip-risk/{ip}` -- IP risk, reputation, and network intelligence (works with or without an API key)
- `GET /v1/usage` -- current billing-period usage and quota (requires an API key)

Full endpoint and error-code reference: [Developer API documentation](https://www.netriskscan.com/).

## NetRiskScan ecosystem

- **.NET SDK** (this package) -- [`NetRiskScan` on NuGet](https://www.nuget.org/packages/NetRiskScan/) (`dotnet add package NetRiskScan`)
- **JavaScript / TypeScript SDK** -- [`@netriskscan/sdk`](https://www.npmjs.com/package/@netriskscan/sdk) on npm
- **Python SDK** -- [`netriskscan`](https://pypi.org/project/netriskscan/) on PyPI (`pip install netriskscan`)
- **CLI** -- [`netriskscan-cli`](https://www.npmjs.com/package/netriskscan-cli) (`npx netriskscan-cli check 8.8.8.8`)
- **Website / Developer API** -- [netriskscan.com](https://www.netriskscan.com/)
- **GitHub** -- [github.com/TeamQQ](https://github.com/TeamQQ)

Need JavaScript, TypeScript, or Python instead? See [`@netriskscan/sdk`](https://www.npmjs.com/package/@netriskscan/sdk) or [`netriskscan`](https://pypi.org/project/netriskscan/).

## Samples

Runnable projects in [`samples/`](samples/):

| Project | Demonstrates |
| --- | --- |
| [`samples/ConsoleExample`](samples/ConsoleExample) | No DI container: `using var client = new NetRiskScanClient();`, anonymous and error-handling paths |
| [`samples/AspNetCoreExample`](samples/AspNetCoreExample) | `AddNetRiskScan()`, `INetRiskScanClient` injected into a service, `CancellationToken` propagation from a minimal API endpoint |

## Security

- The API key is only ever sent as an `Authorization: Bearer` header, never in a URL, log line, or exception message.
- This SDK makes no calls to any host other than the configured `BaseUrl`.
- No telemetry of any kind is collected or transmitted by this package.

Found a security issue? See [SECURITY.md](SECURITY.md).

## License

MIT -- see [LICENSE](LICENSE).
