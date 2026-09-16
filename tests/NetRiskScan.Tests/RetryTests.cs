using System.Net;
using NetRiskScan.Exceptions;
using Xunit;

namespace NetRiskScan.Tests;

/// <summary>
/// Automatic retry behavior: only <c>429</c>/<c>502</c>/<c>503</c>/<c>504</c> and transient network
/// failures are retried, bounded by <c>MaxRetries</c>/<c>MaxRetryDelay</c>, honoring <c>Retry-After</c>
/// when present. <c>400</c>/<c>401</c>/<c>403</c>/<c>404</c> are never retried.
/// </summary>
public sealed class RetryTests
{
    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    public async Task RetryableStatus_SucceedsAfterOneRetry(HttpStatusCode transientStatus)
    {
        var handler = FakeHttpMessageHandler.Sequence(
            FakeHttpMessageHandler.JsonResponse(transientStatus, TestJson.ErrorEnvelope("temporarily_unavailable", "retry me"), r => r.Headers.Add("Retry-After", "0")),
            FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions { MaxRetries = 2 });

        var result = await client.GetIpRiskAsync("8.8.8.8");

        Assert.Equal("8.8.8.8", result.Ip);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.NotFound)]
    public async Task NonRetryableStatus_FailsOnFirstAttempt(HttpStatusCode status)
    {
        var handler = FakeHttpMessageHandler.Sequence(
            FakeHttpMessageHandler.JsonResponse(status, TestJson.ErrorEnvelope("some_code", "failure")),
            FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions { MaxRetries = 2 });

        await Assert.ThrowsAnyAsync<NetRiskScanException>(() => client.GetIpRiskAsync("8.8.8.8"));

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ExhaustingMaxRetries_ThrowsTheMappedException()
    {
        var handler = new FakeHttpMessageHandler(_ => FakeHttpMessageHandler.JsonResponse(
            HttpStatusCode.ServiceUnavailable, TestJson.ErrorEnvelope("temporarily_unavailable", "down"), r => r.Headers.Add("Retry-After", "0")));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions { MaxRetries = 2 });

        await Assert.ThrowsAsync<NetRiskScanApiException>(() => client.GetIpRiskAsync("8.8.8.8"));

        // The initial attempt plus exactly MaxRetries retries -- never open-ended.
        Assert.Equal(3, handler.Requests.Count);
    }

    [Fact]
    public async Task RetryAfterLongerThanMaxRetryDelay_RaisesImmediately_WithoutBlocking()
    {
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(
            HttpStatusCode.TooManyRequests, TestJson.ErrorEnvelope("rate_limit_exceeded", "slow down"), r => r.Headers.Add("Retry-After", "3600")));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions
        {
            MaxRetries = 3,
            MaxRetryDelay = TimeSpan.FromSeconds(1),
        });

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var ex = await Assert.ThrowsAsync<NetRiskScanRateLimitException>(() => client.GetIpRiskAsync("8.8.8.8"));
        sw.Stop();

        Assert.Single(handler.Requests);
        Assert.Equal(TimeSpan.FromHours(1), ex.RetryAfter);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"Expected an immediate failure, took {sw.Elapsed}");
    }

    [Fact]
    public async Task MaxRetriesZero_NeverRetries()
    {
        var handler = FakeHttpMessageHandler.Sequence(
            FakeHttpMessageHandler.JsonResponse(HttpStatusCode.ServiceUnavailable, TestJson.ErrorEnvelope("temporarily_unavailable", "down")),
            FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions { MaxRetries = 0 });

        await Assert.ThrowsAsync<NetRiskScanApiException>(() => client.GetIpRiskAsync("8.8.8.8"));

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task TransientNetworkFailure_IsRetried()
    {
        var attempt = 0;
        var handler = new FakeHttpMessageHandler((_, _) =>
        {
            attempt++;
            if (attempt == 1)
            {
                throw new HttpRequestException("connection reset");
            }

            return Task.FromResult(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        });
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions { MaxRetries = 2 });

        var result = await client.GetIpRiskAsync("8.8.8.8");

        Assert.Equal("8.8.8.8", result.Ip);
        Assert.Equal(2, attempt);
    }

    [Fact]
    public async Task TransientNetworkFailure_ExhaustingRetries_ThrowsNetworkException()
    {
        var handler = new FakeHttpMessageHandler((_, _) => throw new HttpRequestException("connection reset"));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions { MaxRetries = 1 });

        var ex = await Assert.ThrowsAsync<NetRiskScanNetworkException>(() => client.GetIpRiskAsync("8.8.8.8"));
        Assert.NotNull(ex.InnerException);
    }
}
