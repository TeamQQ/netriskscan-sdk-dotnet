using System.Net;
using NetRiskScan.Exceptions;
using Xunit;

namespace NetRiskScan.Tests;

public sealed class ClientTests
{
    [Fact]
    public async Task GetIpRiskAsync_Anonymous_SendsNoAuthorizationHeader()
    {
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions());

        var result = await client.GetIpRiskAsync("8.8.8.8");

        Assert.Equal("8.8.8.8", result.Ip);
        Assert.Single(handler.Requests);
        Assert.Null(handler.Requests.Single().Headers.Authorization);
    }

    [Fact]
    public async Task GetIpRiskAsync_WithApiKey_SendsBearerHeader()
    {
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions { ApiKey = "nrs_live_testkey123" });

        await client.GetIpRiskAsync("8.8.8.8");

        var request = handler.Requests.Single();
        Assert.NotNull(request.Headers.Authorization);
        Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
        Assert.Equal("nrs_live_testkey123", request.Headers.Authorization.Parameter);
    }

    [Fact]
    public async Task GetIpRiskAsync_UsesConfiguredBaseUrlAndEscapesIp()
    {
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions { BaseUrl = "https://staging.example.com/" });

        await client.GetIpRiskAsync("2001:db8::1");

        var request = handler.Requests.Single();
        Assert.Equal("https://staging.example.com/v1/ip-risk/2001%3Adb8%3A%3A1", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetIpRiskAsync_SendsDefaultUserAgentWithVersion()
    {
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions());

        await client.GetIpRiskAsync("8.8.8.8");

        var userAgent = handler.Requests.Single().Headers.GetValues("User-Agent").Single();
        Assert.StartsWith("netriskscan-dotnet/", userAgent);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task GetIpRiskAsync_RejectsEmptyIp_WithoutSendingRequest(string ip)
    {
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions());

        var ex = await Assert.ThrowsAsync<NetRiskScanValidationException>(() => client.GetIpRiskAsync(ip));

        Assert.Equal("invalid_ip", ex.Code);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task GetIpRiskAsync_DoesNotRejectLenientAddressForms_LeavesValidationToServer()
    {
        // The server accepts lenient forms a strict client-side IP parser would reject (e.g. octal
        // octets). The SDK must never be stricter than the server -- see README "IP validation".
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions());

        await client.GetIpRiskAsync("0177.0.0.1");

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task GetUsageAsync_WithoutApiKey_ThrowsLocallyWithoutSendingRequest()
    {
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.UsageResponse));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions());

        var ex = await Assert.ThrowsAsync<NetRiskScanValidationException>(() => client.GetUsageAsync());

        Assert.Equal("invalid_api_key", ex.Code);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task GetUsageAsync_WithApiKey_ReturnsParsedResult()
    {
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.UsageResponse));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions { ApiKey = "nrs_live_testkey123" });

        var result = await client.GetUsageAsync();

        Assert.Equal("growth", result.Plan);
        Assert.Equal(1200, result.Units.Used);
        Assert.Equal(10000, result.Units.Limit);
        Assert.Equal(8800, result.Units.Remaining);
        Assert.Equal(60, result.RateLimit.RequestsPerMinute);
    }

    [Fact]
    public async Task GetIpRiskAsync_PropagatesCallerCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetIpRiskAsync("8.8.8.8", cts.Token));
    }

    [Fact]
    public void Constructor_RejectsEmptyExplicitApiKey()
    {
        Assert.Throws<ArgumentException>(() => new NetRiskScanClient(new NetRiskScanOptions { ApiKey = "   " }));
    }

    [Fact]
    public void Constructor_RejectsEmptyBaseUrl()
    {
        Assert.Throws<ArgumentException>(() => new NetRiskScanClient(new NetRiskScanOptions { BaseUrl = "" }));
    }

    [Fact]
    public void Constructor_RejectsNonPositiveTimeout()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new NetRiskScanClient(new NetRiskScanOptions { Timeout = TimeSpan.Zero }));
    }

    [Fact]
    public void Constructor_RejectsNegativeMaxRetries()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new NetRiskScanClient(new NetRiskScanOptions { MaxRetries = -1 }));
    }

    [Fact]
    public async Task Dispose_DoesNotDisposeCallerSuppliedHttpClient()
    {
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        using var httpClient = new HttpClient(handler);
        var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions());

        client.Dispose();

        // Would throw ObjectDisposedException if the client had disposed the caller's HttpClient.
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
        var exception = await Record.ExceptionAsync(() => httpClient.SendAsync(request));
        Assert.Null(exception);
    }
}
