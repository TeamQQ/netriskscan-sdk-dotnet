using System.Net;
using Xunit;

namespace NetRiskScan.Tests;

/// <summary>
/// Verifies the model layer is a faithful projection of the wire format: tri-state detection flags stay
/// three-valued, a null <c>risk.index</c> is never coerced to <c>0</c> (and vice versa), optional
/// objects are null exactly when the JSON omits or nulls them, and unknown fields never break
/// deserialization -- see spec sections 十六 through十九 and 二十三 of the project brief.
/// </summary>
public sealed class SerializationTests
{
    private static async Task<Models.IpRiskResult> QueryAsync(string json)
    {
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, json));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions());
        return await client.GetIpRiskAsync("8.8.8.8");
    }

    [Fact]
    public async Task TriStateFlags_TrueIsTrue_FalseIsFalse_NullIsNull()
    {
        var falseResult = await QueryAsync(TestJson.IpRiskFullyKnown);
        Assert.False(falseResult.Flags.Proxy);
        Assert.False(falseResult.Flags.Vpn);
        Assert.True(falseResult.Flags.SearchCrawler);

        var nullResult = await QueryAsync(TestJson.IpRiskUnknownFlags);
        Assert.Null(nullResult.Flags.Proxy);
        Assert.Null(nullResult.Flags.Vpn);
        Assert.Null(nullResult.Flags.Tor);
        Assert.Null(nullResult.Flags.Datacenter);
        Assert.Null(nullResult.Flags.Scanner);
        Assert.Null(nullResult.Flags.Abuse);
        Assert.Null(nullResult.Flags.SearchCrawler);

        var trueResult = await QueryAsync(TestJson.IpRiskZeroIndex);
        Assert.True(trueResult.Flags.Proxy);
        Assert.True(trueResult.Flags.Datacenter);
        Assert.True(trueResult.Flags.Abuse);
    }

    [Fact]
    public async Task RiskIndex_ZeroIsNotConflatedWithNull()
    {
        var zeroScored = await QueryAsync(TestJson.IpRiskZeroIndex);
        Assert.NotNull(zeroScored.Risk.Index);
        Assert.Equal(0, zeroScored.Risk.Index);
        Assert.Equal("high_risk", zeroScored.Risk.Band);

        var unscoreable = await QueryAsync(TestJson.IpRiskUnknownFlags);
        Assert.Null(unscoreable.Risk.Index);
        Assert.Null(unscoreable.Risk.Band);
        Assert.Equal("insufficient", unscoreable.Risk.AssessmentGrade);
    }

    [Fact]
    public async Task ProxyType_NonNullOnlyWhenProxyIsTrue()
    {
        var proxyDetected = await QueryAsync(TestJson.IpRiskZeroIndex);
        Assert.True(proxyDetected.Flags.Proxy);
        Assert.Equal("datacenter_proxy", proxyDetected.Flags.ProxyType);

        var proxyFalse = await QueryAsync(TestJson.IpRiskFullyKnown);
        Assert.False(proxyFalse.Flags.Proxy);
        Assert.Null(proxyFalse.Flags.ProxyType);
    }

    [Fact]
    public async Task Location_NullWhenServerSendsNull()
    {
        var result = await QueryAsync(TestJson.IpRiskUnknownFlags);
        Assert.Null(result.Location);
    }

    [Fact]
    public async Task Location_PopulatedWhenServerSendsLocation()
    {
        var result = await QueryAsync(TestJson.IpRiskFullyKnown);
        Assert.NotNull(result.Location);
        Assert.Equal("US", result.Location!.CountryCode);
        Assert.Equal("Mountain View", result.Location.City);
    }

    [Fact]
    public async Task Tor_AbsentForNonTorAddress()
    {
        var result = await QueryAsync(TestJson.IpRiskFullyKnown);
        Assert.Null(result.Tor);
    }

    [Fact]
    public async Task Tor_PopulatedForTorRelay()
    {
        var result = await QueryAsync(TestJson.IpRiskTorExit);
        Assert.NotNull(result.Tor);
        Assert.True(result.Tor!.IsRelay);
        Assert.True(result.Tor.IsExit);
        Assert.False(result.Tor.IsBadExit);
        Assert.Equal("exit", result.Tor.Role);
        // The same fact as flags.tor -- the two must agree.
        Assert.Equal(result.Flags.Tor, result.Tor.IsExit);
    }

    [Fact]
    public async Task Usage_AbsentOnApiKeyResponses_PresentOnAnonymousResponses()
    {
        var keyed = await QueryAsync(TestJson.IpRiskFullyKnown);
        Assert.Null(keyed.Usage);

        var anonymous = await QueryAsync(TestJson.IpRiskAnonymousWithUsage);
        Assert.NotNull(anonymous.Usage);
        Assert.Equal("anonymous", anonymous.Usage!.Mode);
        Assert.Equal(30, anonymous.Usage.DailyLimit);
        Assert.Equal(1, anonymous.Usage.Used);
        Assert.Equal(29, anonymous.Usage.Remaining);
    }

    [Fact]
    public async Task UnknownJsonFields_AreIgnored_NotAnError()
    {
        // A field the server adds after this SDK version ships must never break deserialization.
        var result = await QueryAsync(TestJson.IpRiskWithUnknownField);
        Assert.Equal("8.8.8.8", result.Ip);
        Assert.Equal(95, result.Risk.Index);
    }

    [Fact]
    public async Task Reasons_EmptyArray_NotNull_WhenNothingFired()
    {
        var result = await QueryAsync(TestJson.IpRiskAnonymousWithUsage);
        Assert.NotNull(result.Risk.Reasons);
        Assert.Empty(result.Risk.Reasons);
    }

    [Fact]
    public async Task NetworkProfileAndService_NullWhenNoFirstPartyRecord()
    {
        var result = await QueryAsync(TestJson.IpRiskZeroIndex);
        Assert.Null(result.Network.Profile);
        Assert.Null(result.Network.Service);
    }

    [Fact]
    public async Task Meta_PopulatedFromResponseHeaders()
    {
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(
            HttpStatusCode.OK,
            TestJson.IpRiskFullyKnown,
            response =>
            {
                response.Headers.Add("X-Request-Id", "req_headertest001");
                response.Headers.Add("X-NetRiskScan-Scoring-Version", "risk-v4.35");
                response.Headers.Add("X-RateLimit-Limit", "60");
                response.Headers.Add("X-RateLimit-Remaining", "59");
                response.Headers.Add("X-RateLimit-Reset", "1700000000");
                response.Headers.Add("X-Quota-Limit", "10000");
                response.Headers.Add("X-Quota-Used", "1");
                response.Headers.Add("X-Quota-Remaining", "9999");
            }));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions());

        var result = await client.GetIpRiskAsync("8.8.8.8");

        Assert.NotNull(result.Meta);
        Assert.Equal(200, result.Meta!.StatusCode);
        Assert.Equal("req_headertest001", result.Meta.RequestId);
        Assert.Equal("risk-v4.35", result.Meta.ScoringVersion);
        Assert.Equal(60, result.Meta.RateLimit.Limit);
        Assert.Equal(59, result.Meta.RateLimit.Remaining);
        Assert.Equal(1700000000, result.Meta.RateLimit.Reset);
        Assert.Equal(10000, result.Meta.Quota.Limit);
        Assert.Equal(1, result.Meta.Quota.Used);
        Assert.Equal(9999, result.Meta.Quota.Remaining);
    }

    [Fact]
    public async Task Meta_MissingHeaders_AreNullNotZero()
    {
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions());

        var result = await client.GetIpRiskAsync("8.8.8.8");

        Assert.NotNull(result.Meta);
        Assert.Null(result.Meta!.RateLimit.Limit);
        Assert.Null(result.Meta.Quota.Limit);
        Assert.Null(result.Meta.RequestId);
    }
}
