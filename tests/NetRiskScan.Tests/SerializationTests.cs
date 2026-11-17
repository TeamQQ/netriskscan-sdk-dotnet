using System.Net;
using System.Text.Json;
using NetRiskScan.Internal;
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

    // ---- API schema 1.6.0: network.domain/range and the five new location fields ----

    [Fact]
    public async Task Schema160_AllSevenFieldsPresent_AreReadVerbatim()
    {
        var result = await QueryAsync(TestJson.IpRiskFullyKnown);

        Assert.Equal("google.com", result.Network.Domain);
        Assert.Equal("8.8.8.0/24", result.Network.Range);
        Assert.Equal("NA", result.Location!.ContinentCode);
        Assert.Equal("North America", result.Location.Continent);
        Assert.Equal("94043", result.Location.PostalCode);
        Assert.Equal(37.4056d, result.Location.Latitude);
        Assert.Equal(-122.0775d, result.Location.Longitude);
    }

    [Fact]
    public async Task Schema160_AllSevenFieldsExplicitNull_AreNull_NotEmptyStringOrZero()
    {
        var result = await QueryAsync(TestJson.IpRiskSchema160AllNewFieldsNull);

        Assert.Null(result.Network.Domain);
        Assert.Null(result.Network.Range);
        Assert.Null(result.Location!.ContinentCode);
        Assert.Null(result.Location.Continent);
        Assert.Null(result.Location.PostalCode);
        Assert.Null(result.Location.Latitude);
        Assert.Null(result.Location.Longitude);

        // The original six location fields keep their values untouched.
        Assert.Equal("US", result.Location.CountryCode);
        Assert.Equal("San Francisco", result.Location.City);
        Assert.Equal("America/Los_Angeles", result.Location.TimeZone);
    }

    [Fact]
    public async Task LegacyServer_MissingSchema160Keys_StillParses_WithNewPropertiesNull()
    {
        var result = await QueryAsync(TestJson.IpRiskLegacyFullyKnown);

        Assert.Null(result.Network.Domain);
        Assert.Null(result.Network.Range);
        Assert.Null(result.Location!.ContinentCode);
        Assert.Null(result.Location.Continent);
        Assert.Null(result.Location.PostalCode);
        Assert.Null(result.Location.Latitude);
        Assert.Null(result.Location.Longitude);

        // Old fields, flags, and risk are unaffected by the missing keys.
        Assert.Equal("8.8.8.8", result.Ip);
        Assert.Equal("AS15169", result.Network.Asn);
        Assert.Equal("Google LLC", result.Network.Organization);
        Assert.Equal("Mountain View", result.Location.City);
        Assert.Equal(95, result.Risk.Index);
        Assert.Equal("excellent", result.Risk.Band);
        Assert.True(result.Flags.SearchCrawler);
        Assert.False(result.Flags.Proxy);
        Assert.Null(result.Usage); // keyed call: no anonymous usage block
    }

    [Fact]
    public async Task LegacyServer_AnonymousCall_StillParses_WithNewPropertiesNull()
    {
        // The anonymous fixture is also pre-1.6.0 shaped: no new keys, but a usage block.
        var result = await QueryAsync(TestJson.IpRiskAnonymousWithUsage);

        Assert.Null(result.Network.Domain);
        Assert.Null(result.Network.Range);
        Assert.Null(result.Location);
        Assert.NotNull(result.Usage);
        Assert.Equal(29, result.Usage!.Remaining);
        Assert.Equal(95, result.Risk.Index);
    }

    [Fact]
    public async Task Schema160_ZeroCoordinates_AreValidValues_NotNull()
    {
        var result = await QueryAsync(TestJson.IpRiskSchema160ZeroCoordinates);

        Assert.Equal(0d, result.Location!.Latitude);
        Assert.Equal(0d, result.Location.Longitude);
    }

    [Fact]
    public async Task Schema160_Anycast_NullCoordinatePair_IsPreserved_NotCompleted()
    {
        var result = await QueryAsync(TestJson.IpRiskSchema160Anycast);

        Assert.Null(result.Location!.Latitude);
        Assert.Null(result.Location.Longitude);
        Assert.Null(result.Location.PostalCode);
        // Known fields around the null pair survive; the SDK never fills the pair in.
        Assert.Equal("US", result.Location.CountryCode);
        Assert.Equal("NA", result.Location.ContinentCode);
        Assert.Equal("google.com", result.Network.Domain);
        Assert.Equal("8.8.8.0/24", result.Network.Range);
    }

    [Fact]
    public async Task Schema160_IPv6Range_IsReadVerbatim()
    {
        var result = await QueryAsync(TestJson.IpRiskSchema160IPv6);

        Assert.Equal("2001:4860:4860::8888", result.Ip);
        Assert.Equal("2001:4860:4840::/42", result.Network.Range);
        Assert.Equal("google.com", result.Network.Domain);
    }

    [Fact]
    public async Task Schema160_PostalCode_KeepsLeadingZeros_AsString()
    {
        var result = await QueryAsync(TestJson.IpRiskSchema160PartialLocation);

        Assert.Equal("00501", result.Location!.PostalCode);
        // A partially-known location keeps what is known and nulls only the rest.
        Assert.Equal("Holtsville", result.Location.City);
        Assert.Null(result.Location.ContinentCode);
        Assert.Null(result.Location.Latitude);
        Assert.Null(result.Location.Longitude);
    }

    [Fact]
    public async Task Schema160_ReservedAddress_DomainAndRangeNull_LocationNull()
    {
        var result = await QueryAsync(TestJson.IpRiskSchema160ReservedAddress);

        Assert.Null(result.Network.Domain);
        Assert.Null(result.Network.Range);
        Assert.Null(result.Location);
        Assert.Null(result.Risk.Index);
        Assert.Null(result.Risk.Band);
        Assert.Equal("insufficient", result.Risk.AssessmentGrade);
    }

    [Fact]
    public async Task Schema160_FutureUnknownFields_InsideNetworkAndLocation_AreStillIgnored()
    {
        // Adding the seven fields must not tighten parsing: a future server extension anywhere in
        // the payload -- including inside network/location -- stays ignorable.
        const string json = """
            {
              "requestId": "req_futurefields01",
              "ip": "8.8.8.8",
              "risk": { "index": 95, "band": "excellent", "assessmentGrade": "complete", "reasons": [] },
              "network": {
                "type": "public_infrastructure", "connectionType": "direct", "asn": "AS15169",
                "organization": "Google LLC", "domain": "google.com", "range": "8.8.8.0/24",
                "futureNetworkField": { "nested": true }
              },
              "flags": {
                "proxy": false, "proxyType": null, "vpn": false, "tor": false, "datacenter": false,
                "scanner": false, "abuse": false, "searchCrawler": null, "searchCrawlerName": null
              },
              "location": {
                "countryCode": "US", "country": "United States", "regionCode": null, "region": null,
                "city": null, "timeZone": null, "continentCode": "NA", "continent": "North America",
                "postalCode": null, "latitude": null, "longitude": null,
                "futureLocationField": "ignored"
              }
            }
            """;

        var result = await QueryAsync(json);

        Assert.Equal("google.com", result.Network.Domain);
        Assert.Equal("8.8.8.0/24", result.Network.Range);
        Assert.Equal("NA", result.Location!.ContinentCode);
        Assert.Null(result.Location.Latitude);
    }

    [Fact]
    public async Task Schema160_PublishedButUnmodeledKeys_EvidenceAndSignals_AreIgnoredGracefully()
    {
        // risk.evidence (schema 1.4.0) and risk.signals (schema 1.5.0) are required keys in the
        // published 1.6.0 contract but are not modeled by this SDK version yet. They must not break
        // parsing, and the modeled risk fields must keep their values.
        var result = await QueryAsync(TestJson.IpRiskFullyKnown);

        Assert.Equal(95, result.Risk.Index);
        Assert.Equal("excellent", result.Risk.Band);
        Assert.Equal("complete", result.Risk.AssessmentGrade);
        Assert.Equal(2, result.Risk.Reasons.Count);
    }

    [Fact]
    public async Task Schema160_SourceGeneratedSerialization_RoundTripsAllSevenFields()
    {
        var result = await QueryAsync(TestJson.IpRiskFullyKnown);

        // Through the SDK's real source-generated context -- no reflection-based fallback.
        var json = JsonSerializer.Serialize(result, NetRiskScanJsonContext.Default.IpRiskResult);
        using var doc = JsonDocument.Parse(json);

        var network = doc.RootElement.GetProperty("network");
        Assert.Equal("google.com", network.GetProperty("domain").GetString());
        Assert.Equal("8.8.8.0/24", network.GetProperty("range").GetString());

        var location = doc.RootElement.GetProperty("location");
        Assert.Equal("NA", location.GetProperty("continentCode").GetString());
        Assert.Equal("North America", location.GetProperty("continent").GetString());
        Assert.Equal("94043", location.GetProperty("postalCode").GetString());
        Assert.Equal(JsonValueKind.Number, location.GetProperty("latitude").ValueKind);
        Assert.Equal(JsonValueKind.Number, location.GetProperty("longitude").ValueKind);
        Assert.Equal(37.4056d, location.GetProperty("latitude").GetDouble());
        Assert.Equal(-122.0775d, location.GetProperty("longitude").GetDouble());

        // Original fields are not lost by the addition.
        Assert.Equal("req_8f3ab21c9dab", doc.RootElement.GetProperty("requestId").GetString());
        Assert.Equal("AS15169", network.GetProperty("asn").GetString());
        Assert.Equal("Mountain View", location.GetProperty("city").GetString());
        Assert.True(doc.RootElement.GetProperty("flags").GetProperty("searchCrawler").GetBoolean());

        var roundTripped = JsonSerializer.Deserialize(json, NetRiskScanJsonContext.Default.IpRiskResult);
        Assert.NotNull(roundTripped);
        Assert.Equal(result.Network.Domain, roundTripped!.Network.Domain);
        Assert.Equal(result.Network.Range, roundTripped.Network.Range);
        Assert.Equal(result.Location!.ContinentCode, roundTripped.Location!.ContinentCode);
        Assert.Equal(result.Location.Continent, roundTripped.Location.Continent);
        Assert.Equal(result.Location.PostalCode, roundTripped.Location.PostalCode);
        Assert.Equal(result.Location.Latitude, roundTripped.Location.Latitude);
        Assert.Equal(result.Location.Longitude, roundTripped.Location.Longitude);
        Assert.Equal(result.Risk.Index, roundTripped.Risk.Index);
        Assert.Equal(result.Flags.SearchCrawler, roundTripped.Flags.SearchCrawler);
    }

    [Fact]
    public async Task Schema160_SourceGeneratedSerialization_NullsStayNull_ZeroStaysZero()
    {
        var allNull = await QueryAsync(TestJson.IpRiskSchema160AllNewFieldsNull);
        var nullJson = JsonSerializer.Serialize(allNull, NetRiskScanJsonContext.Default.IpRiskResult);
        using var nullDoc = JsonDocument.Parse(nullJson);

        var nullNetwork = nullDoc.RootElement.GetProperty("network");
        Assert.Equal(JsonValueKind.Null, nullNetwork.GetProperty("domain").ValueKind);
        Assert.Equal(JsonValueKind.Null, nullNetwork.GetProperty("range").ValueKind);
        var nullLocation = nullDoc.RootElement.GetProperty("location");
        Assert.Equal(JsonValueKind.Null, nullLocation.GetProperty("continentCode").ValueKind);
        Assert.Equal(JsonValueKind.Null, nullLocation.GetProperty("continent").ValueKind);
        Assert.Equal(JsonValueKind.Null, nullLocation.GetProperty("postalCode").ValueKind);
        Assert.Equal(JsonValueKind.Null, nullLocation.GetProperty("latitude").ValueKind);
        Assert.Equal(JsonValueKind.Null, nullLocation.GetProperty("longitude").ValueKind);

        var zero = await QueryAsync(TestJson.IpRiskSchema160ZeroCoordinates);
        var zeroJson = JsonSerializer.Serialize(zero, NetRiskScanJsonContext.Default.IpRiskResult);
        using var zeroDoc = JsonDocument.Parse(zeroJson);

        var zeroLocation = zeroDoc.RootElement.GetProperty("location");
        Assert.Equal(JsonValueKind.Number, zeroLocation.GetProperty("latitude").ValueKind);
        Assert.Equal(JsonValueKind.Number, zeroLocation.GetProperty("longitude").ValueKind);
        Assert.Equal(0d, zeroLocation.GetProperty("latitude").GetDouble());
        Assert.Equal(0d, zeroLocation.GetProperty("longitude").GetDouble());
    }
}
