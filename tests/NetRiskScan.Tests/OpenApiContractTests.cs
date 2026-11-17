using System.Text.Json;
using Xunit;

namespace NetRiskScan.Tests;

/// <summary>
/// Pins this SDK's models against the fields required by the published <c>/v1</c> OpenAPI contract
/// (<c>Doc/openapi/paid-api-v1.yaml</c>, schema version 1.6.0, in the main NetRiskScan repository at
/// commit <c>6e936691</c> -- the <c>ip-intelligence-completeness-v1</c> release this SDK upgrade tracks).
///
/// This is a local pin, not a live fetch: the main repository is a separate project this SDK does not
/// depend on at build or test time (see the project report's "OpenAPI Contract Tests" section for why,
/// and for the recommendation to vendor the spec file directly into CI for a tighter guarantee).
/// If a future contract revision adds/renames/removes a required field, this test file is the first
/// place to update -- and a failure here is a prompt to re-review the spec, not to "fix" the assertion
/// without checking it first.
///
/// Three distinct contract concepts are pinned separately here, because conflating them is exactly how
/// a nullable/optional/required bug slips in:
/// <list type="bullet">
/// <item><b>Required key</b> -- the JSON object must always carry the key (OpenAPI <c>required</c>).
/// A required key's value may still be null.</item>
/// <item><b>Nullable value</b> -- the key's value may be JSON null (OpenAPI <c>type: [T, 'null']</c>).
/// All seven schema-1.6.0 additions are required keys with nullable values.</item>
/// <item><b>Optional key</b> -- the key may be omitted entirely (not in <c>required</c>), e.g.
/// <c>network.profile</c>/<c>network.service</c>, which are omitted -- never sent as null -- when no
/// first-party record exists, and the top-level <c>tor</c>/<c>usage</c> blocks.</item>
/// </list>
///
/// Known gap, reported rather than hidden: the published 1.6.0 contract also requires
/// <c>risk.evidence</c> (added in schema 1.4.0) and <c>risk.signals</c> (added in schema 1.5.0). This
/// SDK version does not model those two objects yet -- they arrived between the 1.3.0 pin this SDK was
/// built against and the 1.6.0 revision tracked here, and modeling them is separate follow-up work.
/// The fixture carries them and the SDK ignores them gracefully (unknown-key tolerance), so runtime
/// compatibility holds; <see cref="SerializationTests.Schema160_PublishedButUnmodeledKeys_EvidenceAndSignals_AreIgnoredGracefully"/>
/// pins that behavior.
/// </summary>
public sealed class OpenApiContractTests
{
    private static readonly string[] IpRiskResponseRequiredKeys = ["requestId", "ip", "risk", "network", "flags", "location"];
    private static readonly string[] RiskRequiredKeys = ["index", "band", "assessmentGrade", "reasons", "evidence", "signals"];
    private static readonly string[] NetworkRequiredKeys = ["type", "connectionType", "asn", "organization", "domain", "range"];
    private static readonly string[] FlagsRequiredKeys =
        ["proxy", "proxyType", "vpn", "tor", "datacenter", "scanner", "abuse", "searchCrawler", "searchCrawlerName"];
    private static readonly string[] LocationRequiredKeys =
        ["countryCode", "country", "regionCode", "region", "city", "timeZone", "continentCode", "continent", "postalCode", "latitude", "longitude"];
    private static readonly string[] TorRelayRequiredKeys = ["isRelay", "isExit", "isBadExit", "role"];
    private static readonly string[] UsageResponseRequiredKeys = ["plan", "period", "units", "rateLimit"];
    private static readonly string[] ErrorEnvelopeRequiredKeys = ["code", "message", "requestId"];

    /// <summary>The seven fields added by schema 1.6.0: two on network, five on location.</summary>
    private static readonly string[] Schema160NetworkAdditions = ["domain", "range"];
    private static readonly string[] Schema160LocationAdditions = ["continentCode", "continent", "postalCode", "latitude", "longitude"];

    /// <summary>The pre-1.6.0 required sets, pinned separately so an additive revision can never
    /// silently drop or rename an original required key.</summary>
    private static readonly string[] LegacyNetworkRequiredKeys = ["type", "connectionType", "asn", "organization"];
    private static readonly string[] LegacyLocationRequiredKeys = ["countryCode", "country", "regionCode", "region", "city", "timeZone"];
    private static readonly string[] LegacyRiskRequiredKeys = ["index", "band", "assessmentGrade", "reasons"];

    /// <summary>The complete, documented <c>error.code</c> vocabulary as of schema 1.6.0 (unchanged
    /// since 1.3.0). Open-ended in practice (the server may add more), but every one of these must still
    /// map to a specific exception type -- see <see cref="ErrorHandlingTests"/> for the per-code
    /// assertions.</summary>
    private static readonly string[] DocumentedErrorCodes =
    [
        "invalid_ip", "invalid_request", "unsupported_parameter", "invalid_api_key", "api_key_disabled",
        "scope_not_allowed", "not_found", "feature_not_available", "rate_limit_exceeded", "quota_exceeded",
        "anonymous_daily_limit_reached", "temporarily_unavailable",
    ];

    [Fact]
    public void IpRiskFixture_ContainsExactlyTheDocumentedRequiredKeys()
    {
        using var doc = JsonDocument.Parse(TestJson.IpRiskFullyKnown);
        AssertKeysPresent(doc.RootElement, IpRiskResponseRequiredKeys);
        AssertKeysPresent(doc.RootElement.GetProperty("risk"), RiskRequiredKeys);
        AssertKeysPresent(doc.RootElement.GetProperty("network"), NetworkRequiredKeys);
        AssertKeysPresent(doc.RootElement.GetProperty("flags"), FlagsRequiredKeys);
        AssertKeysPresent(doc.RootElement.GetProperty("location"), LocationRequiredKeys);
    }

    [Fact]
    public void Schema160Fixture_NetworkAndLocation_CarryAllSevenNewRequiredKeys()
    {
        using var doc = JsonDocument.Parse(TestJson.IpRiskFullyKnown);
        AssertKeysPresent(doc.RootElement.GetProperty("network"), Schema160NetworkAdditions);
        AssertKeysPresent(doc.RootElement.GetProperty("location"), Schema160LocationAdditions);
    }

    [Fact]
    public void Schema160NewFields_AreNullable_ExplicitNullIsAValidValue()
    {
        // Required key + nullable value: the 1.6.0 server always sends the seven keys, and may send
        // any of them as JSON null. The all-null fixture pins that shape.
        using var doc = JsonDocument.Parse(TestJson.IpRiskSchema160AllNewFieldsNull);

        foreach (var key in Schema160NetworkAdditions)
        {
            Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("network").GetProperty(key).ValueKind);
        }

        foreach (var key in Schema160LocationAdditions)
        {
            Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("location").GetProperty(key).ValueKind);
        }
    }

    [Fact]
    public void Schema160Coordinates_AreJsonNumbers_NotStrings_AndZeroIsANumber()
    {
        using var populated = JsonDocument.Parse(TestJson.IpRiskFullyKnown);
        var location = populated.RootElement.GetProperty("location");
        Assert.Equal(JsonValueKind.Number, location.GetProperty("latitude").ValueKind);
        Assert.Equal(JsonValueKind.Number, location.GetProperty("longitude").ValueKind);

        using var zero = JsonDocument.Parse(TestJson.IpRiskSchema160ZeroCoordinates);
        var zeroLocation = zero.RootElement.GetProperty("location");
        Assert.Equal(JsonValueKind.Number, zeroLocation.GetProperty("latitude").ValueKind);
        Assert.Equal(0d, zeroLocation.GetProperty("latitude").GetDouble());
        Assert.Equal(JsonValueKind.Number, zeroLocation.GetProperty("longitude").ValueKind);
        Assert.Equal(0d, zeroLocation.GetProperty("longitude").GetDouble());
    }

    [Fact]
    public void Schema160StringAdditions_AreJsonStrings_WhenPresent()
    {
        using var doc = JsonDocument.Parse(TestJson.IpRiskFullyKnown);
        var network = doc.RootElement.GetProperty("network");
        Assert.Equal(JsonValueKind.String, network.GetProperty("domain").ValueKind);
        Assert.Equal(JsonValueKind.String, network.GetProperty("range").ValueKind);

        var location = doc.RootElement.GetProperty("location");
        Assert.Equal(JsonValueKind.String, location.GetProperty("continentCode").ValueKind);
        Assert.Equal(JsonValueKind.String, location.GetProperty("continent").ValueKind);
        // postalCode is a string, never a number -- leading zeros must survive.
        Assert.Equal(JsonValueKind.String, location.GetProperty("postalCode").ValueKind);
    }

    [Fact]
    public void LegacyServerFixture_OmitsAllSevenSchema160Keys()
    {
        // Backward compatibility pin: a pre-1.6.0 server omits the new keys entirely. The SDK must
        // still parse that shape (asserted end-to-end in SerializationTests' LegacyServer_* tests);
        // this pins the fixture itself so the compatibility test can never drift into silently
        // testing a 1.6.0 payload.
        using var doc = JsonDocument.Parse(TestJson.IpRiskLegacyFullyKnown);
        AssertKeysAbsent(doc.RootElement.GetProperty("network"), Schema160NetworkAdditions);
        AssertKeysAbsent(doc.RootElement.GetProperty("location"), Schema160LocationAdditions);
    }

    [Fact]
    public void OriginalRequiredKeys_AreUnchangedBySchema160()
    {
        // The additive revision keeps every pre-1.6.0 required key required, with the same names.
        using var legacy = JsonDocument.Parse(TestJson.IpRiskLegacyFullyKnown);
        AssertKeysPresent(legacy.RootElement, IpRiskResponseRequiredKeys);
        AssertKeysPresent(legacy.RootElement.GetProperty("risk"), LegacyRiskRequiredKeys);
        AssertKeysPresent(legacy.RootElement.GetProperty("network"), LegacyNetworkRequiredKeys);
        AssertKeysPresent(legacy.RootElement.GetProperty("flags"), FlagsRequiredKeys);
        AssertKeysPresent(legacy.RootElement.GetProperty("location"), LegacyLocationRequiredKeys);

        using var current = JsonDocument.Parse(TestJson.IpRiskFullyKnown);
        AssertKeysPresent(current.RootElement.GetProperty("risk"), LegacyRiskRequiredKeys);
        AssertKeysPresent(current.RootElement.GetProperty("network"), LegacyNetworkRequiredKeys);
        AssertKeysPresent(current.RootElement.GetProperty("location"), LegacyLocationRequiredKeys);
    }

    [Fact]
    public void NetworkProfileAndService_AreOptionalKeys_OmittedWhenNoFirstPartyRecord()
    {
        // profile/service are NOT in the contract's required list and are omitted -- never sent as
        // null -- when NetRiskScan holds no record. The SDK reads an omitted key as null.
        using var doc = JsonDocument.Parse(TestJson.IpRiskZeroIndex);
        AssertKeysAbsent(doc.RootElement.GetProperty("network"), ["profile", "service"]);
    }

    [Fact]
    public void LocationKey_IsAlwaysPresent_EvenWhenTheWholeObjectIsNull()
    {
        // Unlike tor/usage (omitted when absent), location is a required top-level key whose value
        // may be null as a whole.
        foreach (var json in new[] { TestJson.IpRiskFullyKnown, TestJson.IpRiskUnknownFlags, TestJson.IpRiskSchema160ReservedAddress })
        {
            using var doc = JsonDocument.Parse(json);
            Assert.True(doc.RootElement.TryGetProperty("location", out _));
        }

        using var reserved = JsonDocument.Parse(TestJson.IpRiskSchema160ReservedAddress);
        Assert.Equal(JsonValueKind.Null, reserved.RootElement.GetProperty("location").ValueKind);
    }

    [Fact]
    public void Schema160ReservedAddress_KeepsRequiredKeys_WithNullValues()
    {
        // An unscoreable address is a normal 200: network keeps all six required keys (domain/range
        // null), risk keeps its keys with index/band null, and location is present-but-null.
        using var doc = JsonDocument.Parse(TestJson.IpRiskSchema160ReservedAddress);
        AssertKeysPresent(doc.RootElement.GetProperty("network"), NetworkRequiredKeys);
        Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("network").GetProperty("domain").ValueKind);
        Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("network").GetProperty("range").ValueKind);
        Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("risk").GetProperty("index").ValueKind);
        Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("risk").GetProperty("band").ValueKind);
    }

    [Fact]
    public void TorFixture_ContainsExactlyTheDocumentedRequiredKeys()
    {
        using var doc = JsonDocument.Parse(TestJson.IpRiskTorExit);
        AssertKeysPresent(doc.RootElement.GetProperty("tor"), TorRelayRequiredKeys);
    }

    [Fact]
    public void UsageFixture_ContainsExactlyTheDocumentedRequiredKeys()
    {
        using var doc = JsonDocument.Parse(TestJson.UsageResponse);
        AssertKeysPresent(doc.RootElement, UsageResponseRequiredKeys);
        AssertKeysPresent(doc.RootElement.GetProperty("period"), ["start", "end"]);
        AssertKeysPresent(doc.RootElement.GetProperty("units"), ["used", "limit", "remaining"]);
        AssertKeysPresent(doc.RootElement.GetProperty("rateLimit"), ["requestsPerMinute"]);
    }

    [Fact]
    public void ErrorFixture_ContainsExactlyTheDocumentedRequiredKeys()
    {
        using var doc = JsonDocument.Parse(TestJson.ErrorEnvelope("invalid_ip", "bad"));
        AssertKeysPresent(doc.RootElement.GetProperty("error"), ErrorEnvelopeRequiredKeys);
    }

    [Theory]
    [MemberData(nameof(DocumentedErrorCodesData))]
    public void EveryDocumentedErrorCode_DeserializesIntoTheEnvelope(string code)
    {
        using var doc = JsonDocument.Parse(TestJson.ErrorEnvelope(code, "message"));
        Assert.Equal(code, doc.RootElement.GetProperty("error").GetProperty("code").GetString());
    }

    public static TheoryData<string> DocumentedErrorCodesData() => new(DocumentedErrorCodes);

    [Fact]
    public void DefaultBaseUrl_MatchesThePublishedServerUrl()
    {
        Assert.Equal("https://api.netriskscan.com", new NetRiskScanOptions().BaseUrl);
    }

    /// <summary>Every key the contract requires must be present -- extra/unknown keys are fine (forward
    /// compatibility, see <see cref="SerializationTests.UnknownJsonFields_AreIgnored_NotAnError"/>), so
    /// this deliberately checks for a subset, not an exact set.</summary>
    private static void AssertKeysPresent(JsonElement element, IEnumerable<string> requiredKeys)
    {
        foreach (var key in requiredKeys)
        {
            Assert.True(element.TryGetProperty(key, out _), $"Expected required key \"{key}\" to be present.");
        }
    }

    private static void AssertKeysAbsent(JsonElement element, IEnumerable<string> keys)
    {
        foreach (var key in keys)
        {
            Assert.False(element.TryGetProperty(key, out _), $"Expected optional key \"{key}\" to be omitted.");
        }
    }
}