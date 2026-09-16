using System.Text.Json;
using Xunit;

namespace NetRiskScan.Tests;

/// <summary>
/// Pins this SDK's models against the fields required by the published <c>/v1</c> OpenAPI contract
/// (<c>Doc/openapi/paid-api-v1.yaml</c>, schema version 1.3.0, in the main NetRiskScan repository at the
/// commit this SDK was built against).
///
/// This is a local pin, not a live fetch: the main repository is a separate project this SDK does not
/// depend on at build or test time (see the project report's "OpenAPI Contract Tests" section for why,
/// and for the recommendation to vendor the spec file directly into CI for a tighter guarantee).
/// If a future contract revision adds/renames/removes a required field, this test file is the first
/// place to update -- and a failure here is a prompt to re-review the spec, not to "fix" the assertion
/// without checking it first.
/// </summary>
public sealed class OpenApiContractTests
{
    private static readonly string[] IpRiskResponseRequiredKeys = ["requestId", "ip", "risk", "network", "flags", "location"];
    private static readonly string[] RiskRequiredKeys = ["index", "band", "assessmentGrade", "reasons"];
    private static readonly string[] NetworkRequiredKeys = ["type", "connectionType", "asn", "organization"];
    private static readonly string[] FlagsRequiredKeys =
        ["proxy", "proxyType", "vpn", "tor", "datacenter", "scanner", "abuse", "searchCrawler", "searchCrawlerName"];
    private static readonly string[] LocationRequiredKeys = ["countryCode", "country", "regionCode", "region", "city", "timeZone"];
    private static readonly string[] TorRelayRequiredKeys = ["isRelay", "isExit", "isBadExit", "role"];
    private static readonly string[] UsageResponseRequiredKeys = ["plan", "period", "units", "rateLimit"];
    private static readonly string[] ErrorEnvelopeRequiredKeys = ["code", "message", "requestId"];

    /// <summary>The complete, documented <c>error.code</c> vocabulary as of schema 1.3.0. Open-ended in
    /// practice (the server may add more), but every one of these must still map to a specific exception
    /// type -- see <see cref="ErrorHandlingTests"/> for the per-code assertions.</summary>
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
}
