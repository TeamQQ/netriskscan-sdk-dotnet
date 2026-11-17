namespace NetRiskScan.Tests;

/// <summary>
/// Canned <c>/v1</c> response bodies, shaped exactly like the published OpenAPI contract
/// (<c>Doc/openapi/paid-api-v1.yaml</c>, schema version 1.6.0, in the main NetRiskScan repository).
///
/// These are mock fixtures, not recorded production answers: they pin the wire shape (key names, JSON
/// types, nullability, key presence/omission), never a business rule about any particular IP. The
/// example addresses' live responses can and do change.
/// </summary>
internal static class TestJson
{
    /// <summary>Schema 1.6.0 shape with every field the contract can carry present and non-null.
    /// Also carries <c>risk.evidence</c> (schema 1.4.0) and <c>risk.signals</c> (schema 1.5.0), which
    /// the published contract requires but this SDK version does not model yet -- they must be ignored
    /// gracefully, exactly like any other unmodeled key.</summary>
    public const string IpRiskFullyKnown = """
        {
          "requestId": "req_8f3ab21c9dab",
          "ip": "8.8.8.8",
          "risk": {
            "index": 95,
            "band": "excellent",
            "assessmentGrade": "complete",
            "reasons": [
              { "code": "VERIFIED_SEARCH_CRAWLER", "category": "identity", "severity": "info" },
              { "code": "PUBLIC_INFRASTRUCTURE", "category": "network", "severity": "info" }
            ],
            "evidence": { "coverage": 87, "confidence": "high", "agreement": "high", "freshnessSeconds": 1080 },
            "signals": {
              "Proxy": "not_detected",
              "Vpn": "not_detected",
              "Tor": "not_detected",
              "Datacenter": "not_detected",
              "Scanner": "not_detected",
              "Abuse": "not_detected",
              "SearchCrawler": "detected"
            }
          },
          "network": {
            "type": "public_infrastructure",
            "profile": "public_dns_resolver",
            "service": "Google Public DNS",
            "connectionType": "direct",
            "asn": "AS15169",
            "organization": "Google LLC",
            "domain": "google.com",
            "range": "8.8.8.0/24"
          },
          "flags": {
            "proxy": false,
            "proxyType": null,
            "vpn": false,
            "tor": false,
            "datacenter": false,
            "scanner": false,
            "abuse": false,
            "searchCrawler": true,
            "searchCrawlerName": "Google"
          },
          "location": {
            "countryCode": "US",
            "country": "United States",
            "regionCode": "CA",
            "region": "California",
            "city": "Mountain View",
            "timeZone": "America/Los_Angeles",
            "continentCode": "NA",
            "continent": "North America",
            "postalCode": "94043",
            "latitude": 37.4056,
            "longitude": -122.0775
          }
        }
        """;

    /// <summary>A pre-1.6.0 server's answer: none of the seven schema-1.6.0 keys is present anywhere.
    /// The SDK must still parse it, with every new property reading as null.</summary>
    public const string IpRiskLegacyFullyKnown = """
        {
          "requestId": "req_8f3ab21c9dab",
          "ip": "8.8.8.8",
          "risk": {
            "index": 95,
            "band": "excellent",
            "assessmentGrade": "complete",
            "reasons": [
              { "code": "VERIFIED_SEARCH_CRAWLER", "category": "identity", "severity": "info" },
              { "code": "PUBLIC_INFRASTRUCTURE", "category": "network", "severity": "info" }
            ]
          },
          "network": {
            "type": "public_infrastructure",
            "profile": "public_dns_resolver",
            "service": "Google Public DNS",
            "connectionType": "direct",
            "asn": "AS15169",
            "organization": "Google LLC"
          },
          "flags": {
            "proxy": false,
            "proxyType": null,
            "vpn": false,
            "tor": false,
            "datacenter": false,
            "scanner": false,
            "abuse": false,
            "searchCrawler": true,
            "searchCrawlerName": "Google"
          },
          "location": {
            "countryCode": "US",
            "country": "United States",
            "regionCode": "CA",
            "region": "California",
            "city": "Mountain View",
            "timeZone": "America/Los_Angeles"
          }
        }
        """;

    /// <summary>Anycast public DNS: the operator domain and containing range are known, but no
    /// verifiable node location exists, so the coordinate pair and postal code are null -- never
    /// filled in with the registration address or a zero.</summary>
    public const string IpRiskSchema160Anycast = """
        {
          "requestId": "req_anycast0000001",
          "ip": "8.8.8.8",
          "risk": { "index": 95, "band": "excellent", "assessmentGrade": "complete", "reasons": [] },
          "network": {
            "type": "public_infrastructure",
            "profile": "public_dns_resolver",
            "service": "Google Public DNS",
            "connectionType": "direct",
            "asn": "AS15169",
            "organization": "Google LLC",
            "domain": "google.com",
            "range": "8.8.8.0/24"
          },
          "flags": {
            "proxy": false, "proxyType": null, "vpn": false, "tor": false, "datacenter": false,
            "scanner": false, "abuse": false, "searchCrawler": null, "searchCrawlerName": null
          },
          "location": {
            "countryCode": "US",
            "country": "United States",
            "regionCode": null,
            "region": null,
            "city": null,
            "timeZone": null,
            "continentCode": "NA",
            "continent": "North America",
            "postalCode": null,
            "latitude": null,
            "longitude": null
          }
        }
        """;

    /// <summary>IPv6 anycast: the containing range is an IPv6 CIDR and must survive verbatim.</summary>
    public const string IpRiskSchema160IPv6 = """
        {
          "requestId": "req_ipv60000000001",
          "ip": "2001:4860:4860::8888",
          "risk": { "index": 95, "band": "excellent", "assessmentGrade": "complete", "reasons": [] },
          "network": {
            "type": "public_infrastructure",
            "profile": "public_dns_resolver",
            "service": "Google Public DNS",
            "connectionType": "direct",
            "asn": "AS15169",
            "organization": "Google LLC",
            "domain": "google.com",
            "range": "2001:4860:4840::/42"
          },
          "flags": {
            "proxy": false, "proxyType": null, "vpn": false, "tor": false, "datacenter": false,
            "scanner": false, "abuse": false, "searchCrawler": null, "searchCrawlerName": null
          },
          "location": {
            "countryCode": "US",
            "country": "United States",
            "regionCode": null,
            "region": null,
            "city": null,
            "timeZone": null,
            "continentCode": "NA",
            "continent": "North America",
            "postalCode": null,
            "latitude": null,
            "longitude": null
          }
        }
        """;

    /// <summary>Partially-known location: country/subdivision/city/postal are known, the rest is null.
    /// The postal code carries leading zeros that must survive as a string.</summary>
    public const string IpRiskSchema160PartialLocation = """
        {
          "requestId": "req_partialgeo0001",
          "ip": "203.0.113.10",
          "risk": { "index": 80, "band": "good", "assessmentGrade": "partial", "reasons": [] },
          "network": {
            "type": "business_access",
            "connectionType": "direct",
            "asn": "AS64500",
            "organization": "Example ISP",
            "domain": null,
            "range": "203.0.113.0/24"
          },
          "flags": {
            "proxy": false, "proxyType": null, "vpn": false, "tor": false, "datacenter": false,
            "scanner": false, "abuse": false, "searchCrawler": false, "searchCrawlerName": null
          },
          "location": {
            "countryCode": "US",
            "country": "United States",
            "regionCode": "NY",
            "region": "New York",
            "city": "Holtsville",
            "timeZone": null,
            "continentCode": null,
            "continent": null,
            "postalCode": "00501",
            "latitude": null,
            "longitude": null
          }
        }
        """;

    /// <summary>Every schema-1.6.0 key present but explicitly null; the original six location fields
    /// keep their values. Explicit null must map to C# null -- never to "" or 0.</summary>
    public const string IpRiskSchema160AllNewFieldsNull = """
        {
          "requestId": "req_allnewnull0001",
          "ip": "198.51.100.23",
          "risk": { "index": 72, "band": "fair", "assessmentGrade": "partial", "reasons": [] },
          "network": {
            "type": "hosting",
            "connectionType": "direct",
            "asn": "AS64501",
            "organization": "Example Hosting",
            "domain": null,
            "range": null
          },
          "flags": {
            "proxy": false, "proxyType": null, "vpn": false, "tor": false, "datacenter": true,
            "scanner": false, "abuse": false, "searchCrawler": false, "searchCrawlerName": null
          },
          "location": {
            "countryCode": "US",
            "country": "United States",
            "regionCode": "CA",
            "region": "California",
            "city": "San Francisco",
            "timeZone": "America/Los_Angeles",
            "continentCode": null,
            "continent": null,
            "postalCode": null,
            "latitude": null,
            "longitude": null
          }
        }
        """;

    /// <summary>A genuine zero coordinate pair: 0/0 is a valid location estimate, not "unknown".</summary>
    public const string IpRiskSchema160ZeroCoordinates = """
        {
          "requestId": "req_zerocoord00001",
          "ip": "192.0.2.55",
          "risk": { "index": 65, "band": "fair", "assessmentGrade": "limited", "reasons": [] },
          "network": {
            "type": "unknown",
            "connectionType": "unknown",
            "asn": null,
            "organization": null,
            "domain": null,
            "range": null
          },
          "flags": {
            "proxy": null, "proxyType": null, "vpn": null, "tor": null, "datacenter": null,
            "scanner": null, "abuse": null, "searchCrawler": null, "searchCrawlerName": null
          },
          "location": {
            "countryCode": null,
            "country": null,
            "regionCode": null,
            "region": null,
            "city": null,
            "timeZone": null,
            "continentCode": null,
            "continent": null,
            "postalCode": null,
            "latitude": 0,
            "longitude": 0
          }
        }
        """;

    /// <summary>A reserved/loopback address on a 1.6.0 server: unscoreable (index/band null, grade
    /// insufficient), network.domain/range present but null, location key present but null.</summary>
    public const string IpRiskSchema160ReservedAddress = """
        {
          "requestId": "req_reserved000001",
          "ip": "127.0.0.1",
          "risk": {
            "index": null,
            "band": null,
            "assessmentGrade": "insufficient",
            "reasons": [
              { "code": "INSUFFICIENT_EVIDENCE", "category": "quality", "severity": "info" }
            ]
          },
          "network": {
            "type": "unknown",
            "connectionType": "unknown",
            "asn": null,
            "organization": null,
            "domain": null,
            "range": null
          },
          "flags": {
            "proxy": null, "proxyType": null, "vpn": null, "tor": null, "datacenter": null,
            "scanner": null, "abuse": null, "searchCrawler": null, "searchCrawlerName": null
          },
          "location": null
        }
        """;

    public const string IpRiskUnknownFlags = """
        {
          "requestId": "req_unknownflags0001",
          "ip": "203.0.113.5",
          "risk": {
            "index": null,
            "band": null,
            "assessmentGrade": "insufficient",
            "reasons": [
              { "code": "INSUFFICIENT_EVIDENCE", "category": "quality", "severity": "info" }
            ]
          },
          "network": {
            "type": "unknown",
            "connectionType": "unknown",
            "asn": null,
            "organization": null
          },
          "flags": {
            "proxy": null,
            "proxyType": null,
            "vpn": null,
            "tor": null,
            "datacenter": null,
            "scanner": null,
            "abuse": null,
            "searchCrawler": null,
            "searchCrawlerName": null
          },
          "location": null
        }
        """;

    public const string IpRiskZeroIndex = """
        {
          "requestId": "req_zeroindex00001",
          "ip": "198.51.100.7",
          "risk": {
            "index": 0,
            "band": "high_risk",
            "assessmentGrade": "complete",
            "reasons": [
              { "code": "BLACKLIST_MATCH", "category": "reputation", "severity": "critical" }
            ]
          },
          "network": {
            "type": "datacenter",
            "connectionType": "proxy",
            "asn": "AS64500",
            "organization": "Example Hosting"
          },
          "flags": {
            "proxy": true,
            "proxyType": "datacenter_proxy",
            "vpn": false,
            "tor": false,
            "datacenter": true,
            "scanner": false,
            "abuse": true,
            "searchCrawler": false,
            "searchCrawlerName": null
          },
          "location": null
        }
        """;

    public const string IpRiskTorExit = """
        {
          "requestId": "req_torexit0000001",
          "ip": "51.15.0.1",
          "risk": {
            "index": 30,
            "band": "high_risk",
            "assessmentGrade": "complete",
            "reasons": [
              { "code": "TOR_EXIT_NODE", "category": "anonymity", "severity": "high" }
            ]
          },
          "network": {
            "type": "datacenter",
            "connectionType": "tor",
            "asn": "AS12876",
            "organization": "Online SAS"
          },
          "flags": {
            "proxy": false,
            "proxyType": null,
            "vpn": false,
            "tor": true,
            "datacenter": true,
            "scanner": false,
            "abuse": false,
            "searchCrawler": false,
            "searchCrawlerName": null
          },
          "location": null,
          "tor": { "isRelay": true, "isExit": true, "isBadExit": false, "role": "exit" }
        }
        """;

    public const string IpRiskAnonymousWithUsage = """
        {
          "requestId": "req_anon00000000001",
          "ip": "8.8.8.8",
          "risk": { "index": 95, "band": "excellent", "assessmentGrade": "complete", "reasons": [] },
          "network": { "type": "public_infrastructure", "connectionType": "direct", "asn": "AS15169", "organization": "Google LLC" },
          "flags": {
            "proxy": false, "proxyType": null, "vpn": false, "tor": false, "datacenter": false,
            "scanner": false, "abuse": false, "searchCrawler": null, "searchCrawlerName": null
          },
          "location": null,
          "usage": { "mode": "anonymous", "dailyLimit": 30, "used": 1, "remaining": 29, "resetAt": "2026-08-29T00:00:00Z" }
        }
        """;

    public const string IpRiskWithUnknownField = """
        {
          "requestId": "req_unknownfield001",
          "ip": "8.8.8.8",
          "risk": { "index": 95, "band": "excellent", "assessmentGrade": "complete", "reasons": [], "newField": "should be ignored" },
          "network": { "type": "public_infrastructure", "connectionType": "direct", "asn": "AS15169", "organization": "Google LLC", "somethingNew": 42 },
          "flags": {
            "proxy": false, "proxyType": null, "vpn": false, "tor": false, "datacenter": false,
            "scanner": false, "abuse": false, "searchCrawler": null, "searchCrawlerName": null
          },
          "location": null,
          "futureTopLevelField": { "anything": true }
        }
        """;

    public const string UsageResponse = """
        {
          "plan": "growth",
          "period": { "start": "2026-08-01T00:00:00Z", "end": "2026-09-01T00:00:00Z" },
          "units": { "used": 1200, "limit": 10000, "remaining": 8800 },
          "rateLimit": { "requestsPerMinute": 60 }
        }
        """;

    public static string ErrorEnvelope(string code, string message, string requestId = "req_error0000001") =>
        $$"""
        { "error": { "code": "{{code}}", "message": "{{message}}", "requestId": "{{requestId}}" } }
        """;

    public static string AnonymousLimitErrorEnvelope(long dailyLimit, long used, long remaining, string resetAt, string signupUrl) =>
        $$"""
        {
          "error": {
            "code": "anonymous_daily_limit_reached",
            "message": "Anonymous daily limit reached.",
            "requestId": "req_anonlimit00001",
            "dailyLimit": {{dailyLimit}},
            "used": {{used}},
            "remaining": {{remaining}},
            "resetAt": "{{resetAt}}",
            "signupUrl": "{{signupUrl}}"
          }
        }
        """;
}
