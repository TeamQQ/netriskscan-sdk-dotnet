namespace NetRiskScan.Tests;

/// <summary>Canned <c>/v1</c> response bodies, shaped exactly like the published OpenAPI contract
/// (<c>Doc/openapi/paid-api-v1.yaml</c> in the main NetRiskScan repository).</summary>
internal static class TestJson
{
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
