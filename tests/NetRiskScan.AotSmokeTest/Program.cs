using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetRiskScan;
using NetRiskScan.Models;

// Native AOT smoke test for the NetRiskScan SDK's schema 1.6.0 support.
//
// Published as a native binary by the CI "aot" job (dotnet publish -r linux-x64) and executed there:
// a regular managed build cannot prove the source-generated JSON metadata survives trimming/AOT, so
// this exercises the real client deserialization path (the SDK's internal NetRiskScanJsonContext) and
// source-generated serialization of the models at runtime, reflection-free.
//
// Deserialization goes through NetRiskScanClient against a canned transport; serialization uses a
// local source-generated context over the same public models (the SDK's own context is internal).
// Fixtures are mock wire shapes, not production answers.

var handler = new CannedRiskHandler();
using var httpClient = new HttpClient(handler);
using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions());

// 1. All seven schema-1.6.0 fields present: deserialized through the SDK's real source-gen context.
var full = await client.GetIpRiskAsync("142.250.190.78");
Check(full.Network.Domain == "google.com", "network.domain");
Check(full.Network.Range == "142.250.190.64/26", "network.range");
Check(full.Location!.ContinentCode == "NA", "location.continentCode");
Check(full.Location.Continent == "North America", "location.continent");
Check(full.Location.PostalCode == "60666", "location.postalCode");
Check(full.Location.Latitude == 41.8781d, "location.latitude");
Check(full.Location.Longitude == -87.6298d, "location.longitude");
Check(full.Risk.Index == 95, "risk.index unchanged");

// 2. Anycast: the null coordinate pair stays null -- never completed, never coerced to zero.
var anycast = await client.GetIpRiskAsync("8.8.8.8");
Check(anycast.Network.Domain == "google.com", "anycast network.domain");
Check(anycast.Network.Range == "8.8.8.0/24", "anycast network.range");
Check(anycast.Location!.Latitude is null, "anycast latitude null");
Check(anycast.Location.Longitude is null, "anycast longitude null");
Check(anycast.Location.PostalCode is null, "anycast postalCode null");

// 3. A genuine zero coordinate pair is a value, not "unknown".
var zero = await client.GetIpRiskAsync("192.0.2.55");
Check(zero.Location!.Latitude is 0d, "zero latitude preserved");
Check(zero.Location.Longitude is 0d, "zero longitude preserved");

// 4. Source-generated serialization of the models under AOT: names, numeric coordinates, nulls.
var fullJson = JsonSerializer.Serialize(full, SmokeJsonContext.Default.IpRiskResult);
Check(fullJson.Contains("\"domain\":\"google.com\"", StringComparison.Ordinal), "serialized domain name");
Check(fullJson.Contains("\"range\":\"142.250.190.64/26\"", StringComparison.Ordinal), "serialized range name");
Check(fullJson.Contains("\"continentCode\":\"NA\"", StringComparison.Ordinal), "serialized continentCode name");
Check(fullJson.Contains("\"postalCode\":\"60666\"", StringComparison.Ordinal), "serialized postalCode name");
Check(fullJson.Contains("\"latitude\":41.8781", StringComparison.Ordinal), "serialized latitude is a number");
Check(fullJson.Contains("\"longitude\":-87.6298", StringComparison.Ordinal), "serialized longitude is a number");

var anycastJson = JsonSerializer.Serialize(anycast, SmokeJsonContext.Default.IpRiskResult);
Check(anycastJson.Contains("\"latitude\":null", StringComparison.Ordinal), "serialized null latitude stays null");
Check(anycastJson.Contains("\"longitude\":null", StringComparison.Ordinal), "serialized null longitude stays null");

var roundTripped = JsonSerializer.Deserialize(fullJson, SmokeJsonContext.Default.IpRiskResult);
Check(roundTripped!.Network.Domain == "google.com", "round-trip domain");
Check(roundTripped.Network.Range == "142.250.190.64/26", "round-trip range");
Check(roundTripped.Location!.ContinentCode == "NA", "round-trip continentCode");
Check(roundTripped.Location.Continent == "North America", "round-trip continent");
Check(roundTripped.Location.PostalCode == "60666", "round-trip postalCode");
Check(roundTripped.Location.Latitude == 41.8781d, "round-trip latitude");
Check(roundTripped.Location.Longitude == -87.6298d, "round-trip longitude");

Console.WriteLine("NetRiskScan AOT smoke test passed (schema 1.6.0 fields, null/zero semantics, source-gen round-trip).");
return 0;

static void Check(bool condition, string what)
{
    if (!condition)
    {
        throw new InvalidOperationException($"AOT smoke check failed: {what}");
    }
}

internal sealed class CannedRiskHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var json = request.RequestUri!.AbsolutePath switch
        {
            "/v1/ip-risk/142.250.190.78" => FullJson,
            "/v1/ip-risk/8.8.8.8" => AnycastJson,
            "/v1/ip-risk/192.0.2.55" => ZeroCoordinatesJson,
            _ => null,
        };

        var response = json is null
            ? new HttpResponseMessage(HttpStatusCode.NotFound)
            : new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
        return Task.FromResult(response);
    }

    private const string FullJson = """
        {
          "requestId": "req_aotsmoke000001",
          "ip": "142.250.190.78",
          "risk": { "index": 95, "band": "excellent", "assessmentGrade": "complete", "reasons": [] },
          "network": {
            "type": "public_infrastructure", "connectionType": "direct", "asn": "AS15169",
            "organization": "Google LLC", "domain": "google.com", "range": "142.250.190.64/26"
          },
          "flags": {
            "proxy": false, "proxyType": null, "vpn": false, "tor": false, "datacenter": false,
            "scanner": false, "abuse": false, "searchCrawler": null, "searchCrawlerName": null
          },
          "location": {
            "countryCode": "US", "country": "United States", "regionCode": "IL", "region": "Illinois",
            "city": "Chicago", "timeZone": "America/Chicago", "continentCode": "NA",
            "continent": "North America", "postalCode": "60666", "latitude": 41.8781, "longitude": -87.6298
          }
        }
        """;

    private const string AnycastJson = """
        {
          "requestId": "req_aotsmoke000002",
          "ip": "8.8.8.8",
          "risk": { "index": 95, "band": "excellent", "assessmentGrade": "complete", "reasons": [] },
          "network": {
            "type": "public_infrastructure", "profile": "public_dns_resolver", "service": "Google Public DNS",
            "connectionType": "direct", "asn": "AS15169", "organization": "Google LLC",
            "domain": "google.com", "range": "8.8.8.0/24"
          },
          "flags": {
            "proxy": false, "proxyType": null, "vpn": false, "tor": false, "datacenter": false,
            "scanner": false, "abuse": false, "searchCrawler": null, "searchCrawlerName": null
          },
          "location": {
            "countryCode": "US", "country": "United States", "regionCode": null, "region": null,
            "city": null, "timeZone": null, "continentCode": "NA", "continent": "North America",
            "postalCode": null, "latitude": null, "longitude": null
          }
        }
        """;

    private const string ZeroCoordinatesJson = """
        {
          "requestId": "req_aotsmoke000003",
          "ip": "192.0.2.55",
          "risk": { "index": 65, "band": "fair", "assessmentGrade": "limited", "reasons": [] },
          "network": {
            "type": "unknown", "connectionType": "unknown", "asn": null, "organization": null,
            "domain": null, "range": null
          },
          "flags": {
            "proxy": null, "proxyType": null, "vpn": null, "tor": null, "datacenter": null,
            "scanner": null, "abuse": null, "searchCrawler": null, "searchCrawlerName": null
          },
          "location": {
            "countryCode": null, "country": null, "regionCode": null, "region": null, "city": null,
            "timeZone": null, "continentCode": null, "continent": null, "postalCode": null,
            "latitude": 0, "longitude": 0
          }
        }
        """;
}

/// <summary>Local source-generated context over the SDK's public models: proves the schema 1.6.0
/// properties serialize reflection-free under Native AOT. (The SDK's own context is internal; the
/// client deserialization path above exercises it directly.)</summary>
[JsonSerializable(typeof(IpRiskResult))]
internal sealed partial class SmokeJsonContext : JsonSerializerContext
{
}