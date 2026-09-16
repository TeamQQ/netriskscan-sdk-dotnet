using System.Text.Json.Serialization;

namespace NetRiskScan.Models;

/// <summary>
/// The full response of <c>GET /v1/ip-risk/{ip}</c>.
///
/// This is a plain, immutable projection of what the server returned -- the SDK never recomputes
/// <see cref="RiskInfo.Index"/>/<see cref="RiskInfo.Band"/> or derives a detection flag from another
/// field. See the "Null is not false" section of the README for the tri-state semantics every
/// <c>bool?</c> field in <see cref="Flags"/> carries.
/// </summary>
public sealed record IpRiskResult
{
    /// <summary>Trace ID for this request, <c>req_…</c>. Quote it in a support request.</summary>
    [JsonPropertyName("requestId")]
    public required string RequestId { get; init; }

    /// <summary>
    /// The queried address in its canonical form -- the server's parse of it, not a verbatim echo of
    /// the input. <c>2001:0DB8::0001</c> returns as <c>2001:db8::1</c>; an IPv4-mapped address stays
    /// IPv6 (<c>::ffff:8.8.8.8</c> is not collapsed to <c>8.8.8.8</c>). Use this value, not the input
    /// you passed, to match a response back to its request when batching.
    /// </summary>
    [JsonPropertyName("ip")]
    public required string Ip { get; init; }

    /// <summary>The risk verdict: index, band, assessment grade, and the reasons behind them.</summary>
    [JsonPropertyName("risk")]
    public required RiskInfo Risk { get; init; }

    /// <summary>Network classification: type, ASN, organization, connection type.</summary>
    [JsonPropertyName("network")]
    public required NetworkInfo Network { get; init; }

    /// <summary>The nine tri-state detection flags (proxy, VPN, Tor, datacenter, scanner, abuse,
    /// search-crawler identity, plus the two subordinate descriptor fields).</summary>
    [JsonPropertyName("flags")]
    public required FlagsInfo Flags { get; init; }

    /// <summary>
    /// Network-level geolocation of the address -- not device GPS. Always present as a key in the JSON
    /// response; <see langword="null"/> when nothing is known about where this network is.
    /// </summary>
    [JsonPropertyName("location")]
    public LocationInfo? Location { get; init; }

    /// <summary>
    /// Tor Project relay detail. Present only when the address is an actual Tor relay and the Tor
    /// Project consensus answered; <see langword="null"/> for every other address.
    /// </summary>
    [JsonPropertyName("tor")]
    public TorInfo? Tor { get; init; }

    /// <summary>
    /// The anonymous daily trial allowance, as of and including this request. Present only when the
    /// call was made without an API key; <see langword="null"/> for an authenticated call, whose
    /// entitlement is reported by <see cref="NetRiskScanClient.GetUsageAsync"/> and
    /// <see cref="Meta"/> instead.
    /// </summary>
    [JsonPropertyName("usage")]
    public AnonymousUsage? Usage { get; init; }

    /// <summary>
    /// Rate-limit/quota headers and the request id for the HTTP response this result was parsed from.
    /// Populated by <see cref="NetRiskScanClient"/>; never present on a value you construct yourself.
    /// </summary>
    [JsonIgnore]
    public ResponseMetadata? Meta { get; internal set; }
}

/// <summary>
/// The published risk verdict.
///
/// <see cref="Index"/> and <see cref="Band"/> are a matched pair: both are non-null together, or both
/// are <see langword="null"/> together when the address cannot be scored at all (a private, loopback,
/// or otherwise special-purpose address), in which case <see cref="AssessmentGrade"/> is
/// <c>"insufficient"</c>. That is a normal, successful (HTTP 200) response -- not an error.
/// </summary>
public sealed record RiskInfo
{
    /// <summary>
    /// The NetRiskScan Index, 0-100. <b>Higher means cleaner</b> -- this is a cleanliness score, not a
    /// threat score. <see langword="null"/> when the address cannot be scored; never coerce a null
    /// index to <c>0</c>, which is a real, valid, very-high-risk score.
    /// </summary>
    [JsonPropertyName("index")]
    public int? Index { get; init; }

    /// <summary>
    /// Server-side classification of <see cref="Index"/>: <c>excellent</c>, <c>good</c>, <c>fair</c>,
    /// <c>poor</c>, <c>high_risk</c>, or <c>unknown</c>. Treat the value set as open -- render an
    /// unrecognized value rather than rejecting it.
    /// </summary>
    [JsonPropertyName("band")]
    public string? Band { get; init; }

    /// <summary>
    /// Evidence completeness behind this assessment: <c>complete</c>, <c>partial</c>, <c>limited</c>,
    /// or <c>insufficient</c>. Always present, independent of <see cref="Band"/>. Open value set.
    /// </summary>
    [JsonPropertyName("assessmentGrade")]
    public required string AssessmentGrade { get; init; }

    /// <summary>
    /// Why the address scores the way it does. Always present; empty when nothing fired, never
    /// <see langword="null"/>. Ordered severity-descending, then by code, so a given result always
    /// serializes identically. These are explanations of observed network characteristics, not
    /// accusations -- see the README for the full code vocabulary.
    /// </summary>
    [JsonPropertyName("reasons")]
    public IReadOnlyList<RiskReason> Reasons { get; init; } = [];
}

/// <summary>One published reason behind a risk assessment.</summary>
public sealed record RiskReason
{
    /// <summary>
    /// What was observed, e.g. <c>VERIFIED_SEARCH_CRAWLER</c>, <c>VPN_DETECTED</c>,
    /// <c>TOR_EXIT_NODE</c>. Treat this as an open value set: new codes are added as intelligence
    /// improves, without a new API version.
    /// </summary>
    [JsonPropertyName("code")]
    public required string Code { get; init; }

    /// <summary>Which axis the observation belongs to: <c>network</c>, <c>anonymity</c>,
    /// <c>reputation</c>, <c>threat</c>, <c>identity</c>, or <c>quality</c>.</summary>
    [JsonPropertyName("category")]
    public required string Category { get; init; }

    /// <summary>How much weight the observation deserves: <c>info</c>, <c>low</c>, <c>medium</c>,
    /// <c>high</c>, or <c>critical</c>. Not a recommendation about what to do with it.</summary>
    [JsonPropertyName("severity")]
    public required string Severity { get; init; }
}

/// <summary>Network classification for the queried address.</summary>
public sealed record NetworkInfo
{
    /// <summary>
    /// Published network classification: <c>residential</c>, <c>mobile</c>, <c>business_access</c>,
    /// <c>education</c>, <c>hosting</c>, <c>datacenter</c>, <c>public_infrastructure</c>, or
    /// <c>unknown</c>. <c>unknown</c> is a legitimate answer, not an error. Open value set.
    /// </summary>
    [JsonPropertyName("type")]
    public string? Type { get; init; }

    /// <summary>
    /// What the network is for -- <c>public_dns_resolver</c>, <c>cdn_edge</c>, <c>search_crawler</c>,
    /// and so on. <see langword="null"/> both when the server omits the key (no first-party record)
    /// and when it sends an explicit null; both mean the same thing. Open value set.
    /// </summary>
    [JsonPropertyName("profile")]
    public string? Profile { get; init; }

    /// <summary>
    /// The specific service, e.g. <c>Googlebot</c>, <c>Google Public DNS</c>. Display text, not an
    /// identifier -- branch on <see cref="Profile"/> instead. Present only on a first-party match.
    /// </summary>
    [JsonPropertyName("service")]
    public string? Service { get; init; }

    /// <summary>How the address connects: <c>direct</c>, <c>vpn</c>, <c>proxy</c>,
    /// <c>residential_proxy</c>, <c>tor</c>, <c>relay</c>, <c>unknown</c>. Open value set.</summary>
    [JsonPropertyName("connectionType")]
    public string? ConnectionType { get; init; }

    /// <summary>Autonomous system number, e.g. <c>AS15169</c>.</summary>
    [JsonPropertyName("asn")]
    public string? Asn { get; init; }

    /// <summary>Canonical operator of the network or ASN, e.g. <c>Google LLC</c>.</summary>
    [JsonPropertyName("organization")]
    public string? Organization { get; init; }
}

/// <summary>
/// Seven independent tri-state detection facts, plus two subordinate descriptor fields.
///
/// Every <c>bool?</c> here means the same three things: <see langword="true"/> = detected,
/// <see langword="false"/> = checked and confirmed not detected, <see langword="null"/> = unknown, or
/// not supported by any source this round used. <b><c>null</c> is not <c>false</c></b> -- collapsing it
/// turns an unanswered question into a finding. None of these fields is a projection of
/// <see cref="NetworkInfo.Type"/>: <c>type = public_infrastructure</c> implies nothing about
/// <see cref="Datacenter"/>, because a public DNS resolver is routinely public infrastructure and not a
/// datacenter.
/// </summary>
public sealed record FlagsInfo
{
    /// <summary>Whether this address is a confirmed proxy.</summary>
    [JsonPropertyName("proxy")]
    public bool? Proxy { get; init; }

    /// <summary>
    /// What kind of proxy infrastructure this is: <c>residential_proxy</c>, <c>isp_proxy</c>,
    /// <c>mobile_proxy</c>, <c>datacenter_proxy</c>, or <c>unknown_proxy</c>. <b>Non-null exactly when
    /// <see cref="Proxy"/> is <see langword="true"/></b> -- a confirmed proxy never publishes
    /// <see langword="null"/> here, even when the subtype is unresolved (<c>unknown_proxy</c>).
    /// </summary>
    [JsonPropertyName("proxyType")]
    public string? ProxyType { get; init; }

    /// <summary>Whether this address is a confirmed VPN endpoint.</summary>
    [JsonPropertyName("vpn")]
    public bool? Vpn { get; init; }

    /// <summary>
    /// A confirmed Tor <b>exit</b> node -- not "is a Tor node": a Middle or Guard relay is part of Tor
    /// but has no exit capability, and publishes <see langword="false"/> here. See
    /// <see cref="IpRiskResult.Tor"/> for the richer relay/exit/BadExit detail, published separately.
    /// </summary>
    [JsonPropertyName("tor")]
    public bool? Tor { get; init; }

    /// <summary>
    /// Never a projection of <see cref="NetworkInfo.Type"/>: <c>type = public_infrastructure</c>
    /// implies nothing here (a public DNS resolver is routinely public infrastructure and not a
    /// datacenter).
    /// </summary>
    [JsonPropertyName("datacenter")]
    public bool? Datacenter { get; init; }

    /// <summary>
    /// Internet-scanning, crawling, or bot activity actually observed. An address correctly identified
    /// as an official search crawler (<see cref="SearchCrawler"/>) does not make this
    /// <see langword="true"/> by itself: identity and behavior are independent questions.
    /// </summary>
    [JsonPropertyName("scanner")]
    public bool? Scanner { get; init; }

    /// <summary>Standing abuse reputation -- abuse history or blacklist presence.</summary>
    [JsonPropertyName("abuse")]
    public bool? Abuse { get; init; }

    /// <summary>
    /// Whether this address is verified search-engine crawler infrastructure -- identity, not behavior,
    /// and not a whitelist: a crawler address that is also a confirmed proxy, scanner, or abuse source
    /// publishes all of those unchanged. Narrower than "crawler": AI training/assistant crawlers
    /// (GPTBot, ChatGPT-User) and SEO crawlers are <see langword="false"/> here even though they remain
    /// visible via <see cref="NetworkInfo.Profile"/>/<see cref="NetworkInfo.Service"/>.
    /// </summary>
    [JsonPropertyName("searchCrawler")]
    public bool? SearchCrawler { get; init; }

    /// <summary>
    /// The canonical search operator, e.g. <c>Google</c>, <c>Bing</c>, <c>Apple</c> -- the operator, not
    /// the fetcher (see <see cref="NetworkInfo.Service"/> for the fetcher name).
    /// <b>Non-null exactly when <see cref="SearchCrawler"/> is <see langword="true"/></b>. Deliberately
    /// an open string, not a closed enum: new search engines are onboarded without a new API version.
    /// </summary>
    [JsonPropertyName("searchCrawlerName")]
    public string? SearchCrawlerName { get; init; }
}

/// <summary>
/// Network-level IP geolocation -- not GPS, and not device location. Every member is nullable, and a
/// <see langword="null"/> means "not known"; an unknown city is never <c>"Unknown"</c> or a placeholder.
/// Independent of <see cref="NetworkInfo.Profile"/>: Googlebot's identity is a crawler, and its location
/// is still United States / California / Mountain View.
/// </summary>
public sealed record LocationInfo
{
    /// <summary>ISO 3166-1 alpha-2 country code, e.g. <c>US</c>.</summary>
    [JsonPropertyName("countryCode")]
    public string? CountryCode { get; init; }

    /// <summary>English country name, e.g. <c>United States</c>.</summary>
    [JsonPropertyName("country")]
    public string? Country { get; init; }

    /// <summary>Subdivision code as the source reports it, e.g. <c>CA</c>. Open value set.</summary>
    [JsonPropertyName("regionCode")]
    public string? RegionCode { get; init; }

    /// <summary>Subdivision name, e.g. <c>California</c>.</summary>
    [JsonPropertyName("region")]
    public string? Region { get; init; }

    /// <summary>City name, e.g. <c>Mountain View</c>.</summary>
    [JsonPropertyName("city")]
    public string? City { get; init; }

    /// <summary>IANA time-zone name, e.g. <c>America/Los_Angeles</c>.</summary>
    [JsonPropertyName("timeZone")]
    public string? TimeZone { get; init; }
}

/// <summary>
/// What the Tor Project relay consensus says about this address. Present on
/// <see cref="IpRiskResult.Tor"/> only when the address is an actual Tor relay.
/// </summary>
public sealed record TorInfo
{
    /// <summary>Participates in the Tor network -- Middle, Guard, or Exit. Always
    /// <see langword="true"/> when this object is present.</summary>
    [JsonPropertyName("isRelay")]
    public required bool IsRelay { get; init; }

    /// <summary>
    /// A confirmed exit: the consensus grants the Exit role and the exit policy permits at least one
    /// destination port. The same fact as <see cref="FlagsInfo.Tor"/>.
    /// </summary>
    [JsonPropertyName("isExit")]
    public required bool IsExit { get; init; }

    /// <summary>The directory authorities flagged this relay <c>BadExit</c>. Independent of
    /// <see cref="IsExit"/> -- a BadExit is still an exit, just one the Tor network distrusts.</summary>
    [JsonPropertyName("isBadExit")]
    public required bool IsBadExit { get; init; }

    /// <summary>The relay's role: <c>middle</c>, <c>guard</c>, or <c>exit</c>.</summary>
    [JsonPropertyName("role")]
    public required string Role { get; init; }
}

/// <summary>The anonymous daily trial allowance. Present only on an anonymous (no API key) call.</summary>
public sealed record AnonymousUsage
{
    /// <summary>Always <c>"anonymous"</c> today -- a discriminator for the access mode.</summary>
    [JsonPropertyName("mode")]
    public required string Mode { get; init; }

    /// <summary>The daily allowance configured by the server. The SDK never hardcodes this number --
    /// read it from the response.</summary>
    [JsonPropertyName("dailyLimit")]
    public required long DailyLimit { get; init; }

    /// <summary>How many anonymous requests have been used today, counting this one.</summary>
    [JsonPropertyName("used")]
    public required long Used { get; init; }

    /// <summary>How many anonymous requests remain today.</summary>
    [JsonPropertyName("remaining")]
    public required long Remaining { get; init; }

    /// <summary>The next UTC midnight, as an ISO-8601 string, e.g. <c>2026-08-29T00:00:00Z</c>.</summary>
    [JsonPropertyName("resetAt")]
    public required string ResetAt { get; init; }
}
