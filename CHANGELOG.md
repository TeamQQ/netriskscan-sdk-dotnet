# Changelog

All notable changes to this project are documented in this file.

## [0.2.0] - Unreleased

Compatibility feature release: full support for API schema **1.6.0** (`ip-intelligence-completeness-v1`).
Purely additive -- no endpoint, authentication, retry, error-handling, or scoring behavior changes.

- `NetworkInfo.Domain` (`string?`, JSON `domain`) -- the network operator's verified registrable
  primary domain (not a hosted website, cloud customer domain, or reverse-DNS hostname). `null` when
  no trustworthy mapping exists.
- `NetworkInfo.Range` (`string?`, JSON `range`) -- canonical IPv4/IPv6 CIDR containing the queried
  address. `null` when no trustworthy containing prefix is available.
- `LocationInfo.ContinentCode` / `LocationInfo.Continent` (`string?`, JSON `continentCode` /
  `continent`) -- UN geoscheme continent code and English continent name.
- `LocationInfo.PostalCode` (`string?`, JSON `postalCode`) -- postal code as the source reports it;
  kept as a string so leading zeros survive.
- `LocationInfo.Latitude` / `LocationInfo.Longitude` (`double?`, JSON `latitude` / `longitude`) --
  approximate network coordinates (not device GPS), published as a pair. `null` means unknown
  (e.g. anycast); a genuine `0` is preserved and never conflated with `null`.
- All seven properties are nullable and optional at the wire level for backward compatibility: an
  older server that omits the keys still parses, with the new properties reading as `null`. The SDK
  never derives, completes, or coerces any of these values client-side.
- OpenAPI contract tests re-pinned to schema 1.6.0, distinguishing required keys, nullable values,
  and optional (omitted) keys. Note: the published 1.6.0 contract also requires `risk.evidence`
  (schema 1.4.0) and `risk.signals` (schema 1.5.0); this SDK version ignores them gracefully and does
  not model them yet -- tracked as follow-up work.
- Added a Native AOT smoke test (`tests/NetRiskScan.AotSmokeTest`) published and executed as a native
  binary in CI, validating source-generated JSON (de)serialization of the new fields at runtime.

## [0.1.0] - 2026-09-16

Initial release.

- `NetRiskScanClient` (implementing `INetRiskScanClient`) for `GET /v1/ip-risk/{ip}` and `GET /v1/usage`.
- Anonymous access (no API key) and API key authentication via `NETRISKSCAN_API_KEY` or an explicit option.
- `AddNetRiskScan()` ASP.NET Core dependency injection integration, wired through `IHttpClientFactory`.
- Typed, immutable record models preserving tri-state (`true`/`false`/`null`) detection flags and the
  `int?` risk index (never coerced to `0`).
- Full exception hierarchy (`NetRiskScanException` and nine subclasses) mapped to the documented `/v1`
  error codes.
- Automatic retry with backoff and `Retry-After` support for `429`/`502`/`503`/`504`.
- Rate limit and quota metadata via `IpRiskResult.Meta` / `UsageResult.Meta`.
- `CancellationToken` on every async method.
- Targets `net8.0` and `net10.0`; source-generated JSON (de)serialization for Native AOT / trimming
  compatibility.
