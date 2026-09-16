# Changelog

All notable changes to this project are documented in this file.

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
