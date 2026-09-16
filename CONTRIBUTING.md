# Contributing

## Setup

Requires the [.NET SDK](https://dotnet.microsoft.com/download) for `net8.0` and `net10.0` (see
`global.json`).

```bash
dotnet restore
```

## Workflow

```bash
dotnet build -c Release              # build every target framework
dotnet test -c Release               # run the test suite (net8.0 and net10.0)
dotnet format --verify-no-changes    # formatting
dotnet pack -c Release               # build the NuGet package
```

All must pass before a pull request is merged; CI runs the same checks.

## Ground rules

- This SDK is a typed API client, not a risk-scoring engine. Do not add client-side logic that
  recomputes, derives, or overrides `Risk.Index`, `Risk.Band`, or any detection flag -- those values
  come from the server only. See `Doc/openapi/paid-api-v1.yaml` in the main NetRiskScan repository for
  the authoritative `/v1` contract.
- Preserve tri-state semantics (`true` / `false` / `null`) on every detection flag. Never coerce `null`
  to `false`, and never coerce a missing/`null` `Risk.Index` to `0`.
- Unknown JSON fields returned by the API must be ignored, not throw -- this keeps older SDK versions
  working against a server that has added new fields. Do not enable strict/`Disallow` unmapped-member
  handling on `NetRiskScanJsonContext`.
- New response fields go through `System.Text.Json` source generation
  (`Internal/NetRiskScanJsonContext.cs`) with an explicit `[JsonPropertyName]` -- do not switch the
  models to reflection-based serialization.
- Keep behavior consistent with the official JS (`@netriskscan/sdk`) and Python (`netriskscan`) SDKs:
  same authentication precedence, same endpoints, same retry policy, same error-code mapping. Method and
  property naming should still follow .NET conventions (`GetIpRiskAsync`, not `ipRisk`/`ip_risk`).
- Do not read environment variables beyond what's documented (`NETRISKSCAN_API_KEY`).
- No telemetry, analytics, or usage tracking of any kind.

## Releasing

Version is set in `src/NetRiskScan/NetRiskScan.csproj` (`<Version>`). To release: bump it, update
`CHANGELOG.md`, commit, then push a `vX.Y.Z` tag -- `.github/workflows/publish.yml` builds, tests, packs,
and publishes to NuGet.org via Trusted Publishing (OIDC), no stored API key required. Before the very
first release, a maintainer must register this repository/workflow as a trusted publisher for the
`NetRiskScan` package at <https://www.nuget.org/account/trustedpublishing> (one-time manual step).
