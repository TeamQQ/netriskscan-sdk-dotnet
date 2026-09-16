# Security Policy

## Supported versions

The latest `0.x` release receives security fixes.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security problem.

Report it privately through
[GitHub Security Advisories](https://github.com/TeamQQ/netriskscan-sdk-dotnet/security/advisories/new),
or email <security@netriskscan.com>. Include reproduction steps and the affected version. You can
expect an acknowledgement within a few business days.

## Handling API keys

NetRiskScan API keys are bearer credentials: whoever holds one can spend your quota.

- Keep keys in a secret manager, `dotnet user-secrets`, or an environment variable
  (`NETRISKSCAN_API_KEY`) -- never in `appsettings.json` or source control.
- A key is shown in full exactly once at creation. The server stores only a prefix, the last four
  characters, and a hash, so a lost key can only be revoked and replaced.
- Rotate immediately on suspected exposure; revoke from the developer console.

This SDK never places the key in a URL, and never includes it in an error message, exception message,
or log output. It writes nothing to logs itself; if you enable `HttpClient` logging (for example via
`IHttpClientFactory`'s built-in logging handlers), the `Authorization` header value is not written to
the logs by those handlers either.

## Reporting an API problem

For a vulnerability in the NetRiskScan API itself rather than this client library, use the same
private channels above.
