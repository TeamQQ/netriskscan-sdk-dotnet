using System.Net;
using System.Text.Json;
using NetRiskScan.Exceptions;

namespace NetRiskScan.Internal;

/// <summary>Builds the right <see cref="NetRiskScanException"/> subclass for a non-2xx HTTP response.</summary>
internal static class ApiErrorParser
{
    public static async Task<NetRiskScanException> ParseAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var status = response.StatusCode;
        var meta = HeaderParser.ParseResponseMetadata(response);

        ApiErrorBody? body = null;
        try
        {
            var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var envelope = await JsonSerializer
                .DeserializeAsync(stream, NetRiskScanJsonContext.Default.ApiErrorEnvelope, cancellationToken)
                .ConfigureAwait(false);
            body = envelope?.Error;
        }
        catch (JsonException)
        {
            // A gateway or proxy can answer with HTML or an empty body; the status code still carries
            // the meaning, so this falls through to a generic message rather than failing to report
            // the original error at all.
        }

        var code = body?.Code;
        var message = body?.Message ?? $"NetRiskScan API request failed with status {(int)status}.";
        var requestId = body?.RequestId ?? meta.RequestId;
        var retryAfter = HeaderParser.ParseRetryAfter(response);

        switch (status)
        {
            case HttpStatusCode.BadRequest:
                return new NetRiskScanValidationException(message, (int)status, code, requestId);

            case HttpStatusCode.Unauthorized:
            case HttpStatusCode.Forbidden:
                return new NetRiskScanAuthenticationException(message, (int)status, code, requestId);

            case HttpStatusCode.NotFound when code == "feature_not_available":
                return new NetRiskScanFeatureNotAvailableException(message, (int)status, code, requestId);

            case HttpStatusCode.NotFound:
                return new NetRiskScanNotFoundException(message, (int)status, code, requestId);

            case (HttpStatusCode)429 when code is "quota_exceeded" or "anonymous_daily_limit_reached":
                return new NetRiskScanQuotaExceededException(
                    message,
                    (int)status,
                    code,
                    requestId,
                    retryAfter,
                    meta.RateLimit,
                    meta.Quota,
                    dailyLimit: body?.DailyLimit,
                    used: body?.Used,
                    remaining: body?.Remaining,
                    resetAt: body?.ResetAt,
                    signupUrl: body?.SignupUrl);

            case (HttpStatusCode)429:
                return new NetRiskScanRateLimitException(message, (int)status, code, requestId, retryAfter, meta.RateLimit);

            default:
                return new NetRiskScanApiException(message, (int)status, code, requestId);
        }
    }
}
