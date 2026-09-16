using System.Globalization;
using System.Net.Http.Headers;
using NetRiskScan.Models;

namespace NetRiskScan.Internal;

/// <summary>Parses the response headers documented in the <c>/v1</c> OpenAPI contract.</summary>
internal static class HeaderParser
{
    public static ResponseMetadata ParseResponseMetadata(HttpResponseMessage response)
    {
        var headers = response.Headers;
        return new ResponseMetadata
        {
            StatusCode = (int)response.StatusCode,
            RequestId = GetString(headers, "X-Request-Id"),
            ScoringVersion = GetString(headers, "X-NetRiskScan-Scoring-Version"),
            RateLimit = new RateLimitInfo
            {
                Limit = GetInt32(headers, "X-RateLimit-Limit"),
                Remaining = GetInt32(headers, "X-RateLimit-Remaining"),
                Reset = GetInt64(headers, "X-RateLimit-Reset"),
            },
            Quota = new QuotaInfo
            {
                Limit = GetInt64(headers, "X-Quota-Limit"),
                Used = GetInt64(headers, "X-Quota-Used"),
                Remaining = GetInt64(headers, "X-Quota-Remaining"),
            },
        };
    }

    /// <summary>
    /// Parses <c>Retry-After</c> as delta-seconds only -- the API always sends an integer number of
    /// seconds for this header. The HTTP-date form is not produced by this API and is deliberately not
    /// guessed at.
    /// </summary>
    public static TimeSpan? ParseRetryAfter(HttpResponseMessage response)
    {
        var value = response.Headers.RetryAfter;
        if (value?.Delta is { } delta)
        {
            return delta;
        }

        // Some proxies/gateways surface Retry-After as a plain header HttpResponseHeaders.RetryAfter
        // fails to parse into a RetryConditionHeaderValue; fall back to a manual integer parse.
        if (response.Headers.TryGetValues("Retry-After", out var raw))
        {
            var text = raw.FirstOrDefault();
            if (text is not null && int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) && seconds >= 0)
            {
                return TimeSpan.FromSeconds(seconds);
            }
        }

        return null;
    }

    private static string? GetString(HttpResponseHeaders headers, string name) =>
        headers.TryGetValues(name, out var values) ? values.FirstOrDefault() : null;

    private static int? GetInt32(HttpResponseHeaders headers, string name)
    {
        var raw = GetString(headers, name);
        return raw is not null && int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;
    }

    private static long? GetInt64(HttpResponseHeaders headers, string name)
    {
        var raw = GetString(headers, name);
        return raw is not null && long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;
    }
}
