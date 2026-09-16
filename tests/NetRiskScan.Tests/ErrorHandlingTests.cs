using System.Net;
using NetRiskScan.Exceptions;
using Xunit;

namespace NetRiskScan.Tests;

/// <summary>Every documented <c>/v1</c> error code maps to the exception type described in the README
/// "Error handling" section, and every exception carries the server's code/message/requestId.</summary>
public sealed class ErrorHandlingTests
{
    private static NetRiskScanClient MakeClient(HttpResponseMessage response, out FakeHttpMessageHandler handler, NetRiskScanOptions? options = null)
    {
        handler = FakeHttpMessageHandler.Single(response);
        var httpClient = new HttpClient(handler);
        return new NetRiskScanClient(httpClient, options ?? new NetRiskScanOptions { MaxRetries = 0 });
    }

    [Fact]
    public async Task Status400_InvalidIp_ThrowsValidationException()
    {
        var response = FakeHttpMessageHandler.JsonResponse(HttpStatusCode.BadRequest, TestJson.ErrorEnvelope("invalid_ip", "The IP address is invalid."));
        using var client = MakeClient(response, out _);

        var ex = await Assert.ThrowsAsync<NetRiskScanValidationException>(() => client.GetIpRiskAsync("not-an-ip"));

        Assert.Equal(400, ex.StatusCode);
        Assert.Equal("invalid_ip", ex.Code);
        Assert.Equal("req_error0000001", ex.RequestId);
        Assert.Equal("The IP address is invalid.", ex.Message);
    }

    [Fact]
    public async Task Status401_InvalidApiKey_ThrowsAuthenticationException()
    {
        var response = FakeHttpMessageHandler.JsonResponse(HttpStatusCode.Unauthorized, TestJson.ErrorEnvelope("invalid_api_key", "Invalid or missing API key."));
        using var client = MakeClient(response, out _);

        var ex = await Assert.ThrowsAsync<NetRiskScanAuthenticationException>(() => client.GetIpRiskAsync("8.8.8.8"));

        Assert.Equal(401, ex.StatusCode);
        Assert.Equal("invalid_api_key", ex.Code);
    }

    [Fact]
    public async Task Status403_ApiKeyDisabled_ThrowsAuthenticationException()
    {
        var response = FakeHttpMessageHandler.JsonResponse(HttpStatusCode.Forbidden, TestJson.ErrorEnvelope("api_key_disabled", "API key is disabled."));
        using var client = MakeClient(response, out _, new NetRiskScanOptions { ApiKey = "nrs_live_disabled", MaxRetries = 0 });

        var ex = await Assert.ThrowsAsync<NetRiskScanAuthenticationException>(() => client.GetIpRiskAsync("8.8.8.8"));

        Assert.Equal(403, ex.StatusCode);
        Assert.Equal("api_key_disabled", ex.Code);
    }

    [Fact]
    public async Task Status403_ScopeNotAllowed_ThrowsAuthenticationException()
    {
        var response = FakeHttpMessageHandler.JsonResponse(HttpStatusCode.Forbidden, TestJson.ErrorEnvelope("scope_not_allowed", "The API key does not allow usage reads."));
        using var client = MakeClient(response, out _, new NetRiskScanOptions { ApiKey = "nrs_live_noscope", MaxRetries = 0 });

        var ex = await Assert.ThrowsAsync<NetRiskScanAuthenticationException>(() => client.GetUsageAsync());

        Assert.Equal("scope_not_allowed", ex.Code);
    }

    [Fact]
    public async Task Status404_NotFound_ThrowsNotFoundException()
    {
        var response = FakeHttpMessageHandler.JsonResponse(HttpStatusCode.NotFound, TestJson.ErrorEnvelope("not_found", "No such route."));
        using var client = MakeClient(response, out _);

        await Assert.ThrowsAsync<NetRiskScanNotFoundException>(() => client.GetIpRiskAsync("8.8.8.8"));
    }

    [Fact]
    public async Task Status404_FeatureNotAvailable_ThrowsFeatureNotAvailableException()
    {
        var response = FakeHttpMessageHandler.JsonResponse(HttpStatusCode.NotFound, TestJson.ErrorEnvelope("feature_not_available", "Not open yet."));
        using var client = MakeClient(response, out _);

        await Assert.ThrowsAsync<NetRiskScanFeatureNotAvailableException>(() => client.GetIpRiskAsync("8.8.8.8"));
    }

    [Fact]
    public async Task Status429_RateLimitExceeded_ThrowsRateLimitException_NotQuotaExceeded()
    {
        var response = FakeHttpMessageHandler.JsonResponse(HttpStatusCode.TooManyRequests, TestJson.ErrorEnvelope("rate_limit_exceeded", "API rate limit exceeded."), r =>
        {
            r.Headers.Add("Retry-After", "5");
            r.Headers.Add("X-RateLimit-Limit", "60");
            r.Headers.Add("X-RateLimit-Remaining", "0");
        });
        using var client = MakeClient(response, out _);

        var ex = await Assert.ThrowsAsync<NetRiskScanRateLimitException>(() => client.GetIpRiskAsync("8.8.8.8"));

        Assert.IsNotType<NetRiskScanQuotaExceededException>(ex);
        Assert.Equal(TimeSpan.FromSeconds(5), ex.RetryAfter);
        Assert.Equal(60, ex.RateLimit.Limit);
    }

    [Fact]
    public async Task Status429_QuotaExceeded_ThrowsQuotaExceededException_CatchableAsRateLimitException()
    {
        var response = FakeHttpMessageHandler.JsonResponse(HttpStatusCode.TooManyRequests, TestJson.ErrorEnvelope("quota_exceeded", "API quota exceeded."), r =>
        {
            r.Headers.Add("Retry-After", "3600");
            r.Headers.Add("X-Quota-Remaining", "0");
        });
        using var client = MakeClient(response, out _, new NetRiskScanOptions { ApiKey = "nrs_live_test", MaxRetries = 0 });

        var ex = await Assert.ThrowsAsync<NetRiskScanQuotaExceededException>(() => client.GetIpRiskAsync("8.8.8.8"));

        // Subclass of RateLimitException, so a coarse `catch (NetRiskScanRateLimitException)` also works.
        Assert.IsAssignableFrom<NetRiskScanRateLimitException>(ex);
        Assert.Equal(0, ex.Quota.Remaining);
        Assert.Null(ex.DailyLimit); // billing-period variant -- not the anonymous-tier fields
    }

    [Fact]
    public async Task Status429_AnonymousDailyLimitReached_PopulatesAnonymousFields()
    {
        var body = TestJson.AnonymousLimitErrorEnvelope(30, 30, 0, "2026-08-29T00:00:00Z", "https://www.netriskscan.com/signup");
        var response = FakeHttpMessageHandler.JsonResponse(HttpStatusCode.TooManyRequests, body, r => r.Headers.Add("Retry-After", "3600"));
        using var client = MakeClient(response, out _);

        var ex = await Assert.ThrowsAsync<NetRiskScanQuotaExceededException>(() => client.GetIpRiskAsync("8.8.8.8"));

        Assert.Equal("anonymous_daily_limit_reached", ex.Code);
        Assert.Equal(30, ex.DailyLimit);
        Assert.Equal(30, ex.Used);
        Assert.Equal(0, ex.Remaining);
        Assert.Equal("2026-08-29T00:00:00Z", ex.ResetAt);
        Assert.Equal("https://www.netriskscan.com/signup", ex.SignupUrl);
    }

    [Fact]
    public async Task Status503_TemporarilyUnavailable_ThrowsApiException()
    {
        var response = FakeHttpMessageHandler.JsonResponse(HttpStatusCode.ServiceUnavailable, TestJson.ErrorEnvelope("temporarily_unavailable", "The API is temporarily unavailable."));
        using var client = MakeClient(response, out _);

        var ex = await Assert.ThrowsAsync<NetRiskScanApiException>(() => client.GetIpRiskAsync("8.8.8.8"));

        Assert.Equal("temporarily_unavailable", ex.Code);
    }

    [Fact]
    public async Task UnrecognizedErrorCode_StillThrowsApiException_ForwardCompatible()
    {
        var response = FakeHttpMessageHandler.JsonResponse((HttpStatusCode)418, TestJson.ErrorEnvelope("something_future_versions_invented", "?"));
        using var client = MakeClient(response, out _);

        var ex = await Assert.ThrowsAsync<NetRiskScanApiException>(() => client.GetIpRiskAsync("8.8.8.8"));

        Assert.Equal("something_future_versions_invented", ex.Code);
    }

    [Fact]
    public async Task MalformedJsonBody_ThrowsNetworkException()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("not json at all", System.Text.Encoding.UTF8, "application/json"),
        };
        using var client = MakeClient(response, out _);

        await Assert.ThrowsAsync<NetRiskScanNetworkException>(() => client.GetIpRiskAsync("8.8.8.8"));
    }

    [Fact]
    public async Task ErrorBodyThatIsNotJson_StillThrowsWithGenericMessage()
    {
        // A gateway/proxy in front of the API can answer an error status with an HTML or empty body.
        var response = new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            Content = new StringContent("<html>502 Bad Gateway</html>", System.Text.Encoding.UTF8, "text/html"),
        };
        using var client = MakeClient(response, out _, new NetRiskScanOptions { MaxRetries = 0 });

        var ex = await Assert.ThrowsAsync<NetRiskScanApiException>(() => client.GetIpRiskAsync("8.8.8.8"));

        Assert.Equal(502, ex.StatusCode);
        Assert.Null(ex.Code);
        Assert.Contains("502", ex.Message);
    }

    [Fact]
    public async Task PerAttemptTimeout_ThrowsTimeoutException()
    {
        var handler = FakeHttpMessageHandler.Delayed(
            TimeSpan.FromSeconds(5),
            FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        using var httpClient = new HttpClient(handler);
        using var client = new NetRiskScanClient(httpClient, new NetRiskScanOptions
        {
            Timeout = TimeSpan.FromMilliseconds(20),
            MaxRetries = 0,
        });

        var ex = await Assert.ThrowsAsync<NetRiskScanTimeoutException>(() => client.GetIpRiskAsync("8.8.8.8"));
        Assert.Equal(TimeSpan.FromMilliseconds(20), ex.Timeout);
    }
}
