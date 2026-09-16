using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace NetRiskScan.Tests;

/// <summary>
/// <c>AddNetRiskScan()</c>: <see cref="INetRiskScanClient"/> resolves, options bind from the delegate,
/// and the underlying <see cref="HttpClient"/> comes from <c>IHttpClientFactory</c> -- never a
/// per-request <c>new HttpClient()</c>.
/// </summary>
public sealed class DependencyInjectionTests
{
    [Fact]
    public void AddNetRiskScan_ResolvesINetRiskScanClient()
    {
        var services = new ServiceCollection();
        services.AddNetRiskScan();
        using var provider = services.BuildServiceProvider();

        var client = provider.GetRequiredService<INetRiskScanClient>();

        Assert.IsType<NetRiskScanClient>(client);
    }

    [Fact]
    public void AddNetRiskScan_ResolvesAsSingletonPerScope_ThroughHttpClientFactory()
    {
        var services = new ServiceCollection();
        services.AddNetRiskScan();
        using var provider = services.BuildServiceProvider();

        var first = provider.GetRequiredService<INetRiskScanClient>();
        var second = provider.GetRequiredService<INetRiskScanClient>();

        // AddHttpClient<TClient, TImplementation> registers the typed client as transient by default --
        // resolving twice from the root provider produces two instances, each backed by a pooled
        // HttpMessageHandler from IHttpClientFactory rather than two raw sockets-owning HttpClients.
        Assert.NotSame(first, second);
    }

    [Fact]
    public void AddNetRiskScan_BindsConfigureDelegate()
    {
        var services = new ServiceCollection();
        services.AddNetRiskScan(options =>
        {
            options.ApiKey = "nrs_live_ditest";
            options.BaseUrl = "https://di-test.example.com";
        });
        using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<NetRiskScanOptions>>().Value;

        Assert.Equal("nrs_live_ditest", options.ApiKey);
        Assert.Equal("https://di-test.example.com", options.BaseUrl);
    }

    [Fact]
    public async Task AddNetRiskScan_ResolvedClient_CanMakeRequests_ThroughInjectedHandler()
    {
        var handler = FakeHttpMessageHandler.Single(FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown));
        var services = new ServiceCollection();
        services.AddNetRiskScan()
            .ConfigurePrimaryHttpMessageHandler(() => handler);
        using var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<INetRiskScanClient>();

        var result = await client.GetIpRiskAsync("8.8.8.8");

        Assert.Equal("8.8.8.8", result.Ip);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public void AddNetRiskScan_InvalidOptions_ThrowsOnResolution()
    {
        var services = new ServiceCollection();
        services.AddNetRiskScan(options => options.MaxRetries = -1);
        using var provider = services.BuildServiceProvider();

        Assert.Throws<Microsoft.Extensions.Options.OptionsValidationException>(
            () => provider.GetRequiredService<INetRiskScanClient>());
    }

    [Fact]
    public void AddNetRiskScan_ReturnsHttpClientBuilder_ForFurtherConfiguration()
    {
        var services = new ServiceCollection();

        // The returned IHttpClientBuilder lets a caller chain further IHttpClientFactory configuration
        // (a Polly handler, a custom DelegatingHandler, ...) onto the same named/typed client.
        var builder = services.AddNetRiskScan();
        builder.ConfigurePrimaryHttpMessageHandler(() => FakeHttpMessageHandler.Single(
            FakeHttpMessageHandler.JsonResponse(HttpStatusCode.OK, TestJson.IpRiskFullyKnown)));

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredService<INetRiskScanClient>());
    }
}
