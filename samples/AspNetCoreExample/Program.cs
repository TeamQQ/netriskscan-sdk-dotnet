using NetRiskScan;
using NetRiskScan.Exceptions;

var builder = WebApplication.CreateBuilder(args);

// Registers INetRiskScanClient through IHttpClientFactory. This sample ships with no
// NetRiskScan:ApiKey configured at all, so it runs anonymously out of the box. To use a real key,
// set it via user-secrets (`dotnet user-secrets set NetRiskScan:ApiKey nrs_live_...`) or the
// NETRISKSCAN_API_KEY environment variable -- never commit a key to appsettings.json. Note that an
// empty string is rejected as a configuration mistake (see NetRiskScanClient), not silently treated
// as "no key" -- only an absent/null configuration value falls back to anonymous access.
builder.Services.AddNetRiskScan(options =>
{
    options.ApiKey = builder.Configuration["NetRiskScan:ApiKey"];
});

// RiskService below depends on INetRiskScanClient directly; nothing extra to register for it.
builder.Services.AddTransient<RiskService>();

var app = builder.Build();

app.MapGet("/risk/{ip}", async (string ip, RiskService service, CancellationToken cancellationToken) =>
{
    try
    {
        return Results.Ok(await service.CheckAsync(ip, cancellationToken));
    }
    catch (NetRiskScanValidationException ex)
    {
        return Results.Problem(ex.Message, statusCode: StatusCodes.Status400BadRequest, title: ex.Code);
    }
    catch (NetRiskScanRateLimitException ex)
    {
        return Results.Problem(ex.Message, statusCode: StatusCodes.Status429TooManyRequests, title: ex.Code);
    }
    catch (NetRiskScanException ex)
    {
        return Results.Problem(ex.Message, statusCode: ex.StatusCode ?? StatusCodes.Status502BadGateway, title: ex.Code);
    }
});

app.Run();

/// <summary>The pattern the README's ASP.NET Core section documents: depend on
/// <see cref="INetRiskScanClient"/>, not the concrete client, so this class is trivially unit-testable
/// against a fake implementation.</summary>
public sealed class RiskService(INetRiskScanClient client)
{
    public async Task<object> CheckAsync(string ip, CancellationToken cancellationToken)
    {
        var result = await client.GetIpRiskAsync(ip, cancellationToken);
        return new
        {
            result.Ip,
            result.Risk.Index,
            result.Risk.Band,
            result.Flags.Proxy,
            result.Flags.Vpn,
            result.Flags.Tor,
        };
    }
}
