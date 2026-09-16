// Console / script usage: no ASP.NET Core, no dependency injection container -- just `using var client`.
// Run with an API key set: NETRISKSCAN_API_KEY=nrs_live_xxxx dotnet run --project samples/ConsoleExample
using NetRiskScan;
using NetRiskScan.Exceptions;

using var client = new NetRiskScanClient();

var ip = args.Length > 0 ? args[0] : "8.8.8.8";

try
{
    var result = await client.GetIpRiskAsync(ip);

    Console.WriteLine($"ip:               {result.Ip}");
    Console.WriteLine($"risk.index:       {result.Risk.Index?.ToString() ?? "null (not scoreable)"}");
    Console.WriteLine($"risk.band:        {result.Risk.Band ?? "null"}");
    Console.WriteLine($"assessmentGrade:  {result.Risk.AssessmentGrade}");
    Console.WriteLine($"network.type:     {result.Network.Type ?? "unknown"}");
    Console.WriteLine($"network.org:      {result.Network.Organization ?? "unknown"}");

    // Every detection flag is bool? -- true/false/null are three distinct answers. Never treat null as
    // false: it means "unknown", not "checked and clean".
    Console.WriteLine($"flags.proxy:      {Render(result.Flags.Proxy)}");
    Console.WriteLine($"flags.vpn:        {Render(result.Flags.Vpn)}");
    Console.WriteLine($"flags.tor:        {Render(result.Flags.Tor)}");

    if (result.Usage is { } usage)
    {
        // Present only on an anonymous (no API key) call.
        Console.WriteLine($"anonymous usage:  {usage.Used}/{usage.DailyLimit} used today, resets {usage.ResetAt}");
    }
}
catch (NetRiskScanValidationException ex)
{
    Console.Error.WriteLine($"Invalid request ({ex.Code}): {ex.Message}");
}
catch (NetRiskScanRateLimitException ex)
{
    Console.Error.WriteLine($"Rate limited ({ex.Code}); retry after {ex.RetryAfter}. Request {ex.RequestId}.");
}
catch (NetRiskScanException ex)
{
    Console.Error.WriteLine($"NetRiskScan API error ({ex.Code}, HTTP {ex.StatusCode}): {ex.Message}. Request {ex.RequestId}.");
}

static string Render(bool? value) => value switch
{
    true => "Yes",
    false => "No",
    null => "Unknown",
};
