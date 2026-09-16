using System.Reflection;

namespace NetRiskScan.Internal;

/// <summary>Resolves the SDK's own version for the default <c>User-Agent</c> header.</summary>
internal static class SdkVersion
{
    /// <summary>
    /// The package version, read from the assembly's informational version (which MSBuild populates
    /// from <c>&lt;Version&gt;</c> in the project file) rather than hardcoded -- unlike a string
    /// constant, this can never drift from the version actually published to NuGet.
    /// </summary>
    public static readonly string Value = ResolveValue();

    private static string ResolveValue()
    {
        var informational = typeof(SdkVersion).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        if (string.IsNullOrEmpty(informational))
        {
            return "0.0.0";
        }

        // Strips the SourceLink commit-hash metadata suffix MSBuild appends (e.g. "0.1.0+abcdef1234"),
        // which has no place in a User-Agent header.
        var plusIndex = informational.IndexOf('+');
        return plusIndex >= 0 ? informational[..plusIndex] : informational;
    }
}
