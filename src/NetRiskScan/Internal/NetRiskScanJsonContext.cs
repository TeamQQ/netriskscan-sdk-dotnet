using System.Text.Json.Serialization;
using NetRiskScan.Models;

namespace NetRiskScan.Internal;

/// <summary>
/// Source-generated <see cref="JsonSerializerContext"/> for every type this SDK (de)serializes.
///
/// Source generation is used instead of reflection-based serialization so the SDK works unmodified
/// under Native AOT / trimming (see <c>IsAotCompatible</c> in the project file) and avoids the startup
/// reflection cost reflection-based <c>System.Text.Json</c> would otherwise pay on every cold start --
/// relevant for short-lived Azure Functions / AWS Lambda callers of this SDK.
///
/// Unknown JSON properties are ignored by default (not an error): a server that adds a new field must
/// never break an older SDK version reading its response.
/// </summary>
[JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(IpRiskResult))]
[JsonSerializable(typeof(UsageResult))]
[JsonSerializable(typeof(ApiErrorEnvelope))]
internal partial class NetRiskScanJsonContext : JsonSerializerContext
{
}
