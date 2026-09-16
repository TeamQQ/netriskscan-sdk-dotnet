using System.Text.Json.Serialization;

namespace NetRiskScan.Internal;

/// <summary>The single error envelope every <c>/v1</c> failure uses: <c>{"error": {...}}</c>.</summary>
internal sealed record ApiErrorEnvelope
{
    [JsonPropertyName("error")]
    public ApiErrorBody? Error { get; init; }
}

/// <summary>
/// The error body. <see cref="DailyLimit"/> through <see cref="SignupUrl"/> are present only on the
/// anonymous daily-allowance <c>429</c>, which is a superset of the plain error envelope.
/// </summary>
internal sealed record ApiErrorBody
{
    [JsonPropertyName("code")]
    public string? Code { get; init; }

    [JsonPropertyName("message")]
    public string? Message { get; init; }

    [JsonPropertyName("requestId")]
    public string? RequestId { get; init; }

    [JsonPropertyName("dailyLimit")]
    public long? DailyLimit { get; init; }

    [JsonPropertyName("used")]
    public long? Used { get; init; }

    [JsonPropertyName("remaining")]
    public long? Remaining { get; init; }

    [JsonPropertyName("resetAt")]
    public string? ResetAt { get; init; }

    [JsonPropertyName("signupUrl")]
    public string? SignupUrl { get; init; }
}
