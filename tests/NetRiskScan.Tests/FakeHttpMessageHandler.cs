using System.Collections.Concurrent;

namespace NetRiskScan.Tests;

/// <summary>
/// A minimal, dependency-free <see cref="HttpMessageHandler"/> test double. CI must be able to run
/// fully offline against <c>api.netriskscan.com</c>, so this stands in for the real network: every test
/// constructs one with a canned response (or a sequence of them, for retry tests) and a
/// <see cref="HttpClient"/> wrapping it, and asserts against <see cref="Requests"/> afterward.
/// </summary>
internal sealed class FakeHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _responder;

    public ConcurrentQueue<HttpRequestMessage> Requests { get; } = new();

    public FakeHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        : this((request, _) => Task.FromResult(responder(request)))
    {
    }

    public FakeHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responder)
    {
        _responder = responder;
    }

    /// <summary>Returns each response in <paramref name="responses"/> in order, one per call; the last
    /// response repeats if there are more calls than responses.</summary>
    public static FakeHttpMessageHandler Sequence(params HttpResponseMessage[] responses)
    {
        var index = 0;
        return new FakeHttpMessageHandler(_ =>
        {
            var response = responses[Math.Min(index, responses.Length - 1)];
            index++;
            return response;
        });
    }

    public static FakeHttpMessageHandler Single(HttpResponseMessage response) =>
        new(_ => response);

    /// <summary>Waits <paramref name="delay"/> (honoring cancellation, so a timeout test actually
    /// observes the SDK's per-attempt timeout cancelling the in-flight call) before returning
    /// <paramref name="response"/>.</summary>
    public static FakeHttpMessageHandler Delayed(TimeSpan delay, HttpResponseMessage response) =>
        new(async (_, cancellationToken) =>
        {
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            return response;
        });

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Enqueue(request);
        cancellationToken.ThrowIfCancellationRequested();
        return await _responder(request, cancellationToken).ConfigureAwait(false);
    }

    public static HttpResponseMessage JsonResponse(System.Net.HttpStatusCode status, string json, Action<HttpResponseMessage>? configure = null)
    {
        var response = new HttpResponseMessage(status)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json"),
        };
        configure?.Invoke(response);
        return response;
    }
}
