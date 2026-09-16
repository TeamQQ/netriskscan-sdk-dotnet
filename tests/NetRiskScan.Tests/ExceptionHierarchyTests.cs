using NetRiskScan.Exceptions;
using Xunit;

namespace NetRiskScan.Tests;

public sealed class ExceptionHierarchyTests
{
    [Theory]
    [InlineData(typeof(NetRiskScanApiException))]
    [InlineData(typeof(NetRiskScanAuthenticationException))]
    [InlineData(typeof(NetRiskScanValidationException))]
    [InlineData(typeof(NetRiskScanRateLimitException))]
    [InlineData(typeof(NetRiskScanQuotaExceededException))]
    [InlineData(typeof(NetRiskScanNotFoundException))]
    [InlineData(typeof(NetRiskScanFeatureNotAvailableException))]
    [InlineData(typeof(NetRiskScanTimeoutException))]
    [InlineData(typeof(NetRiskScanNetworkException))]
    public void EveryConcreteException_DerivesFromTheCommonBase(Type exceptionType)
    {
        Assert.True(typeof(NetRiskScanException).IsAssignableFrom(exceptionType));
    }

    [Fact]
    public void QuotaExceededException_IsARateLimitException()
    {
        Assert.True(typeof(NetRiskScanRateLimitException).IsAssignableFrom(typeof(NetRiskScanQuotaExceededException)));
    }

    [Fact]
    public void CommonBase_IsAbstract_CannotBeThrownDirectly()
    {
        Assert.True(typeof(NetRiskScanException).IsAbstract);
    }
}
