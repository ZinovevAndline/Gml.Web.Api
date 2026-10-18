using Gml.Web.Api.Core.Integrations.Auth;
using NUnit.Framework;

namespace Gml.WebApi.Tests;

public class CustomEndpointAuthResponseTests
{
    [TestCase("")]
    [TestCase("null")]
    [TestCase("<html>error</html>")]
    public void InvalidSuccessBodyDoesNotAuthenticate(string body)
    {
        Assert.That(CustomEndpointAuthService.ParseResponse("Player", true, body).IsSuccess, Is.False);
    }

    [TestCase("{}")]
    [TestCase("{\"Login\":\"Player\"}")]
    [TestCase("{\"Login\":\"Other\",\"UserUuid\":\"12345678-1234-1234-1234-123456789abc\"}")]
    [TestCase("{\"Login\":\"Player\",\"UserUuid\":\"00000000-0000-0000-0000-000000000000\"}")]
    public void MissingOrMismatchedIdentityDoesNotAuthenticate(string body)
    {
        Assert.That(CustomEndpointAuthService.ParseResponse("Player", true, body).IsSuccess, Is.False);
    }

    [Test]
    public void UpstreamSuccessMustNotPromotePendingTwoFactor()
    {
        var body = "{\"Login\":\"Player\",\"UserUuid\":\"12345678-1234-1234-1234-123456789abc\",\"Message\":\"2FA_PENDING\"}";
        Assert.That(CustomEndpointAuthService.ParseResponse("Player", true, body).IsSuccess, Is.False);
    }

    [TestCase("2FA_PENDING [tiauth:request:continuation:120] Подтвердите вход в боте")]
    [TestCase("2FA_DENIED")]
    [TestCase("2FA_EXPIRED")]
    public void FailedAuthPreservesContinuationAndNeverAuthenticates(string message)
    {
        var body = Newtonsoft.Json.JsonConvert.SerializeObject(new { Message = message });
        var result = CustomEndpointAuthService.ParseResponse("Player", false, body);
        Assert.Multiple(() =>
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Message, Is.EqualTo(message));
        });
    }

    [Test]
    public void SuccessfulAuthPreservesServerIdentity()
    {
        var result = CustomEndpointAuthService.ParseResponse("player", true,
            "{\"Login\":\"Player\",\"UserUuid\":\"12345678-1234-1234-1234-123456789abc\",\"IsSlim\":true}");
        Assert.Multiple(() =>
        {
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Login, Is.EqualTo("Player"));
            Assert.That(result.Uuid, Is.EqualTo("12345678-1234-1234-1234-123456789abc"));
            Assert.That(result.IsSlim, Is.True);
            Assert.That(result.TwoFactorEnabled, Is.False);
        });
    }
}
