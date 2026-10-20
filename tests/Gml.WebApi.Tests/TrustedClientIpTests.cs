using System.Net;
using Gml.Web.Api.Core.Extensions;
using Gml.Web.Api.Core.Handlers;
using System.Reflection;
using Microsoft.AspNetCore.Http;
using NUnit.Framework;

namespace Gml.WebApi.Tests;

[TestFixture]
public class TrustedClientIpTests
{
    [Test]
    public void PublicClientCannotImpersonateCloudflareOrForwardedIp()
    {
        var request = new DefaultHttpContext();
        request.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.60");
        request.Request.Headers["CF-Connecting-IP"] = "192.0.2.1";
        request.Request.Headers["X-Real-IP"] = "192.0.2.2";
        request.Request.Headers["X-Forwarded-For"] = "192.0.2.3";
        Assert.That(request.ParseRemoteAddress(), Is.EqualTo(IPAddress.Parse("203.0.113.60")));
    }

    [Test]
    public void LauncherSessionIpCannotRecordLoopbackOrPrivatePangolinPeer()
    {
        var publicIp = typeof(AuthIntegrationHandler).GetMethod(
            "PublicLauncherIp", BindingFlags.Static | BindingFlags.NonPublic);
        Assert.That(publicIp, Is.Not.Null);

        string? Resolve(string input) => (string?)publicIp!.Invoke(
            null, new object?[] { IPAddress.Parse(input) });

        Assert.Multiple(() =>
        {
            Assert.That(Resolve("127.0.0.1"), Is.Null);
            Assert.That(Resolve("::1"), Is.Null);
            Assert.That(Resolve("10.42.0.4"), Is.Null);
            Assert.That(Resolve("172.20.0.6"), Is.Null);
            Assert.That(Resolve("192.168.1.5"), Is.Null);
            Assert.That(Resolve("::ffff:127.0.0.1"), Is.Null);
            Assert.That(Resolve("198.51.100.45"), Is.EqualTo("198.51.100.45"));
            Assert.That(Resolve("::ffff:198.51.100.45"), Is.EqualTo("198.51.100.45"));
        });
    }

    [Test]
    public void InternalYarpPeerUsesOnlyCanonicalSingleForwardedAddress()
    {
        var request = new DefaultHttpContext();
        request.Connection.RemoteIpAddress = IPAddress.Loopback;
        request.Request.Headers["X-Forwarded-For"] = "198.51.100.12";
        request.Request.Headers["X-Real-IP"] = "192.0.2.100";
        Assert.That(request.ParseRemoteAddress(), Is.EqualTo(IPAddress.Parse("198.51.100.12")));

        // Mixed chains are ambiguous and cannot be used as identities.
        request.Request.Headers["X-Forwarded-For"] = "192.0.2.9, 198.51.100.12";
        Assert.That(request.ParseRemoteAddress(), Is.EqualTo(IPAddress.Loopback));
    }
}
