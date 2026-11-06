using System;
using Gml.Models.User;
using Gml.Web.Api.Core.Handlers;
using NUnit.Framework;

namespace Gml.WebApi.Tests;

[TestFixture]
public sealed class MainMenuSessionProofTests
{
    [Test]
    public void AcceptsOnlyExactActiveBearerDigest()
    {
        var now = DateTime.UtcNow;
        var active = new LauncherAuthSession {
            SessionId = Guid.NewGuid().ToString("N"),
            TokenHash = new string('A', 64),
            ExpiresAtUtc = now.AddMinutes(5)
        };
        Assert.That(AndlineLauncherSessionHandler.FindActiveMenuSession(
            new[] { active }, new string('a', 64), now), Is.SameAs(active));
        Assert.That(AndlineLauncherSessionHandler.FindActiveMenuSession(
            new[] { active }, new string('b', 64), now), Is.Null);
        Assert.That(AndlineLauncherSessionHandler.FindActiveMenuSession(
            new[] { active }, "not-hex", now), Is.Null);
    }

    [Test]
    public void RevokedAndExpiredDevicesNeverAuthorizeMenu()
    {
        var now = DateTime.UtcNow;
        var expired = new LauncherAuthSession {
            TokenHash = new string('C', 64), ExpiresAtUtc = now
        };
        var revoked = new LauncherAuthSession {
            TokenHash = new string('D', 64), ExpiresAtUtc = now.AddDays(1),
            RevokedAtUtc = now.AddSeconds(-1)
        };
        Assert.That(AndlineLauncherSessionHandler.FindActiveMenuSession(
            new[] { expired }, new string('c', 64), now), Is.Null);
        Assert.That(AndlineLauncherSessionHandler.FindActiveMenuSession(
            new[] { revoked }, new string('d', 64), now), Is.Null);
    }
}
