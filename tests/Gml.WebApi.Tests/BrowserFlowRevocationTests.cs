using System;
using Gml.Web.Api.Core.Handlers;
using NUnit.Framework;

namespace Gml.WebApi.Tests;

[TestFixture]
public class BrowserFlowRevocationTests
{
    [Test]
    public void RevokingAccountInvalidatesOlderBrowserGrants()
    {
        var account = Guid.NewGuid();
        var before = DateTimeOffset.UtcNow.AddMinutes(-1);
        Assert.That(BrowserLauncherAuthHandler.IsRevokedSince(account, before), Is.False);
        BrowserLauncherAuthHandler.CancelPendingForUser(account);
        Assert.That(BrowserLauncherAuthHandler.IsRevokedSince(account, before), Is.True);
        Assert.That(BrowserLauncherAuthHandler.IsRevokedSince(account, DateTimeOffset.UtcNow.AddMinutes(1)), Is.False);
        Assert.That(BrowserLauncherAuthHandler.IsRevokedSince(Guid.NewGuid(), before), Is.False);
    }
}
