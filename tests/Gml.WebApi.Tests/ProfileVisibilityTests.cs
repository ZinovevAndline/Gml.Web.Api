using Gml.Web.Api.Core.Handlers;
using NUnit.Framework;

namespace Gml.WebApi.Tests;

[TestFixture]
public class ProfileVisibilityTests
{
    private const string UserD = "f84c6a79-cc03-43c5-9a9f-cf1e3aa6c345";
    private const string UserN = "f84c6a79cc0343c59a9fcf1e3aa6c345";

    [Test]
    public void Public_enabled_profile_is_visible()
    {
        Assert.That(ProfileHandler.IsVisibleToPlayer(true, Array.Empty<string>(), UserD), Is.True);
    }

    [Test]
    public void Existing_whitelist_accepts_UUID_case_and_format_differences()
    {
        Assert.That(ProfileHandler.IsVisibleToPlayer(true, new[] { UserD.ToUpperInvariant() }, UserN), Is.True);
        Assert.That(ProfileHandler.IsVisibleToPlayer(true, new[] { UserN.ToUpperInvariant() }, UserD), Is.True);
    }

    [Test]
    public void Whitelist_does_not_leak_other_players_profiles()
    {
        Assert.That(ProfileHandler.IsVisibleToPlayer(true, new[] { "86c8c134-c705-4d7d-8e87-777777777777" }, UserD), Is.False);
        Assert.That(ProfileHandler.IsVisibleToPlayer(true, new[] { "invalid" }, UserD), Is.False);
    }

    [Test]
    public void Disabled_profile_is_not_exposed_even_if_player_whitelisted()
    {
        Assert.That(ProfileHandler.IsVisibleToPlayer(false, new[] { UserD }, UserD), Is.False);
        Assert.That(ProfileHandler.IsVisibleToPlayer(false, Array.Empty<string>(), UserD), Is.False);
    }
}
