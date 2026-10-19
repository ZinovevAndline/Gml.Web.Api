using Gml.Web.Api.Core.Integrations.Auth;
using NUnit.Framework;

namespace Gml.WebApi.Tests;

[TestFixture]
public class AndlineAuthUrlTests
{
    [TestCase("https://andline.pro", "https://andline.pro")]
    [TestCase("https://andline.pro/", "https://andline.pro")]
    [TestCase("https://test.andline.pro", "https://test.andline.pro")]
    [TestCase("http://127.0.0.1:8000", "http://127.0.0.1:8000")]
    public void AcceptsOnlyBaseOrigin(string input, string expected)
    {
        Assert.That(AndlineAuthUrl.TryNormalize(input, out var origin), Is.True);
        Assert.That(origin, Is.EqualTo(expected));
        Assert.That(AndlineAuthUrl.TryBuild(input, out var endpoint), Is.True);
        Assert.That(endpoint.ToString(), Is.EqualTo(expected + "/api/gml/auth"));
    }

    [TestCase("http://andline.pro")]
    [TestCase("https://andline.pro/api/gml/auth")]
    [TestCase("https://andline.pro/api")]
    [TestCase("https://andline.pro/?next=other")]
    [TestCase("https://andline.pro/#session")]
    [TestCase("https://admin:secret@andline.pro")]
    [TestCase("ftp://andline.pro")]
    [TestCase("not a URL")]
    [TestCase("")]
    public void RejectsPathsSecretsAndUnsafeOrigins(string input)
    {
        Assert.That(AndlineAuthUrl.TryNormalize(input, out _), Is.False);
        Assert.That(AndlineAuthUrl.TryBuild(input, out _), Is.False);
    }
}
