using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Builder;
using GmlCore.Interfaces;
using Gml.Web.Api.Core.Extensions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;

namespace Gml.WebApi.Tests;

[TestFixture]
public class FileDeliveryResultsTests
{
    private static DefaultHttpContext CreateContext(string method)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider()
        };
        context.Request.Method = method;
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static IResult FileResult() => Results.File(
        new MemoryStream(Enumerable.Range(0, 10).Select(i => (byte)i).ToArray()),
        "application/octet-stream", "test.bin",
        entityTag: new EntityTagHeaderValue("\"sha\""),
        enableRangeProcessing: true);

    [Test]
    public async Task Range_ReturnsOnlyRequestedBytes()
    {
        var context = CreateContext("GET");
        context.Request.Headers.Range = "bytes=3-6";
        await FileResult().ExecuteAsync(context);
        Assert.Multiple(() =>
        {
            Assert.That(context.Response.StatusCode, Is.EqualTo(206));
            Assert.That(context.Response.Headers.ContentRange.ToString(), Is.EqualTo("bytes 3-6/10"));
            Assert.That(((MemoryStream)context.Response.Body).ToArray(), Is.EqualTo(new byte[] { 3, 4, 5, 6 }));
        });
    }

    [Test]
    public async Task InvalidRange_Returns416()
    {
        var context = CreateContext("GET");
        context.Request.Headers.Range = "bytes=30-40";
        await FileResult().ExecuteAsync(context);
        Assert.That(context.Response.StatusCode, Is.EqualTo(416));
        Assert.That(context.Response.Headers.ContentRange.ToString(), Is.EqualTo("bytes */10"));
    }

    [Test]
    public async Task Head_ReturnsNoPayload()
    {
        var context = CreateContext("HEAD");
        await FileResult().ExecuteAsync(context);
        Assert.That(((MemoryStream)context.Response.Body).Length, Is.Zero);
        Assert.That(context.Response.StatusCode, Is.EqualTo(200));
    }

    [Test]
    public async Task MatchingEtag_Returns304()
    {
        var context = CreateContext("GET");
        context.Request.Headers.IfNoneMatch = "\"sha\"";
        await FileResult().ExecuteAsync(context);
        Assert.That(context.Response.StatusCode, Is.EqualTo(304));
        Assert.That(((MemoryStream)context.Response.Body).Length, Is.Zero);
    }

    [Test]
    public void FileRoutes_InitializeWithSeparateGetAndHeadMethods()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddSingleton<IGmlManager>(_ =>
            throw new InvalidOperationException("Route registration must not open files."));

        using var app = builder.Build();
        EndpointsExtensions.RegisterFileDownloadEndpoints(app);

        // Materializing EndpointDataSource triggers WithOpenApi. Previously this
        // threw on GET+HEAD in one MapMethods registration and broke every URL.
        var routes = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(dataSource => dataSource.Endpoints)
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.RoutePattern.RawText == "/api/v1/file/{fileHash}")
            .ToArray();

        Assert.That(routes, Has.Length.EqualTo(2));
        var verbs = routes.Select(endpoint =>
            endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()!.HttpMethods.ToArray()).ToArray();
        Assert.That(verbs.All(methods => methods.Length == 1), Is.True);
        Assert.That(verbs.SelectMany(methods => methods), Is.EquivalentTo(new[] { "GET", "HEAD" }));
    }
}
