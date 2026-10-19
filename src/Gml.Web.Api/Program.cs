using Gml.Web.Api.Core.Extensions;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Logging;
using System.Net;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddFilter(static (_, level) => level >= LogLevel.Error);

// Pangolin/Newt may connect to this HTTP backend from 127.0.0.1. The
// backend must resolve the original launcher IP BEFORE its login handlers
// create JWT session/history entries. Never trust arbitrary public clients'
// forwarding headers (ASPNETCORE_FORWARDEDHEADERS_ENABLED does that).
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor;
    // Each hop is accepted only if its immediate neighbour is trusted.
    options.ForwardLimit = null;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
    options.KnownProxies.Add(IPAddress.Loopback);
    options.KnownProxies.Add(IPAddress.IPv6Loopback);

    // Additional Docker/Pangolin proxy peer addresses, if any. Only exact IPs:
    // do not use unrestricted ranges or "*" which enable IP spoofing.
    foreach (var item in (Environment.GetEnvironmentVariable("GML_TRUSTED_PROXIES") ?? "")
                 .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        if (IPAddress.TryParse(item, out var address)
            && !options.KnownProxies.Contains(address))
            options.KnownProxies.Add(address);
    }
});

var app = builder.RegisterServices().Build();
app.UseForwardedHeaders();
app.RegisterServices().Run();
