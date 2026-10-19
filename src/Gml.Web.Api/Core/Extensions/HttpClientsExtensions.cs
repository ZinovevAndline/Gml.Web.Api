using System.Net;
using Gml.Web.Api.Core.Options;

namespace Gml.Web.Api.Core.Extensions;

public static class HttpClientsExtensions
{
    public static IServiceCollection AddNamedHttpClients(
        this IServiceCollection services,
        string marketEndpoint)
    {
        string? skinsServiceUrl = Environment.GetEnvironmentVariable("SkinServiceUrl");

        var dockerEnv = Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER");

        var isRunningInDocker = !string.IsNullOrEmpty(dockerEnv) && dockerEnv.ToLower() == "true";

        services.AddHttpClient(HttpClientNames.SkinService, client =>
        {
            client.BaseAddress = isRunningInDocker
                ? new Uri("http://gml-web-skins:8085/")
                : string.IsNullOrEmpty(skinsServiceUrl)
                    ? null
                    : new Uri(skinsServiceUrl);
        });

        services.AddHttpClient(HttpClientNames.MarketService,
            client => { client.BaseAddress = new Uri(marketEndpoint); });

        return services;
    }

    public static IPAddress? ParseRemoteAddress(this HttpContext context)
    {
        var peer = context.Connection.RemoteIpAddress;
        if (peer is null) return null;

        // Client-controlled HTTP headers must never override the socket peer.
        // This service is normally reached via our local YARP reverse proxy.
        // A non-loopback client or arbitrary private host is not trusted to
        // assert any original IP address, even if it sends Cloudflare headers.
        if (!IPAddress.IsLoopback(peer)
            && !(peer.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(peer.MapToIPv4())))
            return peer;

        // YARP's X-Forwarded-For "Set" transform overwrites incoming values
        // with the actual upstream socket peer. The single resulting address
        // is the only supported forwarded identity.
        var forwarded = context.Request.Headers["X-Forwarded-For"].ToString();
        if (!string.IsNullOrWhiteSpace(forwarded)
            && !forwarded.Contains(',')
            && TryParseIp(forwarded, out var ip))
            return ip;

        return peer;
    }

    private static bool TryParseIp(string? value, out IPAddress ip)
    {
        ip = IPAddress.None;

        if (string.IsNullOrWhiteSpace(value))
            return false;

        var s = value.Trim().Trim('"');
        if (s.Equals("unknown", StringComparison.OrdinalIgnoreCase))
            return false;

        if (s.StartsWith("[") && s.Contains(']'))
        {
            var end = s.IndexOf(']');
            if (end > 1)
                s = s.Substring(1, end - 1);
        }
        else
        {
            var firstColon = s.IndexOf(':');
            if (firstColon > 0 && firstColon == s.LastIndexOf(':'))
            {
                s = s.Substring(0, firstColon);
            }
        }

        return IPAddress.TryParse(s, out ip);
    }
}
