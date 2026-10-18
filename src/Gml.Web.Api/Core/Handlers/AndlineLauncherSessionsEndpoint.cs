using System.Security.Cryptography;
using System.Text;
using Gml.Web.Api.Core.Services;

namespace Gml.Web.Api.Core.Handlers;

/// <summary>
/// Site-to-site revocation API, never callable with the public launcher token.
/// The shared signing secret is private to the GML API and ANDLINE backend.
/// A request signature covers method, path and UTC timestamp.
/// </summary>
public static class AndlineLauncherSessionsEndpoint
{
    private static bool Authorized(HttpContext context)
    {
        var key = Environment.GetEnvironmentVariable("ANDLINE_GML_SHARED_SECRET");
        if (string.IsNullOrWhiteSpace(key) || key.Length < 32) return false;

        var stamp = context.Request.Headers["X-Andline-Timestamp"].ToString();
        var signature = context.Request.Headers["X-Andline-Signature"].ToString();
        if (!long.TryParse(stamp, out var seconds)
            || Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - seconds) > 90
            || signature.Length != 64) return false;

        try
        {
            var canonical = context.Request.Method.ToUpperInvariant()
                + "\n" + context.Request.Path.Value + "\n" + stamp;
            var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(key),
                Encoding.UTF8.GetBytes(canonical));
            return CryptographicOperations.FixedTimeEquals(mac, Convert.FromHexString(signature));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static async Task<IResult> List(HttpContext ctx,
        PlayerLauncherSessionRegistry registry, string uuid)
    {
        if (!Authorized(ctx)) return Results.Unauthorized();
        if (!Guid.TryParse(uuid, out _)) return Results.BadRequest();
        var rows = await registry.ListAsync(uuid, ctx.RequestAborted);
        return Results.Ok(new
        {
            ok = true,
            sessions = rows.Select(row => new
            {
                id = row.Id,
                kind = "gml",
                device = row.DeviceLabel,
                created_at = row.CreatedAtUtc,
                last_seen_at = row.LastSeenAtUtc,
                expires_at = row.ExpiresAtUtc,
                current = false,
                single_device = true,
            })
        });
    }

    public static async Task<IResult> Revoke(HttpContext ctx,
        PlayerLauncherSessionRegistry registry, string uuid, Guid id)
    {
        if (!Authorized(ctx)) return Results.Unauthorized();
        if (!Guid.TryParse(uuid, out _)) return Results.BadRequest();
        var changed = await registry.RevokeAsync(uuid, id, ctx.RequestAborted);
        return changed ? Results.Ok(new { ok = true }) : Results.NotFound();
    }

    public static async Task<IResult> RevokeAll(HttpContext ctx,
        PlayerLauncherSessionRegistry registry, string uuid)
    {
        if (!Authorized(ctx)) return Results.Unauthorized();
        if (!Guid.TryParse(uuid, out _)) return Results.BadRequest();
        var count = await registry.RevokeAllAsync(uuid, ctx.RequestAborted);
        return Results.Ok(new { ok = true, revoked = count });
    }
}
