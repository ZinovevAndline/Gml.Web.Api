using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gml.Models.User;
using GmlCore.Interfaces;
using Microsoft.Extensions.Caching.Memory;

namespace Gml.Web.Api.Core.Handlers;

/// <summary>
/// HMAC-protected server-to-server control plane used by ANDLINE Laravel.
/// It never accepts client-supplied bearer tokens or exposes token digests.
/// </summary>
public static class AndlineLauncherSessionHandler
{
    private const string Prefix = "v1";
    private static readonly object NonceLock = new();

    public sealed class SessionRequest
    {
        public string? Uuid { get; set; }
        public string? SessionId { get; set; }
    }

    public static async Task<IResult> Execute(
        HttpContext context,
        IGmlManager manager,
        IMemoryCache cache,
        string action)
    {
        if (action is not ("list" or "revoke" or "revoke-all"))
            return Results.NotFound();

        var secret = Environment.GetEnvironmentVariable("ANDLINE_GML_SESSION_SECRET");
        if (string.IsNullOrEmpty(secret) || secret.Length < 32)
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);

        if (context.Request.ContentLength is > 4096)
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);

        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync(context.RequestAborted);
        if (Encoding.UTF8.GetByteCount(body) > 4096)
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);

        var timestampText = context.Request.Headers["X-Andline-Timestamp"].ToString();
        var nonce = context.Request.Headers["X-Andline-Nonce"].ToString();
        var signature = context.Request.Headers["X-Andline-Signature"].ToString();

        if (timestampText.Length != 10
            || !long.TryParse(timestampText, NumberStyles.None, CultureInfo.InvariantCulture, out var timestamp)
            || Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp) > 60
            || !Guid.TryParseExact(nonce, "N", out _)
            || signature.Length != 64)
            return Results.Unauthorized();

        var signed = string.Join("\n", Prefix, timestampText, nonce,
            context.Request.Path.Value, body);
        var expected = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(signed));
        byte[] actual;
        try
        {
            actual = Convert.FromHexString(signature);
        }
        catch (FormatException)
        {
            return Results.Unauthorized();
        }

        if (!CryptographicOperations.FixedTimeEquals(expected, actual))
            return Results.Unauthorized();

        // Single-process Pterodactyl API: reject replays within the accepted
        // timestamp skew. Behind multiple API replicas use shared nonce storage.
        lock (NonceLock)
        {
            var key = "andline:gml:nonce:" + nonce;
            if (cache.TryGetValue(key, out _))
                return Results.Unauthorized();

            cache.Set(key, true, TimeSpan.FromMinutes(3));
        }

        SessionRequest? input;
        try
        {
            input = JsonSerializer.Deserialize<SessionRequest>(body,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (JsonException)
        {
            return Results.BadRequest();
        }

        if (input is null || !Guid.TryParse(input.Uuid, out var playerUuid)
            || playerUuid == Guid.Empty)
            return Results.BadRequest();

        // Legacy GML SQLite records can store UUIDs with or without hyphens.
        // A single D-form lookup silently returned an empty session list even
        // after a successful launcher login. Resolve all supported forms,
        // comparing the parsed UUID before accepting the identity.
        var user = await manager.Users.GetUserByUuid(playerUuid.ToString("D")) as AuthUser
                   ?? await manager.Users.GetUserByUuid(playerUuid.ToString("N")) as AuthUser;
        if (user is null || !Guid.TryParse(user.Uuid, out var storedUuid) || storedUuid != playerUuid)
        {
            return action == "list" ? Results.Ok(new { sessions = Array.Empty<object>() }) : Results.NotFound();
        }

        var now = DateTime.UtcNow;
        user.LauncherAuthSessions ??= [];

        if (action == "list")
        {
            var sessions = user.LauncherAuthSessions
                .Where(entry => entry.RevokedAtUtc is null && entry.ExpiresAtUtc > now)
                .OrderByDescending(entry => entry.CreatedAtUtc)
                .Select(entry => new
                {
                    session_id = entry.SessionId,
                    device_name = entry.DeviceName,
                    created_at = entry.CreatedAtUtc,
                    expires_at = entry.ExpiresAtUtc
                }).ToArray();
            return Results.Ok(new { sessions });
        }

        if (action == "revoke")
        {
            if (string.IsNullOrWhiteSpace(input.SessionId)
                || !Guid.TryParseExact(input.SessionId, "N", out _))
                return Results.BadRequest();

            var target = user.LauncherAuthSessions.FirstOrDefault(entry =>
                string.Equals(entry.SessionId, input.SessionId, StringComparison.OrdinalIgnoreCase));
            if (target is null)
                return Results.NotFound();

            target.RevokedAtUtc ??= now;
        }
        else
        {
            foreach (var session in user.LauncherAuthSessions)
                session.RevokedAtUtc ??= now;
        }

        // Expiring or revoking a bearer also invalidates a pending game join.
        user.PendingJoinTokenHash = null;
        user.ServerExpiredDate = DateTime.MinValue;
        user.ServerUuid = string.Empty;
        await manager.Users.UpdateUser(user);

        return Results.Ok(new { ok = true });
    }
}
