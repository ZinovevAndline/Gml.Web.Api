using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gml.Models.User;
using GmlCore.Interfaces;
using Gml.Web.Api.Core.Hubs;
using Microsoft.AspNetCore.SignalR;
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
        IHubContext<LauncherHub> hub,
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

        // Serialize revocations with sign-in and last-seen updates, otherwise
        // an activity heartbeat can overwrite a recently revoked bearer.
        var stripe = action == "list" ? null : AuthIntegrationHandler.SessionLockForUuid(playerUuid);
        if (stripe is not null) await stripe.WaitAsync(context.RequestAborted);
        try
        {
            // Old GML data can contain multiple Login primary keys associated
            // with one canonical player UUID. A single GetUserByUuid() returns the
            // first row (which may have no current tokens), hiding newly created
            // launcher sessions from ANDLINE and making revocation incomplete.
            var users = (await manager.Users.GetUsers())
                .OfType<AuthUser>()
                .Where(item => Guid.TryParse(item.Uuid, out var id) && id == playerUuid)
                .ToArray();
            if (users.Length == 0)
                return action == "list" ? Results.Ok(new { sessions = Array.Empty<object>() }) : Results.NotFound();
    
            var now = DateTime.UtcNow;
    
            if (action == "list")
            {
                var sessions = users.SelectMany(item => item.LauncherAuthSessions ?? [])
                    .Where(entry => entry.RevokedAtUtc is null && entry.ExpiresAtUtc > now)
                    .GroupBy(entry => entry.SessionId, StringComparer.OrdinalIgnoreCase)
                    .Select(group => group.OrderByDescending(entry => entry.CreatedAtUtc).First())
                    .OrderByDescending(entry => entry.CreatedAtUtc)
                    .Select(entry => new
                    {
                        session_id = entry.SessionId,
                        device_name = entry.DeviceName,
                        ip_address = entry.IpAddress,
                        last_seen_at = entry.LastSeenAtUtc ?? entry.CreatedAtUtc,
                        created_at = entry.CreatedAtUtc,
                        expires_at = entry.ExpiresAtUtc
                    }).ToArray();
                return Results.Ok(new { sessions });
            }
    
            if (action == "revoke"
                && (string.IsNullOrWhiteSpace(input.SessionId)
                    || !Guid.TryParseExact(input.SessionId, "N", out _)))
                return Results.BadRequest();
    
            var found = action == "revoke-all";
            var revokedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var user in users)
            {
                user.LauncherAuthSessions ??= [];
                var changed = false;
                if (action == "revoke")
                {
                    foreach (var entry in user.LauncherAuthSessions.Where(entry =>
                        string.Equals(entry.SessionId, input!.SessionId, StringComparison.OrdinalIgnoreCase)))
                    {
                        found = true;
                        if (entry.RevokedAtUtc is null)
                        {
                            entry.RevokedAtUtc = now;
                            revokedHashes.Add(entry.TokenHash);
                            changed = true;
                        }
                    }
                }
                else
                {
                    foreach (var entry in user.LauncherAuthSessions)
                    {
                        if (entry.RevokedAtUtc is not null) continue;
                        entry.RevokedAtUtc = now;
                        revokedHashes.Add(entry.TokenHash);
                        changed = true;
                    }
                }
    
                // Invalidate an in-flight game join for every matching account row
                // if and only if a session on that row was revoked.
                if (!changed) continue;
                user.PendingJoinTokenHash = null;
                user.ServerExpiredDate = DateTime.MinValue;
                user.ServerUuid = string.Empty;
                await manager.Users.UpdateUser(user);
            }
    
            if (!found) return Results.NotFound();
            foreach (var hash in revokedHashes)
            {
                try { await hub.Clients.Group(LauncherHub.SessionGroup(hash)).SendAsync("SessionRevoked"); }
                catch (Exception) { /* The persisted revoke wins; clients also verify JWT periodically. */ }
            }
            return Results.Ok(new { ok = true });
        }
        finally
        {
            stripe?.Release();
        }
    }
}
