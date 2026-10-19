using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gml.Web.Api.Core.Integrations.Auth;
using GmlCore.Interfaces;
using GmlCore.Interfaces.Auth;
using GmlCore.Interfaces.Enums;
using MapsterMapper;
using Microsoft.Extensions.Caching.Memory;
using Gml.Web.Api.Core.Extensions;

namespace Gml.Web.Api.Core.Handlers;

/// <summary>
/// OAuth-style device approval. A browser sees only flow ID + display code;
/// the 256-bit device secret stays in the desktop process. Only the ANDLINE
/// HMAC control channel is permitted to approve a user identity.
/// </summary>
public static class BrowserLauncherAuthHandler
{
    private sealed class Flow
    {
        public required string SecretHash { get; init; }
        public required string UserCode { get; init; }
        public required string DeviceLabel { get; init; }
        public required string Hwid { get; init; }
        public string? HardwareSummary { get; init; }
        public required DateTimeOffset ExpiresAt { get; init; }
        public required DateTimeOffset CreatedAt { get; init; }
        public string? Username { get; set; }
        public string? Uuid { get; set; }
        public bool Consumed { get; set; }
        public SemaphoreSlim Gate { get; } = new(1, 1);
    }

    private sealed record PollBody(
        [property: System.Text.Json.Serialization.JsonPropertyName("flow_id")] string? FlowId,
        [property: System.Text.Json.Serialization.JsonPropertyName("device_code")] string? DeviceCode);
    private static readonly ConcurrentDictionary<string, Flow> Flows = new();
    private static readonly ConcurrentDictionary<Guid, DateTimeOffset> Revocations = new();
    private static readonly object RateLock = new();

    private static string Digest(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static bool ConstantEquals(string x, string y)
    {
        var left = Encoding.UTF8.GetBytes(x);
        var right = Encoding.UTF8.GetBytes(y);
        return left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    }

    private static bool TryGet(string? id, string? code, out Flow flow)
    {
        flow = null!;
        if (!Guid.TryParseExact(id, "N", out _) || !Flows.TryGetValue(id, out var pending))
            return false;
        if (pending.ExpiresAt <= DateTimeOffset.UtcNow || pending.Consumed)
        {
            Flows.TryRemove(id, out _);
            return false;
        }
        if (!ConstantEquals(pending.UserCode, (code ?? "").ToUpperInvariant()))
            return false;
        flow = pending;
        return true;
    }

    internal static bool IsRevokedSince(Guid account, DateTimeOffset started) =>
        Revocations.TryGetValue(account, out var revokedAt) && started <= revokedAt;

    /// <summary>
    /// Called under the same account stripe as JWT revocation and issuance.
    /// A pending flow cannot mint a fresh token after a password change or
    /// administrator's revoke-all, even if the browser approved earlier.
    /// </summary>
    internal static void CancelPendingForUser(Guid account)
    {
        var now = DateTimeOffset.UtcNow;
        Revocations[account] = now;
        foreach (var item in Flows)
        {
            var flow = item.Value;
            lock (flow)
            {
                if (!Guid.TryParse(flow.Uuid, out var flowOwner) || flowOwner != account)
                    continue;
                flow.Consumed = true;
                Flows.TryRemove(item.Key, out _);
            }
        }
    }

    // Public start is rate-limited and issues no authorization.
    public static async Task<IResult> Start(HttpContext context, IGmlManager manager, IMemoryCache cache)
    {
        if (await manager.Integrations.GetAuthType() != AuthType.Andline)
            return Results.StatusCode(409);
        var configured = await manager.Integrations.GetActiveAuthService();
        if (!AndlineAuthUrl.TryNormalize(configured?.Endpoint, out var siteOrigin))
            return Results.StatusCode(503);

        var remote = context.ParseRemoteAddress()?.ToString()
            ?? context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var now = DateTimeOffset.UtcNow;
        var rateKey = "andline:browser-start:" + remote;
        lock (RateLock)
        {
            var count = cache.TryGetValue<int>(rateKey, out var previous) ? previous : 0;
            if (count >= 12) return Results.StatusCode(429);
            // Expiring cache keys avoid an unbounded map of source IPs.
            cache.Set(rateKey, count + 1, TimeSpan.FromMinutes(1));
        }

        foreach (var item in Flows)
            if (item.Value.ExpiresAt <= now || item.Value.Consumed)
                Flows.TryRemove(item.Key, out _);
        foreach (var item in Revocations)
            if (now - item.Value > TimeSpan.FromMinutes(6))
                Revocations.TryRemove(item.Key, out _);
        if (Flows.Count >= 1200) return Results.StatusCode(429);

        var device = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var id = Guid.NewGuid().ToString("N");
        var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
        var agent = context.Request.Headers.UserAgent.ToString();
        var flow = new Flow
        {
            SecretHash = Digest(device),
            UserCode = code,
            Hwid = context.Request.Headers["X-HWID"].ToString()[..Math.Min(context.Request.Headers["X-HWID"].ToString().Length, 160)],
            DeviceLabel = agent.Length > 160 ? agent[..160] : agent,
            HardwareSummary = context.Request.Headers["X-Andline-Device-Info"].ToString(),
            ExpiresAt = now.AddMinutes(5),
            CreatedAt = now
        };
        Flows[id] = flow;

        context.Response.Headers.CacheControl = "no-store";
        return Results.Ok(new
        {
            flow_id = id,
            device_code = device,
            user_code = code,
            expires_in = 300,
            interval = 3,
            verification_uri = siteOrigin + "/launcher/connect?flow=" + id + "&code=" + code
        });
    }

    /// <summary>HMAC-authenticated ANDLINE website operations only.</summary>
    public static IResult Inspect(string? flowId, string? code)
    {
        if (!TryGet(flowId, code, out var flow)) return Results.NotFound();
        return Results.Ok(new { valid = true, user_code = flow.UserCode, expires_at = flow.ExpiresAt });
    }

    public static IResult Approve(string? flowId, string? code, string? username, string? uuid)
    {
        if (!TryGet(flowId, code, out var flow)
            || !Guid.TryParse(uuid, out var id) || id == Guid.Empty
            || string.IsNullOrWhiteSpace(username)
            || !System.Text.RegularExpressions.Regex.IsMatch(username, @"^[A-Za-z0-9_]{3,16}$"))
            return Results.NotFound();

        lock (flow)
        {
            if (flow.Consumed || flow.ExpiresAt <= DateTimeOffset.UtcNow
                || IsRevokedSince(id, flow.CreatedAt)
                || flow.Uuid is not null) return Results.Conflict();
            flow.Username = username;
            flow.Uuid = id.ToString("D");
        }
        return Results.Ok(new { ok = true });
    }

    public static async Task<IResult> Poll(
        HttpContext context, IGmlManager manager,
        IAccessTokenService tokens, IMapper mapper)
    {
        if (await manager.Integrations.GetAuthType() != AuthType.Andline)
            return Results.StatusCode(409);
        if (context.Request.ContentLength is > 2048) return Results.BadRequest();
        PollBody? input;
        try
        {
            input = await JsonSerializer.DeserializeAsync<PollBody>(
                context.Request.Body,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true },
                context.RequestAborted);
        }
        catch (JsonException) { return Results.BadRequest(); }
        if (input is null || !Guid.TryParseExact(input.FlowId, "N", out _)
            || string.IsNullOrWhiteSpace(input.DeviceCode)
            || input.DeviceCode.Length > 128
            || !Flows.TryGetValue(input.FlowId, out var flow))
            return Results.Unauthorized();

        if (flow.ExpiresAt <= DateTimeOffset.UtcNow || flow.Consumed)
        {
            Flows.TryRemove(input.FlowId, out _);
            return Results.StatusCode(410);
        }
        if (!ConstantEquals(flow.SecretHash, Digest(input.DeviceCode)))
            return Results.Unauthorized();

        await flow.Gate.WaitAsync(context.RequestAborted);
        try
        {
            if (flow.Consumed || flow.ExpiresAt <= DateTimeOffset.UtcNow
                || flow.Uuid is not null && Guid.TryParse(flow.Uuid, out var accountId)
                    && IsRevokedSince(accountId, flow.CreatedAt))
                return Results.StatusCode(410);
            if (flow.Uuid is null || flow.Username is null)
                return Results.Accepted(value: new { status = "pending" });
            // All identity claims came from the site's authenticated HMAC
            // channel, not a browser redirect or launcher-supplied username.
            var result = await AuthIntegrationHandler.CompleteBrowserSignInAsync(
                context, manager, tokens, mapper,
                flow.Username, flow.Uuid, flow.Hwid, flow.DeviceLabel,
                flow.HardwareSummary, flow.CreatedAt);
            if (result is null) return Results.StatusCode(503);
            flow.Consumed = true;
            Flows.TryRemove(input.FlowId, out _);
            return result;
        }
        finally { flow.Gate.Release(); }
    }
}
