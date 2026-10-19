using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gml.Models.Sessions;
using Gml.Models.User;
using MapsterMapper;
using FluentValidation;
using Gml.Dto.Integration;
using Gml.Dto.Messages;
using Gml.Dto.Player;
using Gml.Dto.User;
using Gml.Web.Api.Core.Extensions;
using Gml.Web.Api.Core.Hubs;
using Microsoft.AspNetCore.SignalR;
using Gml.Web.Api.Core.Integrations.Auth;
using GmlCore.Interfaces;
using GmlCore.Interfaces.Auth;
using GmlCore.Interfaces.Enums;
using GmlCore.Interfaces.User;
using Microsoft.AspNetCore.Authorization;
using Newtonsoft.Json;

namespace Gml.Web.Api.Core.Handlers;

public class AuthIntegrationHandler : IAuthIntegrationHandler
{
    // Fixed-size striped locks: no unbounded dictionary for untrusted logins.
    private static readonly SemaphoreSlim[] SessionLocks = Enumerable.Range(0, 128)
        .Select(_ => new SemaphoreSlim(1, 1)).ToArray();

    internal static SemaphoreSlim SessionLockForUuid(Guid uuid)
    {
        var identity = uuid.ToString("N");
        return SessionLocks[(StringComparer.Ordinal.GetHashCode(identity) & int.MaxValue) % SessionLocks.Length];
    }

    private static async Task<IResult?> HandleCommonAuthValidation(HttpContext context,
        IGmlManager gmlManager,
        AuthType authType,
        string hwid)
    {
        var userAgent = context.Request.Headers["User-Agent"].ToString();

        if (string.IsNullOrWhiteSpace(userAgent) || string.IsNullOrWhiteSpace(hwid))
            return Results.BadRequest(ResponseMessage.Create(
                "Не удалось определить устройство, с которого произошла авторизация",
                HttpStatusCode.BadRequest));

        return null;
    }

    private static async Task<IResult> HandleAuthenticatedUser(HttpContext context, IGmlManager gmlManager,
        IMapper mapper,
        IUser player,
        string userAgent)
    {
        if (player.IsBanned)
        {
            return Results.BadRequest(ResponseMessage.Create(
                "Пользователь заблокирован!",
                HttpStatusCode.BadRequest));
        }

        var hostValue = context.Request.Headers["X-Forwarded-Host"].FirstOrDefault();
        var hostScheme = context.Request.Headers["X-Forwarded-Scheme"].FirstOrDefault();
        string? host = null;
        if (!string.IsNullOrWhiteSpace(hostValue) && !string.IsNullOrEmpty(hostScheme))
        {
            host = $"{hostScheme}://{hostValue}";
        }

        await gmlManager.Profiles.CreateUserSessionAsync(null, player, host);

        // player.TextureSkinUrl = (await gmlManager.Integrations.GetSkinServiceAsync())
        //     .Replace("{userName}", player.Name)
        //     .Replace("{userUuid}", player.Uuid);
        //
        // player.TextureCloakUrl = (await gmlManager.Integrations.GetCloakServiceAsync())
        //     .Replace("{userName}", player.Name)
        //     .Replace("{userUuid}", player.Uuid);

        return Results.Ok(ResponseMessage.Create(
            mapper.Map<PlayerReadDto>(player),
            string.Empty,
            HttpStatusCode.OK));
    }

    private static IResult HandleAuthException(Exception exception, bool isHttpRequestException)
    {
        // Never send internal endpoint URLs, exception stacks or upstream
        // implementation details to the player. Distinguish a temporary
        // upstream outage from malformed player credentials.
        Console.Error.WriteLine("[GML auth] " + exception.GetType().Name);
        var message = isHttpRequestException
            ? "Сервис авторизации временно недоступен. Повторите попытку позже."
            : "Не удалось завершить вход. Попробуйте ещё раз.";
        return Results.Json(
            ResponseMessage.Create(message, HttpStatusCode.ServiceUnavailable),
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    public static async Task<IResult> Auth(
        HttpContext context,
        IGmlManager gmlManager,
        IAccessTokenService accessTokenService,
        IMapper mapper,
        IValidator<BaseUserPassword> validator,
        IAuthService authService,
        BaseUserPassword authDto)
    {
        try
        {
            var result = await validator.ValidateAsync(authDto);
            if (!result.IsValid)
                return Results.BadRequest(ResponseMessage.Create(result.Errors, "Ошибка валидации",
                    HttpStatusCode.BadRequest));

            var hwid = context.Request.Headers["X-HWID"].ToString();
            var userAgent = context.Request.Headers["User-Agent"].ToString();
            var authType = await gmlManager.Integrations.GetAuthType();

            var validationResult = await HandleCommonAuthValidation(context, gmlManager, authType, hwid);

            if (validationResult is not null)
                return validationResult;

            if (authType is not AuthType.Any && string.IsNullOrEmpty(authDto.Password))
            {
                return Results.BadRequest(ResponseMessage.Create(
                    "Не указан пароль при авторизации!",
                    HttpStatusCode.BadRequest));
            }

            var authResult =
                await authService.CheckAuth(authDto.Login, authDto.Password, authType, hwid, authDto.TwoFactorCode);

            if (authResult.TwoFactorEnabled && string.IsNullOrEmpty(authDto.TwoFactorCode))
            {
                return Results.BadRequest(ResponseMessage.Create(
                    authResult.Message ?? "Введите код из приложения 2FA",
                    HttpStatusCode.Unauthorized));
            }

            if (!authResult.IsSuccess)
                return Results.BadRequest(ResponseMessage.Create(
                    authResult.Message ?? "Неверный логин или пароль",
                    HttpStatusCode.Unauthorized));

            // A single SQLite JSON row contains all sessions for one player.
            // Serialize concurrent logins for the same canonical UUID so a
            // second device cannot overwrite the first device's new session.
            var identity = Guid.TryParse(authResult.Uuid, out var canonical)
                ? canonical.ToString("N")
                : (authResult.Login ?? authDto.Login).ToUpperInvariant();
            var stripe = SessionLocks[(StringComparer.Ordinal.GetHashCode(identity) & int.MaxValue) % SessionLocks.Length];
            await stripe.WaitAsync(context.RequestAborted);
            IUser player;
            try
            {
                player = await gmlManager.Users.GetAuthData(
                    authResult.Login ?? authDto.Login,
                    authDto.Password,
                    userAgent,
                    context.Request.Protocol,
                    context.ParseRemoteAddress(),
                    authResult.Uuid,
                    hwid,
                    authResult.IsSlim);

            // Register an individual, revocable launcher session instead of replacing
            // the account's sole bearer token on each new sign-in.
            if (player is not AuthUser launcherUser)
                return Results.Unauthorized();

            IssueLauncherJwt(accessTokenService, launcherUser, hwid,
                userAgent, context.ParseRemoteAddress()?.ToString(),
                context.Request.Headers["X-Andline-Device-Info"].ToString());

            // Persist the authorization decision before fetching optional skins;
            // skin providers may be unavailable and must not lose a live session.
                await gmlManager.Users.UpdateUser(player);
                // The optional texture update also writes the player JSON;
                // keep it inside this lock or it could overwrite a new login.
                return await HandleAuthenticatedUser(context, gmlManager, mapper, player, userAgent);
            }
            finally
            {
                stripe.Release();
            }
        }
        catch (HttpRequestException exception)
        {
            gmlManager.BugTracker.CaptureException(exception);
            return HandleAuthException(exception, true);
        }
        catch (JsonReaderException exception)
        {
            gmlManager.BugTracker.CaptureException(exception);
            var humanException =
                new Exception(
                    "Не удалось прочитать ответ сервера, возможно сайт вернул html, вместо json, или неверно настроен сервер авторизации.");
            return HandleAuthException(humanException, true);
        }
        catch (Exception exception)
        {
            gmlManager.BugTracker.CaptureException(exception);
            return HandleAuthException(exception, false);
        }
    }

    public static async Task<IResult> AuthWithToken(
        HttpContext context,
        IGmlManager gmlManager,
        IMapper mapper,
        IAccessTokenService accessTokenService,
        IAuthService authService,
        BaseUserPassword authDto)
    {
        try
        {
            var authType = await gmlManager.Integrations.GetAuthType();

            if (authType is not AuthType.Any && string.IsNullOrEmpty(authDto.AccessToken))
            {
                return Results.BadRequest(ResponseMessage.Create(
                    "Не был передан AccessToken",
                    HttpStatusCode.BadRequest));
            }

            var user = await gmlManager.Users.GetUserByAccessToken(authDto.AccessToken);
            var userAgent = context.Request.Headers["User-Agent"].ToString();

            if (user is not null && !user.IsBanned && accessTokenService.ValidateToken(authDto.AccessToken))
            {
                return await HandleAuthenticatedUser(context, gmlManager, mapper, user, userAgent);
            }

            return Results.BadRequest(ResponseMessage.Create(
                "Неверный логин или пароль",
                HttpStatusCode.Unauthorized));
        }
        catch (HttpRequestException exception)
        {
            return HandleAuthException(exception, true);
        }
        catch (Exception exception)
        {
            return HandleAuthException(exception, false);
        }
    }


    /// <summary>Single JWT issuer shared by password and browser device sign-in.</summary>
    private static void IssueLauncherJwt(
        IAccessTokenService tokenService, AuthUser user, string hwid,
        string deviceName, string? remoteIp, string? requestDeviceSummary)
    {
        var now = DateTime.UtcNow;
        var token = tokenService.GenerateAccessToken(
            user.Uuid, user.Name, user.Name,
            ["Player"], ["profiles.view", "integrations.news.view"], 60 * 24 * 10);
        user.LauncherAuthSessions ??= [];
        // Keep a limited 90-day security history, including expired and
        // explicitly revoked sessions, for legitimate support investigations.
        user.LauncherAuthSessions.RemoveAll(entry => entry.CreatedAtUtc < now.AddDays(-90));
        user.LauncherAuthSessions.Add(new LauncherAuthSession
        {
            SessionId = Guid.NewGuid().ToString("N"),
            TokenHash = HashToken(token),
            DeviceHash = HashToken(hwid),
            DeviceName = deviceName.Length > 160 ? deviceName[..160] : deviceName,
            IpAddress = remoteIp,
            LastSeenAtUtc = now,
            CreatedAtUtc = now,
            ExpiresAtUtc = now.AddDays(10)
        });
        var latest = user.LauncherAuthSessions[^1];
        ApplyHardwareSummary(latest, requestDeviceSummary);
        // Protect the SQLite account row from unbounded historical growth.
        if (user.LauncherAuthSessions.Count > 240)
            user.LauncherAuthSessions = user.LauncherAuthSessions
                .OrderByDescending(entry => entry.CreatedAtUtc).Take(240).ToList();
        user.AccessToken = token;
    }

    private static void ApplyHardwareSummary(LauncherAuthSession session, string? value)
    {
        // The client can describe its hardware, but never use these attributes
        // for authorization. Reject oversized/malformed metadata without
        // interrupting a legitimate login.
        if (string.IsNullOrWhiteSpace(value) || value.Length > 2200) return;
        try
        {
            var bytes = Convert.FromBase64String(value);
            if (bytes.Length > 1600) return;
            using var doc = JsonDocument.Parse(bytes);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return;
            string? Get(string key, int max)
            {
                if (!doc.RootElement.TryGetProperty(key, out var property)
                    || property.ValueKind != JsonValueKind.String) return null;
                var text = property.GetString()?.Trim();
                if (string.IsNullOrEmpty(text)) return null;
                // Discard control codes, line breaks and potentially sensitive
                // URL-like strings; only display descriptive hardware names.
                text = new string(text.Where(c => !char.IsControl(c)).ToArray());
                return text.Length > max ? text[..max] : text;
            }
            int? Numeric(string key, int max)
            {
                return doc.RootElement.TryGetProperty(key, out var property)
                    && property.ValueKind == JsonValueKind.Number
                    && property.TryGetInt32(out var number) && number > 0 && number <= max
                    ? number : null;
            }
            session.OperatingSystem = Get("os", 90);
            session.Architecture = Get("architecture", 30);
            session.Processor = Get("cpu", 120);
            session.Graphics = Get("gpu", 120);
            session.LauncherVersion = Get("launcher_version", 30);
            session.MemoryGb = Numeric("memory_gb", 2048);
            session.ProcessorCores = Numeric("logical_processors", 1024);
        }
        catch (Exception) { /* Optional device details must never block login. */ }
    }

    // Only BrowserLauncherAuthHandler calls this after the HMAC-authenticated
    // site decision and proof of the original 256-bit device secret.
    internal static async Task<IResult?> CompleteBrowserSignInAsync(
        HttpContext context, IGmlManager manager, IAccessTokenService tokens,
        IMapper mapper, string username, string uuid, string hwid, string device, string? hardwareSummary)
    {
        if (!Guid.TryParse(uuid, out var identity)) return null;
        var stripe = SessionLockForUuid(identity);
        await stripe.WaitAsync(context.RequestAborted);
        try
        {
            // GetAuthData creates or reconciles the canonical GML player record.
            var player = await manager.Users.GetAuthData(
                username, string.Empty, device, context.Request.Protocol,
                context.ParseRemoteAddress(), uuid, hwid, false);
            if (player is not AuthUser authUser || authUser.IsBanned
                || !Guid.TryParse(authUser.Uuid, out var actual) || actual != identity)
                return null;
            IssueLauncherJwt(tokens, authUser, hwid, device, context.ParseRemoteAddress()?.ToString(),
                context.Request.Headers["X-Andline-Device-Info"].ToString());
            await manager.Users.UpdateUser(authUser);
            return await HandleAuthenticatedUser(context, manager, mapper, authUser, device);
        }
        finally { stripe.Release(); }
    }

    private static string HashToken(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static async Task<AuthUser?> GetCurrentLauncherUser(
        HttpContext context, IGmlManager manager, IAccessTokenService tokens)
    {
        var authorization = context.Request.Headers.Authorization.ToString();
        if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return null;

        var bearer = authorization["Bearer ".Length..].Trim();
        if (!tokens.ValidateToken(bearer))
            return null;

        return await manager.Users.GetUserByAccessToken(bearer) as AuthUser;
    }

    // These endpoints are restricted to the current launcher's signed JWT.
    // The caller can only list or revoke sessions belonging to its own identity.
    public static async Task<IResult> GetLauncherSessions(
        HttpContext context, IGmlManager manager, IAccessTokenService tokens)
    {
        var user = await GetCurrentLauncherUser(context, manager, tokens);
        if (user is null)
            return Results.Unauthorized();

        var bearer = context.Request.Headers.Authorization.ToString()["Bearer ".Length..].Trim();
        var currentHash = HashToken(bearer);
        var now = DateTime.UtcNow;
        var sessions = (user.LauncherAuthSessions ?? [])
            .Where(entry => entry.RevokedAtUtc is null && entry.ExpiresAtUtc > now)
            .OrderByDescending(entry => entry.CreatedAtUtc)
            .Select(entry => new
            {
                entry.SessionId,
                entry.DeviceName,
                entry.IpAddress,
                entry.LastSeenAtUtc,
                entry.CreatedAtUtc,
                entry.ExpiresAtUtc,
                IsCurrent = entry.TokenHash == currentHash
            }).ToList();

        return Results.Ok(ResponseMessage.Create(sessions, string.Empty, HttpStatusCode.OK));
    }

    public static async Task<IResult> RevokeLauncherSession(
        HttpContext context, IGmlManager manager, IAccessTokenService tokens, IHubContext<LauncherHub> hub, string sessionId)
    {
        var user = await GetCurrentLauncherUser(context, manager, tokens);
        if (user is null)
            return Results.Unauthorized();

        if (!Guid.TryParse(user.Uuid, out var uuid)) return Results.Unauthorized();
        var stripe = SessionLockForUuid(uuid);
        await stripe.WaitAsync(context.RequestAborted);
        try
        {
            user = await GetCurrentLauncherUser(context, manager, tokens);
            if (user is null) return Results.Unauthorized();
            var target = user.LauncherAuthSessions?.FirstOrDefault(entry => entry.SessionId == sessionId);
            if (target is null)
                return Results.NotFound(ResponseMessage.Create("Сессия не найдена", HttpStatusCode.NotFound));

            target.RevokedAtUtc ??= DateTime.UtcNow;
            user.PendingJoinTokenHash = null;
            user.ServerExpiredDate = DateTime.MinValue;
            user.ServerUuid = string.Empty;
            await manager.Users.UpdateUser(user);
            await NotifyRevokedAsync(hub, new[] { target.TokenHash });
            return Results.Ok(ResponseMessage.Create("Доступ устройства отключён", HttpStatusCode.OK));
        }
        finally
        {
            stripe.Release();
        }
    }

    public static async Task<IResult> RevokeAllLauncherSessions(
        HttpContext context, IGmlManager manager, IAccessTokenService tokens, IHubContext<LauncherHub> hub)
    {
        var user = await GetCurrentLauncherUser(context, manager, tokens);
        if (user is null)
            return Results.Unauthorized();

        if (!Guid.TryParse(user.Uuid, out var uuid)) return Results.Unauthorized();
        var stripe = SessionLockForUuid(uuid);
        await stripe.WaitAsync(context.RequestAborted);
        try
        {
            user = await GetCurrentLauncherUser(context, manager, tokens);
            if (user is null) return Results.Unauthorized();
            var now = DateTime.UtcNow;
            var revokedHashes = (user.LauncherAuthSessions ?? [])
                .Where(entry => entry.RevokedAtUtc is null).Select(entry => entry.TokenHash).ToArray();
            foreach (var entry in user.LauncherAuthSessions ?? [])
                entry.RevokedAtUtc ??= now;

            user.PendingJoinTokenHash = null;
            user.ServerExpiredDate = DateTime.MinValue;
            user.ServerUuid = string.Empty;
            await manager.Users.UpdateUser(user);
            await NotifyRevokedAsync(hub, revokedHashes);
            return Results.Ok(ResponseMessage.Create("Доступ на всех устройствах отключён", HttpStatusCode.OK));
        }
        finally
        {
            stripe.Release();
        }
    }

    /// <summary>
    /// Persist real launcher activity at most once per minute. Re-fetch the
    /// token under the same per-player lock as sign-in to prevent a stale
    /// session snapshot from replacing a concurrent newly issued token.
    /// </summary>
    public static async Task TouchLauncherSessionAsync(
        IGmlManager manager, AuthUser validatedUser, string token)
    {
        if (!Guid.TryParse(validatedUser.Uuid, out var uuid)) return;
        var hash = HashToken(token);
        var now = DateTime.UtcNow;
        var entry = validatedUser.LauncherAuthSessions?.FirstOrDefault(item =>
            item.RevokedAtUtc is null && item.ExpiresAtUtc > now
            && string.Equals(item.TokenHash, hash, StringComparison.OrdinalIgnoreCase));
        if (entry is null || entry.LastSeenAtUtc is { } last && now - last < TimeSpan.FromMinutes(1))
            return;

        var stripe = SessionLockForUuid(uuid);
        await stripe.WaitAsync();
        try
        {
            var current = await manager.Users.GetUserByAccessToken(token) as AuthUser;
            var active = current?.LauncherAuthSessions?.FirstOrDefault(item =>
                item.RevokedAtUtc is null && item.ExpiresAtUtc > DateTime.UtcNow
                && string.Equals(item.TokenHash, hash, StringComparison.OrdinalIgnoreCase));
            if (active is null || active.LastSeenAtUtc is { } seen
                && DateTime.UtcNow - seen < TimeSpan.FromMinutes(1))
                return;
            active.LastSeenAtUtc = DateTime.UtcNow;
            await manager.Users.UpdateUser(current!);
        }
        finally
        {
            stripe.Release();
        }
    }

    /// <summary>Revoke only the device whose signed bearer accompanies this request.</summary>
    public static async Task<IResult> RevokeCurrentLauncherSession(
        HttpContext context, IGmlManager manager, IAccessTokenService tokens, IHubContext<LauncherHub> hub)
    {
        var bearer = context.Request.Headers.Authorization.ToString();
        if (!bearer.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return Results.Unauthorized();

        var token = bearer["Bearer ".Length..].Trim();
        if (!tokens.ValidateToken(token))
            return Results.Unauthorized();

        var user = await manager.Users.GetUserByAccessToken(token) as AuthUser;
        if (user is null)
            return Results.Unauthorized();

        if (!Guid.TryParse(user.Uuid, out var uuid)) return Results.Unauthorized();
        var stripe = SessionLockForUuid(uuid);
        await stripe.WaitAsync(context.RequestAborted);
        try
        {
            user = await manager.Users.GetUserByAccessToken(token) as AuthUser;
            if (user is null) return Results.Unauthorized();

            var hash = HashToken(token);
            var target = user.LauncherAuthSessions?.FirstOrDefault(entry =>
                entry.RevokedAtUtc is null && entry.ExpiresAtUtc > DateTime.UtcNow
                && string.Equals(entry.TokenHash, hash, StringComparison.OrdinalIgnoreCase));
            if (target is null) return Results.Unauthorized();

            target.RevokedAtUtc = DateTime.UtcNow;
            user.PendingJoinTokenHash = null;
            user.ServerExpiredDate = DateTime.MinValue;
            user.ServerUuid = string.Empty;
            await manager.Users.UpdateUser(user);
            await NotifyRevokedAsync(hub, new[] { target.TokenHash });
            return Results.Ok(new { ok = true });
        }
        finally
        {
            stripe.Release();
        }
    }

    private static async Task NotifyRevokedAsync(IHubContext<LauncherHub> hub, IEnumerable<string> hashes)
    {
        foreach (var hash in hashes.Where(h => !string.IsNullOrEmpty(h)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try { await hub.Clients.Group(LauncherHub.SessionGroup(hash)).SendAsync("SessionRevoked"); }
            catch (Exception) { /* Durable server-side revocation remains enforced. */ }
        }
    }

    [Authorize]
    public static async Task<IResult> GetIntegrationServices(IGmlManager gmlManager, IMapper mapper)
    {
        var authServices = await gmlManager.Integrations.GetAuthServices();

        return Results.Ok(ResponseMessage.Create(mapper.Map<List<AuthServiceReadDto>>(authServices), string.Empty,
            HttpStatusCode.OK));
    }

    [Authorize]
    public static async Task<IResult> GetAuthService(IGmlManager gmlManager, IMapper mapper)
    {
        var activeAuthService = await gmlManager.Integrations.GetActiveAuthService();

        return activeAuthService == null
            ? Results.NotFound(ResponseMessage.Create("Не настроен сервис для авторизации", HttpStatusCode.NotFound))
            : Results.Ok(ResponseMessage.Create(mapper.Map<AuthServiceReadDto>(activeAuthService), string.Empty,
                HttpStatusCode.OK));
    }

    [Authorize]
    public static async Task<IResult> SetAuthService(
        IGmlManager gmlManager,
        IValidator<IntegrationUpdateDto> validator,
        IntegrationUpdateDto updateDto)
    {
        var result = await validator.ValidateAsync(updateDto);

        if (!result.IsValid)
            return Results.BadRequest(ResponseMessage.Create(result.Errors, "Ошибка валидации",
                HttpStatusCode.BadRequest));

        var service = await gmlManager.Integrations.GetAuthService(updateDto.AuthType);

        if (service == null)
            service = (await gmlManager.Integrations.GetAuthServices()).FirstOrDefault(c =>
                c.AuthType == updateDto.AuthType);

        if (service == null) return Results.NotFound();

        // Normalize the ANDLINE provider to the origin; never persist a
        // manually entered authentication path or credentials.
        service.Endpoint = updateDto.AuthType == AuthType.Andline
            && AndlineAuthUrl.TryNormalize(updateDto.Endpoint, out var origin)
            ? origin : updateDto.Endpoint;

        await gmlManager.Integrations.SetActiveAuthService(service);

        return Results.Ok(ResponseMessage.Create("Сервис авторизации успешно обновлен", HttpStatusCode.OK));
    }

    [Authorize]
    public static async Task<IResult> RemoveAuthService(IGmlManager gmlManager)
    {
        await gmlManager.Integrations.SetActiveAuthService(null);

        return Results.Ok(ResponseMessage.Create("Сервис авторизации успешно удален", HttpStatusCode.OK));
    }
}
