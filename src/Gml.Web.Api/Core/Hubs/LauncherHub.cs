using Gml.Web.Api.Core.Hubs.Controllers;
using Gml.Models.User;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using GmlCore.Interfaces;
using Microsoft.AspNetCore.SignalR;

namespace Gml.Web.Api.Core.Hubs;

public class LauncherHub : BaseHub
{
    private static IDisposable? _profilesChangedEvent;
    private readonly IGmlManager _gmlManager;
    private readonly HubEvents _hubEvents;
    private readonly PlayersController _playerController;

    public LauncherHub(
        IGmlManager gmlManager,
        PlayersController playerController,
        HubEvents hubEvents)
    {
        _gmlManager = gmlManager;
        _hubEvents = hubEvents;
        _playerController = playerController;

        _profilesChangedEvent ??= gmlManager.Profiles.ProfilesChanged.Subscribe(_ =>
        {
            foreach (var connection in _playerController.LauncherInfos.Values.Select(c => c.Connection)
                         .OfType<ISingleClientProxy>())
            {
                connection?.SendAsync("RefreshProfiles");
            }
        });
    }

    // A distinct group per signed bearer, never per nickname or IP.
    public static string SessionGroup(string tokenHash) => "launcher-session:" + tokenHash;

    public void ConfirmLauncherHash(string hash)
    {
        _playerController.ConfirmLauncherHash(Context.ConnectionId, hash);
    }

    public override async Task OnConnectedAsync()
    {
        // JWT signature verification alone is insufficient after revocation.
        // Require the bearer to be present in the active server-side session table.
        var request = Context.GetHttpContext()?.Request;
        var authorization = request?.Headers.Authorization.ToString();
        var token = authorization is not null
            && authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? authorization["Bearer ".Length..].Trim()
            : request?.Query["access_token"].ToString(); // Legacy clients only.
        var expectedUuid = Context.User?.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(token)
            || string.IsNullOrWhiteSpace(expectedUuid)
            || await _gmlManager.Users.GetUserByAccessToken(token) is not AuthUser active
            || !Guid.TryParse(active.Uuid, out var activeUuid)
            || !Guid.TryParse(expectedUuid, out var claimUuid)
            || activeUuid != claimUuid)
        {
            Context.Abort();
            return;
        }

        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
        await Groups.AddToGroupAsync(Context.ConnectionId, SessionGroup(hash));
        await _playerController.AddLauncherConnection(Context.ConnectionId, Clients.Caller, Context.User!);
        await base.OnConnectedAsync();
    }

    public override Task OnDisconnectedAsync(Exception? exception)
    {
        _playerController.RemoveLauncherConnection(Context.ConnectionId);

        return base.OnDisconnectedAsync(exception);
    }
}
