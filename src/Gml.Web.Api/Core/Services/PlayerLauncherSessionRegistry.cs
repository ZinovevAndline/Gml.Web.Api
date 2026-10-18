using System.Security.Cryptography;
using System.Text;
using Gml.Web.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace Gml.Web.Api.Core.Services;

/// <summary>
/// Database is the authority for launcher token revocation. A valid JWT alone
/// must not re-authenticate a session that has been revoked.
/// </summary>
public sealed class PlayerLauncherSessionRegistry(DatabaseContext db)
{
    public static string Digest(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    public async Task CreateAsync(string uuid, string signedToken, string? hwid,
        string? userAgent, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(uuid) || string.IsNullOrWhiteSpace(signedToken))
            throw new ArgumentException("A verified player and signed access token are required");

        var now = DateTime.UtcNow;
        var item = new PlayerLauncherSession
        {
            PlayerUuid = uuid.ToLowerInvariant(),
            TokenHash = Digest(signedToken),
            DeviceHash = Digest(hwid ?? string.Empty),
            DeviceLabel = string.IsNullOrWhiteSpace(userAgent) ? "GML Launcher"
                : userAgent.Length > 96 ? userAgent[..96] : userAgent,
            CreatedAtUtc = now,
            LastSeenAtUtc = now,
            ExpiresAtUtc = now.AddDays(10),
        };
        db.PlayerLauncherSessions.Add(item);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<PlayerLauncherSession?> ResolveAsync(
        string signedToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(signedToken)) return null;
        var hash = Digest(signedToken);
        var now = DateTime.UtcNow;
        return await db.PlayerLauncherSessions.AsNoTracking().FirstOrDefaultAsync(
            x => x.TokenHash == hash && x.RevokedAtUtc == null && x.ExpiresAtUtc > now,
            cancellationToken);
    }

    public async Task<IReadOnlyList<PlayerLauncherSession>> ListAsync(
        string playerUuid, CancellationToken cancellationToken = default)
    {
        var uuid = playerUuid.ToLowerInvariant();
        return await db.PlayerLauncherSessions.AsNoTracking()
            .Where(x => x.PlayerUuid == uuid && x.RevokedAtUtc == null && x.ExpiresAtUtc > DateTime.UtcNow)
            .OrderByDescending(x => x.CreatedAtUtc)
            .Take(100).ToListAsync(cancellationToken);
    }

    public async Task<bool> RevokeAsync(string playerUuid, Guid id,
        CancellationToken cancellationToken = default)
    {
        var uuid = playerUuid.ToLowerInvariant();
        return await db.PlayerLauncherSessions
            .Where(x => x.PlayerUuid == uuid && x.Id == id && x.RevokedAtUtc == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAtUtc, DateTime.UtcNow),
                cancellationToken) > 0;
    }

    public async Task<int> RevokeAllAsync(string playerUuid,
        CancellationToken cancellationToken = default)
    {
        var uuid = playerUuid.ToLowerInvariant();
        return await db.PlayerLauncherSessions
            .Where(x => x.PlayerUuid == uuid && x.RevokedAtUtc == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAtUtc, DateTime.UtcNow),
                cancellationToken);
    }
}
