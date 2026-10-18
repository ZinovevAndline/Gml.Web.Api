namespace Gml.Web.Api.Data;

/// <summary>
/// One revocable GML launcher authentication grant, identified by a random ID
/// and the SHA-256 digest of the actual signed player access token.
/// Raw access tokens and hardware IDs are never stored.
/// </summary>
public sealed class PlayerLauncherSession
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string PlayerUuid { get; set; } = "";
    public string TokenHash { get; set; } = "";
    public string DeviceHash { get; set; } = "";
    public string DeviceLabel { get; set; } = "GML Launcher";
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
}
