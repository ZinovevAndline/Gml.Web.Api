using GmlCore.Interfaces.Storage;

namespace Gml.Web.Api.Core.Services;

/// <summary>Public, backward-compatible GML launcher manifest enrichment.</summary>
public static class LauncherPublishedCatalog
{
    public static Dictionary<string, LauncherPublishedVersionDto> Map(
        IReadOnlyDictionary<string, IVersionFile?> versions,
        IReadOnlyDictionary<string, LauncherBinaryReleaseMetadata>? metadata)
    {
        var result = new Dictionary<string, LauncherPublishedVersionDto>();
        foreach (var (rid, version) in versions)
        {
            if (version is null || string.IsNullOrWhiteSpace(version.Guid))
                continue;

            LauncherBinaryReleaseMetadata? matched = null;
            if (metadata is not null && metadata.TryGetValue(rid, out var item)
                && item is not null && item.FileId == version.Guid
                && item.Version == version.Version && item.SizeBytes > 0
                && item.Sha256 is { Length: 64 } && item.Sha256.All(Uri.IsHexDigit))
                matched = item;

            result[rid] = new LauncherPublishedVersionDto
            {
                Version = version.Version,
                Title = version.Title,
                Description = version.Description,
                Guid = version.Guid,
                FileName = matched?.FileName,
                SizeBytes = matched?.SizeBytes,
                Sha256 = matched?.Sha256,
                PublishedAt = matched?.PublishedAt
            };
        }
        return result;
    }
}

public sealed class LauncherPublishedVersionDto
{
    public string Version { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Guid { get; set; } = string.Empty;
    public string? FileName { get; set; }
    public long? SizeBytes { get; set; }
    public string? Sha256 { get; set; }
    public DateTimeOffset? PublishedAt { get; set; }
}

/**
 * Wire-compatible with Gml.Core's persisted metadata JSON.
 * Deliberately local so API builds using the stable NuGet Gml.Core remain valid.
 */
public sealed class LauncherBinaryReleaseMetadata
{
    public string FileId { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public DateTimeOffset PublishedAt { get; set; }
}
