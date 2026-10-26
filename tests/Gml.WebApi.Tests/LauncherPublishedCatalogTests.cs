using Gml.Domains.Launcher;
using Gml.Web.Api.Core.Services;
using GmlCore.Interfaces.Storage;

namespace Gml.WebApi.Tests;

public class LauncherPublishedCatalogTests
{
    [Test]
    public void MatchingFileMetadataAppearsAlongsideLegacyFields()
    {
        var version = new LauncherVersion
        {
            Version = "5.1", Title = "Release", Description = "Notes", Guid = "file-one"
        };
        var versions = new Dictionary<string, IVersionFile?> { ["win-x64"] = version };
        var publishedAt = new DateTimeOffset(2026, 10, 26, 10, 0, 0, TimeSpan.Zero);
        var metadata = new Dictionary<string, LauncherBinaryReleaseMetadata>
        {
            ["win-x64"] = new()
            {
                FileId = "file-one", Version = "5.1", FileName = "ANDLINE.Launcher.exe",
                SizeBytes = 1080, Sha256 = new string('a', 64), PublishedAt = publishedAt
            }
        };

        var item = LauncherPublishedCatalog.Map(versions, metadata)["win-x64"];
        Assert.Multiple(() =>
        {
            Assert.That(item.Guid, Is.EqualTo("file-one"));
            Assert.That(item.Version, Is.EqualTo("5.1"));
            Assert.That(item.Description, Is.EqualTo("Notes"));
            Assert.That(item.FileName, Is.EqualTo("ANDLINE.Launcher.exe"));
            Assert.That(item.SizeBytes, Is.EqualTo(1080L));
            Assert.That(item.Sha256, Is.EqualTo(new string('a', 64)));
            Assert.That(item.PublishedAt, Is.EqualTo(publishedAt));
        });
    }

    [Test]
    public void LegacyOrMismatchedMetadataIsNeverPresentedAsVerified()
    {
        var versions = new Dictionary<string, IVersionFile?>
        {
            ["win-x64"] = new LauncherVersion { Version = "5.1", Guid = "new-file" }
        };
        var old = new Dictionary<string, LauncherBinaryReleaseMetadata>
        {
            ["win-x64"] = new()
            {
                FileId = "old-file", Version = "5.1", FileName = "old.exe",
                SizeBytes = 1080, Sha256 = new string('b', 64)
            }
        };

        Assert.That(LauncherPublishedCatalog.Map(versions, old)["win-x64"].Sha256, Is.Null);
        Assert.That(LauncherPublishedCatalog.Map(versions, null)["win-x64"].SizeBytes, Is.Null);
    }
}
