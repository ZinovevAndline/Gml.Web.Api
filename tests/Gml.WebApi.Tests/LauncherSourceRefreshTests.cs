using Gml.Web.Api.Core.Services;

namespace Gml.WebApi.Tests;

public class LauncherSourceRefreshTests
{
    [Test]
    public void ConnectionSettingsDoNotBlockRefresh()
    {
        var names = """
            src/Gml.Launcher/Assets/Resources/ResourceKeysDictionary.cs
            """;

        Assert.That(LauncherSourceUpdater.SelectBlockingEdits(names), Is.Empty);
    }

    [Test]
    public void ChangedSubmoduleCommitAndOtherFilesStillBlockRefresh()
    {
        var names = """
            src/Gml.Launcher/Assets/Resources/ResourceKeysDictionary.cs
            src/Gml.Client
            src/Gml.Launcher/Views/MainWindow.axaml.cs
            """;

        Assert.That(LauncherSourceUpdater.SelectBlockingEdits(names),
            Is.EqualTo(new[]
            {
                "src/Gml.Client",
                "src/Gml.Launcher/Views/MainWindow.axaml.cs"
            }));
    }
}
