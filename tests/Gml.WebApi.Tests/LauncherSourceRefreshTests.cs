using Gml.Web.Api.Core.Services;

namespace Gml.WebApi.Tests;

public class LauncherSourceRefreshTests
{
    [Test]
    public void ConnectionSettingsAndSubmoduleNoiseDoNotBlockRefresh()
    {
        var names = """
            src/Gml.Launcher/Assets/Resources/ResourceKeysDictionary.cs
            src/Gml.Client
            src/GamerVII.Notification.Avalonia
            """;

        Assert.That(LauncherSourceUpdater.SelectBlockingEdits(names), Is.Empty);
    }

    [Test]
    public void OtherTrackedLauncherFilesStillBlockRefresh()
    {
        var names = """
            src/Gml.Launcher/Assets/Resources/ResourceKeysDictionary.cs
            src/Gml.Launcher/Views/MainWindow.axaml.cs
            """;

        Assert.That(LauncherSourceUpdater.SelectBlockingEdits(names),
            Is.EqualTo(new[] { "src/Gml.Launcher/Views/MainWindow.axaml.cs" }));
    }
}
