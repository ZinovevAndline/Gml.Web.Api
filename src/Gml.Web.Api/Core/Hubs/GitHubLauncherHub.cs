using System.Reactive.Linq;
using Gml.Web.Api.Core.Services;
using GmlCore.Interfaces;
using GmlCore.Interfaces.Enums;
using Microsoft.AspNetCore.SignalR;

namespace Gml.Web.Api.Core.Hubs;

public class GitHubLauncherHub(IGitHubService gitHubService, IGmlManager gmlManager) : BaseHub
{
    private const string _launcherGitHub = "https://github.com/ZinovevAndline/Gml.Launcher";
    private static readonly SemaphoreSlim SourceOperation = new(1, 1);

    public async Task Download(string branchName, string host, string folderName)
    {
        if (!await SourceOperation.WaitAsync(0))
        {
            await Clients.Caller.SendAsync("Message", "Дождитесь завершения текущей операции с лаунчером.");
            await Clients.Caller.SendAsync("LauncherDownloadEnded");
            return;
        }
        using var cts = new CancellationTokenSource();
        try
        {
            var projectPath = Path.Combine(gmlManager.LauncherInfo.InstallationDirectory, "Launcher", branchName);

            if (Directory.Exists(projectPath))
            {
                await gmlManager.Notifications
                    .SendMessage("Лаунчер уже существует в папке, удалите его перед сборкой", NotificationType.Error);
                return;
            }

            projectPath = Path.Combine(gmlManager.LauncherInfo.InstallationDirectory, "Launcher");

            ChangeProgress(nameof(GitHubLauncherHub), 5);
            var allowedVersions = await gitHubService
                .GetRepositoryTags("ZinovevAndline", "Gml.Launcher");

            if (allowedVersions.All(c => c != branchName))
            {
                await gmlManager.Notifications
                    .SendMessage($"Полученная версия лаунчера \"{branchName}\" не поддерживается",
                        NotificationType.Error);
                return;
            }

            ChangeProgress(nameof(GitHubLauncherHub), 10);

            var progressSubscription = Observable
                .Timer(TimeSpan.Zero, TimeSpan.FromMilliseconds(700))
                .Select(x => (int)(10 + Math.Min(x * 0.5, 88)))
                .Subscribe(progress => ChangeProgress(nameof(GitHubLauncherHub), progress));

            var newFolder = await gitHubService.DownloadProject(projectPath, branchName, _launcherGitHub);

            await cts.CancelAsync();
            progressSubscription.Dispose();

            ChangeProgress(nameof(GitHubLauncherHub), 98);
            await gitHubService.EditLauncherFiles(newFolder, host, folderName);
            ChangeProgress(nameof(GitHubLauncherHub), 100);
            SendCallerMessage($"Проект \"{branchName}\" успешно создан");
        }
        catch (Exception exception)
        {
            Console.WriteLine(exception);
            await gmlManager.Notifications.SendMessage("Ошибка при загрузке клиента лаунчера", exception);
        }
        finally
        {
            await Clients.Caller.SendAsync("LauncherDownloadEnded");
            await cts.CancelAsync();
            SourceOperation.Release();
        }
    }

    /// <summary>Refresh an existing version's sources from the trusted master branch.</summary>
    public async Task<string> RefreshSource(string version)
    {
        if (!await SourceOperation.WaitAsync(0))
            throw new HubException("Дождитесь завершения другой операции с лаунчером.");

        try
        {
            var commit = await LauncherSourceUpdater.RefreshAsync(
                gmlManager.LauncherInfo.InstallationDirectory, version, Context.ConnectionAborted);
            return commit.Length >= 12 ? commit[..12] : commit;
        }
        catch (InvalidOperationException error)
        {
            throw new HubException(error.Message);
        }
        catch (Exception)
        {
            throw new HubException("Не удалось обновить исходники. Рабочая версия сохранена.");
        }
        finally
        {
            SourceOperation.Release();
        }
    }

    public async Task Compile(string version, string[] osTypes)
    {
        if (!await SourceOperation.WaitAsync(0))
        {
            await Clients.Caller.SendAsync("Message", "Дождитесь завершения текущей операции с лаунчером.");
            await Clients.Caller.SendAsync("LauncherBuildEnded");
            return;
        }
        IDisposable? downloadLogsDisposable = null;
        IDisposable? buildLogsDisposable = null;

        try
        {
            if (!gmlManager.Launcher.CanCompile(version, out string message))
            {
                SendCallerMessage(message);
                return;
            }

            Log("Start compilling...");
            downloadLogsDisposable = gmlManager.LauncherInfo.Settings.SystemProcedures.DownloadLogs.Subscribe(Log);
            if (await gmlManager.LauncherInfo.Settings.SystemProcedures.InstallDotnet())
            {
                buildLogsDisposable = gmlManager.Launcher.BuildLogs.Subscribe(Log);

                var result = await gmlManager.Launcher.Build(version, osTypes);

                if (result)
                    await gmlManager.Notifications.SendMessage("Лаунчер успешно скомпилирован!", NotificationType.Info);
                else
                    await gmlManager.Notifications.SendMessage("Сборка лаунчера завершилась ошибкой!",
                        NotificationType.Error);

            }
        }
        catch (Exception exception)
        {
            Console.WriteLine(exception);
            await gmlManager.Notifications.SendMessage("Ошибка при загрузке клиента лаунчера", exception);
        }
        finally
        {
            downloadLogsDisposable?.Dispose();
            buildLogsDisposable?.Dispose();
            SourceOperation.Release();
            await Clients.Caller.SendAsync("LauncherBuildEnded");
        }
    }
}
