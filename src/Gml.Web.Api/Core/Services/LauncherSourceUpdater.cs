using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Gml.Web.Api.Core.Services;

/// <summary>
/// Safely refreshes an existing panel launcher source checkout from the trusted
/// ANDLINE master branch. Nothing in LauncherBuilds or GML's databases is touched.
/// </summary>
public static class LauncherSourceUpdater
{
    private const string RepositoryUrl = "https://github.com/ZinovevAndline/Gml.Launcher.git";
    private static readonly Regex VersionName = new(
        @"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex ResourceConstant = new(
        "public\\s+const\\s+string\\s+(?<name>[A-Za-z][A-Za-z0-9_]*)\\s*=\\s*\\\"(?<value>(?:\\\\.|[^\\\"\\\\])*)\\\"\\s*;",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static async Task<string> RefreshAsync(
        string installationDirectory, string version, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(version) || version is "." or ".." || !VersionName.IsMatch(version))
            throw new InvalidOperationException("Выберите корректную версию исходников.");

        var projectRoot = Path.GetFullPath(installationDirectory);
        var source = Path.Combine(projectRoot, "Launcher", version);
        var originalConfig = Path.Combine(source, "src", "Gml.Launcher",
            "Assets", "Resources", "ResourceKeysDictionary.cs");

        if (!Directory.Exists(Path.Combine(source, ".git")))
            throw new InvalidOperationException("Исходники этой версии не найдены. Сначала загрузите их через панель.");
        if (!File.Exists(originalConfig))
            throw new InvalidOperationException("Не найден файл настроек лаунчера. Обновление отменено, чтобы не потерять подключение.");

        // Refuse locally edited tracked files instead of silently discarding custom patches.
        var remote = (await GitAsync(cancellationToken, "-C", source, "remote", "get-url", "origin")).Trim();
        var normalizedRemote = remote.TrimEnd('/');
        if (normalizedRemote.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
            normalizedRemote = normalizedRemote[..^4];
        if (!string.Equals(normalizedRemote, RepositoryUrl[..^4], StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Исходники подключены к другому GitHub-репозиторию. Обновление отменено.");

        var changes = await GitAsync(cancellationToken, "-C", source, "status", "--porcelain", "--untracked-files=no");
        if (!string.IsNullOrWhiteSpace(changes))
            throw new InvalidOperationException("В исходниках есть ручные изменения. Сохраните их в GitHub перед обновлением.");

        var currentSha = (await GitAsync(cancellationToken, "-C", source, "rev-parse", "HEAD")).Trim();
        var stage = Path.Combine(projectRoot, ".launcher-source-staging-" + Guid.NewGuid().ToString("N"));
        var backupRoot = Path.Combine(projectRoot, "LauncherSourceBackups");
        var backup = Path.Combine(backupRoot, version + "-previous");
        try
        {
            // Stage a complete, independently checked out copy before touching the working source.
            await GitAsync(cancellationToken, "clone", "--quiet", "--recursive",
                "--depth=1", "--shallow-submodules", "--branch", "master", RepositoryUrl, stage);

            var solution = Path.Combine(stage, "src", "Gml.Launcher", "Gml.Launcher.csproj");
            var client = Path.Combine(stage, "src", "Gml.Client", "src", "Gml.Client", "Gml.Client.csproj");
            var notifications = Path.Combine(stage, "src", "GamerVII.Notification.Avalonia",
                "GamerVII.Notification.Avalonia", "GamerVII.Notification.Avalonia.csproj");
            if (!File.Exists(solution) || !File.Exists(client) || !File.Exists(notifications))
                throw new InvalidOperationException("GitHub вернул неполные исходники или подмодули. Рабочая версия не изменена.");

            var nextSha = (await GitAsync(cancellationToken, "-C", stage, "rev-parse", "HEAD")).Trim();
            if (string.Equals(currentSha, nextSha, StringComparison.OrdinalIgnoreCase))
                return nextSha;

            // Re-create generated resource constants from the NEW template so newly added
            // keys survive, while all previously configured values remain unchanged.
            var template = Path.Combine(stage, "src", "Gml.Launcher", "Assets", "Resources",
                "ResourceKeysDictionary.Template.cs");
            var targetConfig = Path.Combine(stage, "src", "Gml.Launcher", "Assets", "Resources",
                "ResourceKeysDictionary.cs");
            await PreserveLauncherSettings(originalConfig, template, targetConfig, cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();
            Directory.CreateDirectory(backupRoot);
            if (Directory.Exists(backup))
                Directory.Delete(backup, recursive: true); // Keep at most one previous source copy per version.

            Directory.Move(source, backup);
            try
            {
                Directory.Move(stage, source);
            }
            catch
            {
                if (!Directory.Exists(source))
                    Directory.Move(backup, source);
                throw;
            }

            return nextSha;
        }
        finally
        {
            if (Directory.Exists(stage))
                Directory.Delete(stage, recursive: true);
        }
    }

    private static async Task PreserveLauncherSettings(
        string existingConfig, string templateFile, string destination, CancellationToken token)
    {
        if (!File.Exists(templateFile))
            throw new InvalidOperationException("В новой версии отсутствует шаблон настроек лаунчера.");

        var previous = await File.ReadAllTextAsync(existingConfig, token);
        var template = await File.ReadAllTextAsync(templateFile, token);
        var oldValues = ResourceConstant.Matches(previous)
            .ToDictionary(match => match.Groups["name"].Value,
                match => match.Groups["value"].Value, StringComparer.Ordinal);

        // Only replace per-instance parameters; leave newer application strings intact.
        var settings = new HashSet<string>(StringComparer.Ordinal)
        {
            "Host", "SecondaryHost", "FolderName", "WebsiteUrl", "SiteApiUrl",
            "GmlSessionToken", "DiscordUrl", "TelegramUrl", "DonateUrl",
            "SupportUrl", "LeaderboardUrl"
        };
        // Host/folder are essential; new optional settings may appear in later versions.
        if (!oldValues.ContainsKey("Host") || !oldValues.ContainsKey("FolderName"))
            throw new InvalidOperationException(
                "Не удалось восстановить адрес API или папку клиента. Исходники не изменены.");

        var updated = ResourceConstant.Replace(template, match =>
        {
            var key = match.Groups["name"].Value;
            if (!settings.Contains(key) || !oldValues.TryGetValue(key, out var value))
                return match.Value;
            return match.Value.Replace(match.Groups["value"].Value, value, StringComparison.Ordinal);
        });
        await File.WriteAllTextAsync(destination, updated, token);
    }

    private static async Task<string> GitAsync(CancellationToken token, params string[] arguments)
    {
        using var process = new Process();
        process.StartInfo.FileName = "git";
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.CreateNoWindow = true;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;
        foreach (var argument in arguments)
            process.StartInfo.ArgumentList.Add(argument);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromMinutes(8));
        try
        {
            process.Start();
            var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var error = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token);
            var stdout = await output;
            await error;
            if (process.ExitCode != 0)
                throw new InvalidOperationException("GitHub недоступен или скачивание исходников завершилось ошибкой.");
            return stdout;
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
            throw new InvalidOperationException("Превышено время ожидания GitHub. Исходники не изменены.");
        }
    }
}
