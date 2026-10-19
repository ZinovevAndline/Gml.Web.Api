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

    // Only these per-instance constants may legitimately differ from the
    // checked-in source/template when the GML Web panel configures a build.
    private static readonly HashSet<string> ManagedSettings = new(StringComparer.Ordinal)
    {
        "Host", "SecondaryHost", "FolderName", "WebsiteUrl", "SiteApiUrl",
        "GmlSessionToken", "DiscordUrl", "TelegramUrl", "DonateUrl",
        "SupportUrl", "LeaderboardUrl"
    };

    private static string WithoutManagedValues(string content) =>
        ResourceConstant.Replace(content, match =>
        {
            if (!ManagedSettings.Contains(match.Groups["name"].Value))
                return match.Value;
            var value = match.Groups["value"];
            var offset = value.Index - match.Index;
            return match.Value[..offset] + "<ANDLINE-CONFIG>"
                + match.Value[(offset + value.Length)..];
        });

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
        if (!string.Equals(normalizedRemote, RepositoryUrl[..^4], StringComparison.OrdinalIgnoreCase)
            && !string.Equals(normalizedRemote, "https://github.com/Gml-Launcher/Gml.Launcher",
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Исходники подключены к другому GitHub-репозиторию. Обновление отменено.");

        // The panel rewrites ResourceKeysDictionary.cs for this installation.
        // Submodule worktrees also look dirty after a build or on a volume that
        // does not keep file modes. Those are not source patches. A real edit
        // of any other tracked launcher file still stops the refresh.
        var changes = await GitAsync(cancellationToken,
            "-c", "core.filemode=false",
            "-C", source, "diff", "--ignore-cr-at-eol", "--ignore-submodules=dirty",
            "--name-only", "HEAD");
        var blocking = SelectBlockingEdits(changes);
        if (blocking.Count > 0)
        {
            Console.Error.WriteLine("[launcher-refresh] Other tracked edits: " + string.Join(", ", blocking));
            var listed = string.Join(", ", blocking.Take(8));
            var more = blocking.Count > 8 ? $" и ещё {blocking.Count - 8}" : "";
            throw new InvalidOperationException(
                $"Есть изменения в коде лаунчера: {listed}{more}. Сохраните их перед обновлением — настройки подключения сохранятся автоматически.");
        }

        // Whitelisting the file path alone could hide real C# edits inside
        // ResourceKeysDictionary.cs. Accept ONLY changed values of known
        // connection parameters, against either a checked-in file or the
        // GML Web generated template. Everything else must be saved manually.
        var configStatus = await GitAsync(cancellationToken,
            "-C", source, "status", "--porcelain", "--untracked-files=no", "--",
            "src/Gml.Launcher/Assets/Resources/ResourceKeysDictionary.cs");
        if (!string.IsNullOrWhiteSpace(configStatus))
        {
            var templatePath = Path.Combine(source, "src", "Gml.Launcher",
                "Assets", "Resources", "ResourceKeysDictionary.Template.cs");
            var originalFromGit = await GitAsync(cancellationToken, "-C", source,
                "show", "HEAD:src/Gml.Launcher/Assets/Resources/ResourceKeysDictionary.cs");
            var configured = WithoutManagedValues(
                await File.ReadAllTextAsync(originalConfig, cancellationToken));
            var accepted = string.Equals(configured, WithoutManagedValues(originalFromGit),
                               StringComparison.Ordinal)
                           || File.Exists(templatePath)
                           && string.Equals(configured, WithoutManagedValues(
                                   await File.ReadAllTextAsync(templatePath, cancellationToken)),
                               StringComparison.Ordinal);
            // Staged deletion, rename, or type change is not a panel setting.
            var changeKind = configStatus.TrimStart();
            if (!accepted || !changeKind.StartsWith("M", StringComparison.Ordinal))
                throw new InvalidOperationException(
                    "В файле настроек лаунчера изменён код. Сохраните правки перед обновлением.");
        }

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

    /// <summary>
    /// Paths that must not block a source refresh. Connection settings are copied
    /// onto the new tree; submodule checkouts are replaced from master.
    /// </summary>
    public static IReadOnlyList<string> SelectBlockingEdits(string gitNames)
    {
        var ignored =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "src/Gml.Client",
                "src/GamerVII.Notification.Avalonia",
                "src/Gml.Launcher/Assets/Resources/ResourceKeysDictionary.cs"
            };

        return gitNames
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(path => path.Trim().Trim('"').Replace('\\', '/'))
            .Where(path => path.Length > 0 && !ignored.Contains(path))
            .Where(path => !path.EndsWith("/ResourceKeysDictionary.cs", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static async Task PreserveLauncherSettings(
        string existingConfig, string templateFile, string destination, CancellationToken token)
    {
        if (!File.Exists(templateFile))
            throw new InvalidOperationException("В новой версии отсутствует шаблон настроек лаунчера.");

        var previous = await File.ReadAllTextAsync(existingConfig, token);
        var template = await File.ReadAllTextAsync(templateFile, token);
        // The repository's checked-in file provides real default endpoints.
        // Older GML Web downloads only populated HOST/FOLDER_NAME and left
        // every other template placeholder unresolved. Do not keep those
        // placeholder strings when transferring an existing configuration.
        var checkedInDefaults = await File.ReadAllTextAsync(destination, token);
        var defaultValues = ResourceConstant.Matches(checkedInDefaults)
            .ToDictionary(match => match.Groups["name"].Value,
                match => match.Groups["value"].Value, StringComparer.Ordinal);
        var oldValues = ResourceConstant.Matches(previous)
            .ToDictionary(match => match.Groups["name"].Value,
                match => match.Groups["value"].Value, StringComparer.Ordinal);

        // Only replace per-instance parameters; leave newer application strings intact.
        // Host/folder are essential; new optional settings may appear in later versions.
        if (!oldValues.ContainsKey("Host") || !oldValues.ContainsKey("FolderName"))
            throw new InvalidOperationException(
                "Не удалось восстановить адрес API или папку клиента. Исходники не изменены.");

        var updated = ResourceConstant.Replace(template, match =>
        {
            var key = match.Groups["name"].Value;
            if (!ManagedSettings.Contains(key))
                return match.Value;
            oldValues.TryGetValue(key, out var value);
            if (string.IsNullOrWhiteSpace(value)
                || value.StartsWith("{{", StringComparison.Ordinal) && value.EndsWith("}}", StringComparison.Ordinal))
                defaultValues.TryGetValue(key, out value);
            if (string.IsNullOrWhiteSpace(value))
                return match.Value;
            return match.Value.Replace(match.Groups["value"].Value, value, StringComparison.Ordinal);
        });
        // Never deploy a launcher with an unresolved API or site URL.
        if (updated.Contains("{{HOST}}", StringComparison.Ordinal)
            || updated.Contains("{{SITE_API_URL}}", StringComparison.Ordinal)
            || updated.Contains("{{GML_SESSION_TOKEN}}", StringComparison.Ordinal))
            throw new InvalidOperationException(
                "Не удалось восстановить настройки подключения лаунчера. Исходники не изменены.");
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
