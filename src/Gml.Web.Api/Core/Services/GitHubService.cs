using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using GmlCore.Interfaces;
using Newtonsoft.Json.Linq;

namespace Gml.Web.Api.Core.Services;

public class GitHubService : IGitHubService
{
    private readonly IGmlManager _gmlManager;
    private readonly HttpClient _httpClient;
    private ICollection<string> _versions;
    private ICollection<string> _branches;

    public GitHubService(IHttpClientFactory httpClientFactory, IGmlManager gmlManager)
    {
        _gmlManager = gmlManager;
        _httpClient = httpClientFactory.CreateClient();
    }

    public async Task<IEnumerable<string>> GetRepositoryBranches(string user, string repository)
    {
        var url = $"https://api.github.com/repos/{user}/{repository}/branches";

        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("request");

        var response = await _httpClient.GetAsync(url);

        if (response.IsSuccessStatusCode)
        {
            var responseString = await response.Content.ReadAsStringAsync();

            var branches = JArray.Parse(responseString);

            _versions = branches.Select(c => c["name"].ToString()).ToArray();
        }

        return _branches;
    }

    public async Task<IEnumerable<string>> GetRepositoryTags(string user, string repository)
    {
        var url = $"https://api.github.com/repos/{user}/{repository}/tags?per_page=100";
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.ParseAdd("ANDLINE-GML");
        var token = Environment.GetEnvironmentVariable("GML_GITHUB_TOKEN");
        if (!string.IsNullOrWhiteSpace(token))
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Trim());

        using var response = await _httpClient.SendAsync(request);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                "Не удалось получить версии ANDLINE Launcher. Проверьте доступ GitHub в настройках сервера.");

        var content = await response.Content.ReadAsStringAsync();
        var tags = JArray.Parse(content);
        _versions = tags.Select(tag => tag["name"]?.ToString() ?? string.Empty)
            .Where(name => !string.IsNullOrWhiteSpace(name)).ToArray();
        return _versions;
    }

    // public async Task<string> DownloadProject(string projectPath, string branchName, string repoUrl)
    // {
    //
    //
    //     var directory = new DirectoryInfo(projectPath);
    //
    //     if (!directory.Exists) directory.Create();
    //
    //     var zipPath = $"{projectPath}/{branchName}.zip";
    //     var extractPath = NormalizePath(projectPath, branchName);
    //
    //     var url = $"https://github.com/Gml-Launcher/Gml.Launcher/archive/refs/tags/{branchName}.zip";
    //
    //     using (var client = new HttpClient())
    //     {
    //         var stream = await client.GetStreamAsync(url);
    //
    //         await using (var fileStream = new FileStream(zipPath, FileMode.Create, FileAccess.Write, FileShare.None))
    //         {
    //             await stream.CopyToAsync(fileStream);
    //         }
    //     }
    //
    //     // Проверяем, существует ли уже папка для распаковки
    //     if (!Directory.Exists(extractPath))
    //         // Если папка не существует - создаем ее
    //         Directory.CreateDirectory(extractPath);
    //
    //     // Распаковываем архив
    //     ZipFile.ExtractToDirectory(zipPath, extractPath, true);
    //
    //     File.Delete(zipPath);
    //
    //     return new DirectoryInfo(extractPath).GetDirectories().First().FullName;
    // }

    public async Task<string> DownloadProject(string projectPath, string branchName, string repoUrl)
    {
        var directory = new DirectoryInfo(Path.Combine(projectPath, branchName));

        if (!directory.Exists)
        {
            directory.Create();
        }

        var processInfo = new ProcessStartInfo
        {
            FileName = "git",
            Arguments = $"clone --recursive --branch {branchName} {repoUrl} {directory.FullName}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = new Process();
        process.StartInfo = processInfo;
        process.Start();

        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"An error occurred while cloning the repository: {error}");
        }

        Console.WriteLine(output);

        return directory.FullName;
    }

    private string NormalizePath(string directory, string fileDirectory)
    {
        directory = directory
            .Replace('\\', Path.DirectorySeparatorChar)
            .Replace('/', Path.DirectorySeparatorChar);
        // .TrimStart(Path.DirectorySeparatorChar);

        fileDirectory = fileDirectory
            .Replace('\\', Path.DirectorySeparatorChar)
            .Replace('/', Path.DirectorySeparatorChar)
            .TrimStart(Path.DirectorySeparatorChar);

        return Path.Combine(directory, fileDirectory);
    }

    public async Task EditLauncherFiles(string projectPath, string host, string folder)
    {
        // New versions contain a checked-in file with real defaults plus a
        // template with many placeholder constants. Do not replace that file
        // with a template containing unresolved website/API/session settings.
        var resourceDirectory = Path.Combine(projectPath, "src", "Gml.Launcher", "Assets", "Resources");
        var settingsTemplateFile = Path.Combine(resourceDirectory, "ResourceKeysDictionary.Template.cs");
        var settingsFile = Path.Combine(resourceDirectory, "ResourceKeysDictionary.cs");
        if (!File.Exists(settingsTemplateFile) || !File.Exists(settingsFile))
            throw new InvalidOperationException("Не удалось найти настройки исходников лаунчера.");

        var constants = new Regex(
            "public\\s+const\\s+string\\s+(?<name>[A-Za-z][A-Za-z0-9_]*)\\s*=\\s*\\\"(?<value>(?:\\\\.|[^\\\"\\\\])*)\\\"\\s*;",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);
        var original = await File.ReadAllTextAsync(settingsFile);
        var defaults = constants.Matches(original)
            .ToDictionary(m => m.Groups["name"].Value,
                m => m.Groups["value"].Value, StringComparer.Ordinal);
        if (!defaults.ContainsKey("Host") || !defaults.ContainsKey("FolderName"))
            throw new InvalidOperationException("Не удалось прочитать настройки подключения лаунчера.");

        var template = await File.ReadAllTextAsync(settingsTemplateFile);
        var updated = constants.Replace(template, match =>
        {
            var current = match.Groups["value"].Value;
            if (!current.StartsWith("{{", StringComparison.Ordinal)
                || !current.EndsWith("}}", StringComparison.Ordinal))
                return match.Value;

            var name = match.Groups["name"].Value;
            var value = name switch
            {
                "Host" => host,
                "FolderName" => folder,
                _ => defaults.GetValueOrDefault(name)
            };
            if (value is null) return match.Value;
            // JSON escaped strings are also valid quoted C# string contents.
            // Escape user-configured values instead of generating C# code from
            // raw host/folder input.
            var literal = JsonSerializer.Serialize(value);
            return match.Value.Replace("\\\"" + current + "\\\"", literal, StringComparison.Ordinal);
        });
        if (Regex.IsMatch(updated, "\\\"\\{\\{[A-Z0-9_]+\\}\\}\\\""))
            throw new InvalidOperationException(
                "Не удалось заполнить настройки лаунчера. Исходники не изменены.");

        // Write only a complete validated replacement. No deletion before
        // template and defaults have been checked.
        await File.WriteAllTextAsync(settingsFile, updated);
    }
}
