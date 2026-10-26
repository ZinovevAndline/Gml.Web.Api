using System.Net;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Net.Http.Headers;
using MapsterMapper;
using FluentValidation;
using Gml.Dto.Files;
using Gml.Dto.Messages;
using Gml.Models.System;
using GmlCore.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Gml.Web.Api.Core.Handlers;

public class FileHandler : IFileHandler
{
    public static async Task<IResult> GetFile(HttpContext context, IGmlManager gmlManager, string fileHash)
    {
        Stream? file = null;
        try
        {
            var result = await gmlManager.Files.GetFileStream(fileHash);
            file = result.File;
            if (string.IsNullOrEmpty(result.fileName))
            {
                await file.DisposeAsync();
                return Results.NotFound();
            }

            // Files with a content SHA-256 embedded in the ID are immutable.
            // Legacy mutable IDs must never receive long-lived immutable caching.
            var digest = Regex.Match(fileHash, @"(?:^|-)([0-9a-fA-F]{64})(?:-|$)");
            var immutable = digest.Success;
            context.Response.Headers.CacheControl = immutable
                ? "public, max-age=31536000, immutable"
                : "no-store";

            EntityTagHeaderValue? etag = immutable
                ? new EntityTagHeaderValue($"\"{digest.Groups[1].Value.ToLowerInvariant()}\"")
                : null;
            DateTimeOffset? lastModified = file is FileStream local
                ? new DateTimeOffset(File.GetLastWriteTimeUtc(local.Name))
                : null;

            // Keep human-readable download names despite immutable IDs.
            var publicName = immutable
                ? fileHash.Replace("-" + digest.Groups[1].Value + "-", "-",
                    StringComparison.OrdinalIgnoreCase)
                : result.fileName;

            // Results.File uses the seekable stream's Length/Position to emit
            // 206/416 and conditional HTTP responses without buffering the bytes.
            return Results.File(file, "application/octet-stream", publicName,
                lastModified: lastModified, entityTag: etag, enableRangeProcessing: true);
        }
        catch (FileNotFoundException)
        {
            if (file is not null) await file.DisposeAsync();
            return Results.NotFound();
        }
        catch (DirectoryNotFoundException)
        {
            if (file is not null) await file.DisposeAsync();
            return Results.NotFound();
        }
        catch (Exception exception)
        {
            if (file is not null) await file.DisposeAsync();
            gmlManager.BugTracker.CaptureException(exception);
            return Results.StatusCode(StatusCodes.Status500InternalServerError);
        }
    }

    [Authorize]
    public static async Task<IResult> AddFileWhiteList(
        IGmlManager manager,
        IValidator<List<FileWhiteListDto>> validator,
        [FromBody] List<FileWhiteListDto> fileDto)
    {
        var result = await validator.ValidateAsync(fileDto);

        if (!result.IsValid)
            return Results.BadRequest(ResponseMessage.Create(result.Errors, "Ошибка валидации",
                HttpStatusCode.BadRequest));

        fileDto = fileDto.DistinctBy(c => c.Directory).ToList();

        var profileNames = fileDto.GroupBy(c => c.ProfileName);

        foreach (var profileFiles in profileNames)
        {
            var profile = await manager.Profiles.GetProfile(profileFiles.Key);

            if (profile == null)
                return Results.NotFound(ResponseMessage.Create($"Профиль с именем \"{profileFiles.Key}\" не найден",
                    HttpStatusCode.NotFound));

            foreach (var fileInfo in profileFiles)
            {
                await manager.Profiles.AddFileToWhiteList(profile, new LocalFileInfo(fileInfo.Directory));
            }
        }

        return Results.Ok(ResponseMessage.Create($"\"{fileDto.Count}\" файлов было успешно добавлено в White-Лист",
            HttpStatusCode.OK));
    }

    [Authorize]
    public static async Task<IResult> RemoveFileWhiteList(
        IGmlManager manager,
        IValidator<List<FileWhiteListDto>> validator,
        [FromBody] List<FileWhiteListDto> fileDto)
    {
        var result = await validator.ValidateAsync(fileDto);

        if (!result.IsValid)
            return Results.BadRequest(ResponseMessage.Create(result.Errors, "Ошибка валидации",
                HttpStatusCode.BadRequest));

        fileDto = fileDto.DistinctBy(c => c.Directory).ToList();

        var profileNames = fileDto.GroupBy(c => c.ProfileName);

        foreach (var profileFiles in profileNames)
        {
            var profile = await manager.Profiles.GetProfile(profileFiles.Key);

            if (profile == null)
                return Results.NotFound(ResponseMessage.Create($"Профиль с именем \"{profileFiles.Key}\" не найден",
                    HttpStatusCode.NotFound));

            foreach (var fileInfo in profileFiles.DistinctBy(c => c.Directory))
            {
                await manager.Profiles.RemoveFileFromWhiteList(profile, new LocalFileInfo(fileInfo.Directory));
            }
        }

        return Results.Ok(ResponseMessage.Create($"\"{fileDto.Count}\" файлов было успешно удалено из White-Листа",
            HttpStatusCode.OK));
    }

    public static async Task<IResult> AddFolderWhiteList(
        IGmlManager manager,
        IMapper mapper,
        IValidator<List<FolderWhiteListDto>> validator,
        [FromBody] List<FolderWhiteListDto> folderDto)
    {
        var result = await validator.ValidateAsync(folderDto);

        if (!result.IsValid)
            return Results.BadRequest(ResponseMessage.Create(result.Errors, "Ошибка валидации",
                HttpStatusCode.BadRequest));

        folderDto = folderDto.DistinctBy(x => x.Path).ToList();

        var mappedFolders = mapper.Map<List<LocalFolderInfo>>(folderDto);

        var profileNames = folderDto.GroupBy(c => c.ProfileName);

        foreach (var profileFolders in profileNames)
        {
            var profile = await manager.Profiles.GetProfile(profileFolders.Key);

            if (profile == null)
                return Results.NotFound(ResponseMessage.Create($"Профиль с именем \"{profileFolders.Key}\" не найден",
                    HttpStatusCode.NotFound));

            await manager.Profiles.AddFolderToWhiteList(profile, mappedFolders);
        }

        return Results.Ok(ResponseMessage.Create($"\"{folderDto.Count}\" папок было успешно добавлено в White-Лист",
            HttpStatusCode.OK));
    }

    public static async Task<IResult> RemoveFolderWhiteList(
        IGmlManager manager,
        IMapper mapper,
        IValidator<List<FolderWhiteListDto>> validator,
        [FromBody] List<FolderWhiteListDto> folderDto)
    {
        var result = await validator.ValidateAsync(folderDto);

        if (!result.IsValid)
            return Results.BadRequest(ResponseMessage.Create(result.Errors, "Ошибка валидации",
                HttpStatusCode.BadRequest));

        folderDto = folderDto.DistinctBy(x => x.Path).ToList();

        var mappedFolders = mapper.Map<List<LocalFolderInfo>>(folderDto);

        var profileNames = folderDto.GroupBy(c => c.ProfileName);

        foreach (var profileFolders in profileNames)
        {
            var profile = await manager.Profiles.GetProfile(profileFolders.Key);

            if (profile == null)
                return Results.NotFound(ResponseMessage.Create($"Профиль с именем \"{profileFolders.Key}\" не найден",
                    HttpStatusCode.NotFound));

            await manager.Profiles.RemoveFolderFromWhiteList(profile, mappedFolders);
        }

        return Results.Ok(ResponseMessage.Create($"\"{folderDto.Count}\" папок было успешно удалено из White-Лист",
            HttpStatusCode.OK));
    }
}
