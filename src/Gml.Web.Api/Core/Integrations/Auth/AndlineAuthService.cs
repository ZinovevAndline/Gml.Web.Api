using System.Text;
using Gml.Domains.Integrations;
using GmlCore.Interfaces;
using Newtonsoft.Json;

namespace Gml.Web.Api.Core.Integrations.Auth;

/// <summary>
/// Built-in ANDLINE authentication. Admin configures only a base site URL;
/// this service owns the stable POST /api/gml/auth path.
/// This reuses ANDLINE's existing secure password and 2FA continuation flow.
/// </summary>
public sealed class AndlineAuthService(IHttpClientFactory httpClientFactory, IGmlManager manager)
    : IPlatformAuthService
{
    private readonly HttpClient _http = httpClientFactory.CreateClient("andline-auth");

    public async Task<AuthResult> Auth(string login, string password, string? totp = null)
    {
        var configured = await manager.Integrations.GetActiveAuthService();
        if (!AndlineAuthUrl.TryBuild(configured?.Endpoint, out var endpoint))
            return new AuthResult { Login = login, IsSuccess = false, Message = "Сервис ANDLINE настроен неверно" };

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(JsonConvert.SerializeObject(new
            {
                Login = login,
                Password = password,
                Totp = totp
            }), Encoding.UTF8, "application/json")
        };
        // No automatic redirects (including authentication payloads to other origins).
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        var body = await response.Content.ReadAsStringAsync();
        return CustomEndpointAuthService.ParseResponse(login, response.IsSuccessStatusCode, body);
    }
}

/// <summary>
/// A base URL, not an arbitrary endpoint. No path, credentials, query or
/// fragment; HTTPS required except loopback development addresses.
/// </summary>
public static class AndlineAuthUrl
{
    private const string LoginPath = "/api/gml/auth";

    public static bool TryNormalize(string? input, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(input)
            || !Uri.TryCreate(input.Trim(), UriKind.Absolute, out var uri))
            return false;

        if (uri.Scheme is not ("https" or "http")
            || uri.Scheme == "http" && !uri.IsLoopback
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || uri.AbsolutePath != "/"
            || string.IsNullOrWhiteSpace(uri.Host))
            return false;

        normalized = uri.GetLeftPart(UriPartial.Authority);
        return true;
    }

    public static bool TryBuild(string? baseUrl, out Uri endpoint)
    {
        endpoint = null!;
        if (!TryNormalize(baseUrl, out var normalized)) return false;
        endpoint = new Uri(normalized + LoginPath, UriKind.Absolute);
        return true;
    }
}
