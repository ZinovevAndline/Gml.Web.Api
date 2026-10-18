using System.Text;
using Gml.Domains.Integrations;
using GmlCore.Interfaces;
using Newtonsoft.Json;

namespace Gml.Web.Api.Core.Integrations.Auth;

public class CustomEndpointAuthService(IHttpClientFactory httpClientFactory, IGmlManager gmlManager)
    : IPlatformAuthService
{
    private readonly HttpClient _httpClient = httpClientFactory.CreateClient();

    public virtual async Task<AuthResult> Auth(string login, string password, string? totp = null)
    {
        var dto = JsonConvert.SerializeObject(new
        {
            Login = login,
            Password = password,
            Totp = totp
        });

        using var content = new StringContent(dto, Encoding.UTF8, "application/json");

        var authService = await gmlManager.Integrations.GetActiveAuthService();

        using var result = await _httpClient.PostAsync(authService!.Endpoint, content);

        var resultContent = await result.Content.ReadAsStringAsync();

        return ParseResponse(login, result.IsSuccessStatusCode, resultContent);
    }

    internal static AuthResult ParseResponse(string login, bool success, string body)
    {
        // Empty/malformed responses must never create an authenticated player.
        if (string.IsNullOrWhiteSpace(body))
            return new AuthResult { Login = login, IsSuccess = false };

        AuthCustomResponse? model;
        try
        {
            model = JsonConvert.DeserializeObject<AuthCustomResponse>(body);
        }
        catch (JsonException)
        {
            return new AuthResult { Login = login, IsSuccess = false };
        }

        if (model is null)
            return new AuthResult { Login = login, IsSuccess = false };

        return new AuthResult
        {
            Login = model.Login ?? login,
            Uuid = model.UserUuid,
            IsSlim = model.IsSlim ?? false,
            IsSuccess = success,
            // Keep the ANDLINE continuation marker intact for the initiating
            // launcher; never log it or replace it with a TOTP-only prompt.
            Message = model.Message,
            TwoFactorEnabled = !success &&
                (model.Message?.Contains("2fa", StringComparison.OrdinalIgnoreCase) ?? false)
        };
    }
}
