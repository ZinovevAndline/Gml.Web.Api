using FluentValidation;
using Gml.Dto.Integration;
using Gml.Web.Api.Core.Integrations.Auth;
using GmlCore.Interfaces.Enums;

namespace Gml.Web.Api.Core.Validation;

public class IntegrationValidator : AbstractValidator<IntegrationUpdateDto>
{
    public IntegrationValidator()
    {
        RuleFor(x => x.Endpoint)
            .NotEmpty().WithMessage("Endpoint обязателен.")
            .Must((dto, url) => dto.AuthType == AuthType.Andline
                ? AndlineAuthUrl.TryNormalize(url, out _)
                : IsValidUrl(url))
            .WithMessage("Для ANDLINE укажите только адрес сайта (например, https://andline.pro), без /api, пути, параметров или логина.");
    }

    private bool IsValidUrl(string url)
    {
        return Uri.TryCreate(url, UriKind.Absolute, out var uriResult)
               && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);
    }
}
