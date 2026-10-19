using Gml.Web.Api.Core.Extensions;
using Microsoft.Extensions.Logging;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddFilter(static (_, level) => level >= LogLevel.Error);
builder
    .RegisterServices()
    .Build()
    .RegisterServices()
    .Run();
