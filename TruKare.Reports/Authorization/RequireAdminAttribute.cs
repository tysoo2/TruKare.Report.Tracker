using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using TruKare.Reports.DTOs;
using TruKare.Reports.Services;

namespace TruKare.Reports.Authorization;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class RequireAdminAttribute : Attribute, IAsyncAuthorizationFilter
{
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var adminAuthorization = context.HttpContext.RequestServices.GetRequiredService<IAdminAuthorizationService>();
        try
        {
            adminAuthorization.EnsureAdmin(context.HttpContext);
        }
        catch (AdminAuthorizationException ex)
        {
            context.Result = new ObjectResult(ErrorResponse.Forbidden(ex.Message))
            {
                StatusCode = StatusCodes.Status403Forbidden
            };
        }

        await Task.CompletedTask;
    }
}
