using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace TruKare.Reports.Services;

public class AdminAuthorizationService : IAdminAuthorizationService
{
    public const string RoleHeaderName = "X-User-Role";
    public const string UserHeaderName = "X-User";
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AdminAuthorizationService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public bool IsAdmin(HttpContext? context = null)
    {
        context ??= _httpContextAccessor.HttpContext;
        if (context == null)
        {
            return false;
        }

        var roleClaim = context.User?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
        roleClaim ??= context.Request.Headers[RoleHeaderName].FirstOrDefault();

        return string.Equals(roleClaim, "Admin", StringComparison.OrdinalIgnoreCase);
    }

    public string GetCurrentAdminUser(HttpContext? context = null)
    {
        context ??= _httpContextAccessor.HttpContext;
        if (context == null)
        {
            return string.Empty;
        }

        var userName = context.User?.Identity?.Name;
        userName ??= context.Request.Headers[UserHeaderName].FirstOrDefault();
        return userName ?? string.Empty;
    }

    public void EnsureAdmin(HttpContext? context = null)
    {
        if (!IsAdmin(context))
        {
            throw new AdminAuthorizationException("Admin role required.");
        }

        if (string.IsNullOrWhiteSpace(GetCurrentAdminUser(context)))
        {
            throw new AdminAuthorizationException("Admin identity required.");
        }
    }
}
