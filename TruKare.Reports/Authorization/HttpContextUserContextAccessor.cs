using System.Security.Principal;
using Microsoft.AspNetCore.Http;

namespace TruKare.Reports.Authorization;

public class HttpContextUserContextAccessor : IUserContextAccessor
{
    private readonly IAdminGroupValidator _adminGroupValidator;

    public HttpContextUserContextAccessor(IAdminGroupValidator adminGroupValidator)
    {
        _adminGroupValidator = adminGroupValidator;
    }

    public RequestUserContext GetCurrentUser(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        if (httpContext.User?.Identity is not { IsAuthenticated: true })
        {
            throw new InvalidOperationException("No authenticated user available in the current context.");
        }

        var userName = ResolveUserName(httpContext.User.Identity as WindowsIdentity, httpContext.User.Identity?.Name);
        var host = ResolveHost(httpContext);
        var isAdmin = _adminGroupValidator.IsInAdminGroup(httpContext.User);

        return new RequestUserContext(userName, host, isAdmin);
    }

    private static string ResolveUserName(WindowsIdentity? windowsIdentity, string? identityName)
    {
        if (!string.IsNullOrWhiteSpace(identityName))
        {
            return identityName;
        }

        if (!string.IsNullOrWhiteSpace(windowsIdentity?.Name))
        {
            return windowsIdentity.Name;
        }

        throw new InvalidOperationException("Unable to resolve the authenticated user name.");
    }

    private static string ResolveHost(HttpContext httpContext)
    {
        var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(forwardedFor))
        {
            return forwardedFor.Split(',').First().Trim();
        }

        var remoteIp = httpContext.Connection.RemoteIpAddress?.ToString();
        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            return remoteIp;
        }

        return httpContext.Request.Host.ToString();
    }
}
