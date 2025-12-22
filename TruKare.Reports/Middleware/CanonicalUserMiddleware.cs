using System.Security.Claims;
using System.Linq;
using Microsoft.AspNetCore.Http;

namespace TruKare.Reports.Middleware;

public class CanonicalUserMiddleware
{
    private const string CanonicalUserHeader = "X-Canonical-User";
    private readonly RequestDelegate _next;

    public CanonicalUserMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var canonicalUser = GetCanonicalUser(context);
        context.Items["CanonicalUser"] = canonicalUser;

        var identity = CreateIdentity(context.User, canonicalUser);
        context.User = new ClaimsPrincipal(identity);

        await _next(context);
    }

    private static string GetCanonicalUser(HttpContext context)
    {
        var headerUser = context.Request.Headers[CanonicalUserHeader].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(headerUser))
        {
            return headerUser.Trim();
        }

        var existingName = context.User?.Identity?.Name;
        if (!string.IsNullOrWhiteSpace(existingName))
        {
            return existingName;
        }

        var machineUser = Environment.UserName;
        return string.IsNullOrWhiteSpace(machineUser) ? "unknown" : machineUser;
    }

    private static ClaimsIdentity CreateIdentity(ClaimsPrincipal existingPrincipal, string canonicalUser)
    {
        var authenticationType = existingPrincipal.Identity?.AuthenticationType ?? "Custom";
        var nameClaimType = existingPrincipal.Identity is ClaimsIdentity identity
            ? identity.NameClaimType
            : ClaimTypes.Name;
        var roleClaimType = existingPrincipal.Identity is ClaimsIdentity roleIdentity
            ? roleIdentity.RoleClaimType
            : ClaimTypes.Role;

        var claims = existingPrincipal.Claims.Where(c => c.Type != nameClaimType).ToList();
        claims.Add(new Claim(nameClaimType, canonicalUser));

        return new ClaimsIdentity(claims, authenticationType, nameClaimType, roleClaimType);
    }
}
