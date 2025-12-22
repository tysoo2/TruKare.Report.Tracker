using Microsoft.AspNetCore.Http;

namespace TruKare.Reports.Services;

public class HttpContextUserContext : IUserContext
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public HttpContextUserContext(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public string GetCurrentUser()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        var canonicalUser = httpContext?.Items["CanonicalUser"] as string;
        if (!string.IsNullOrWhiteSpace(canonicalUser))
        {
            return canonicalUser;
        }

        var identityName = httpContext?.User?.Identity?.Name;
        return string.IsNullOrWhiteSpace(identityName) ? "unknown" : identityName;
    }
}
