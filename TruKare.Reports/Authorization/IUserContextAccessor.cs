using Microsoft.AspNetCore.Http;

namespace TruKare.Reports.Authorization;

public interface IUserContextAccessor
{
    RequestUserContext GetCurrentUser(HttpContext httpContext);
}
