using Microsoft.AspNetCore.Http;

namespace TruKare.Reports.Services;

public interface IAdminAuthorizationService
{
    bool IsAdmin(HttpContext? context = null);

    string GetCurrentAdminUser(HttpContext? context = null);

    void EnsureAdmin(HttpContext? context = null);
}
