using System.Security.Claims;

namespace TruKare.Reports.Authorization;

public interface IAdminGroupValidator
{
    bool IsInAdminGroup(ClaimsPrincipal user);
}
