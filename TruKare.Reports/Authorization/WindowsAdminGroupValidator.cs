using System.Security.Claims;
using System.Security.Principal;
using Microsoft.Extensions.Options;
using TruKare.Reports.Options;

namespace TruKare.Reports.Authorization;

public class WindowsAdminGroupValidator : IAdminGroupValidator
{
    private readonly AuthOptions _options;
    private readonly ILogger<WindowsAdminGroupValidator> _logger;

    public WindowsAdminGroupValidator(IOptions<AuthOptions> options, ILogger<WindowsAdminGroupValidator> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public bool IsInAdminGroup(ClaimsPrincipal user)
    {
        if (user?.Identity is not { IsAuthenticated: true })
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(_options.AdminGroup))
        {
            _logger.LogWarning("Admin group not configured; treating user {User} as non-admin.", user.Identity?.Name ?? "Unknown");
            return false;
        }

        return IsInAdminGroup(user, _options.AdminGroup);
    }

    private static bool IsInAdminGroup(ClaimsPrincipal user, string adminGroup)
    {
        if (user.IsInRole(adminGroup))
        {
            return true;
        }

        if (user.Identity is WindowsIdentity windowsIdentity && windowsIdentity.Groups is not null)
        {
            foreach (var group in windowsIdentity.Groups)
            {
                try
                {
                    var translated = group.Translate(typeof(NTAccount)).ToString();
                    if (string.Equals(translated, adminGroup, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                catch (IdentityNotMappedException)
                {
                    continue;
                }
            }
        }

        var roleClaims = user.FindAll(ClaimTypes.Role)
            .Select(c => c.Value)
            .Concat(user.FindAll("groups").Select(c => c.Value));

        return roleClaims.Any(value => string.Equals(value, adminGroup, StringComparison.OrdinalIgnoreCase));
    }
}
