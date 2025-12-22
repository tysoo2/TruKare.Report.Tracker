using Microsoft.AspNetCore.Authorization;

namespace TruKare.Reports.Authorization;

public class AdminGroupHandler : AuthorizationHandler<AdminGroupRequirement>
{
    private readonly IAdminGroupValidator _adminGroupValidator;
    private readonly ILogger<AdminGroupHandler> _logger;

    public AdminGroupHandler(IAdminGroupValidator adminGroupValidator, ILogger<AdminGroupHandler> logger)
    {
        _adminGroupValidator = adminGroupValidator;
        _logger = logger;
    }

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminGroupRequirement requirement)
    {
        if (context.User?.Identity is not { IsAuthenticated: true })
        {
            return Task.CompletedTask;
        }

        if (_adminGroupValidator.IsInAdminGroup(context.User))
        {
            context.Succeed(requirement);
        }
        else
        {
            _logger.LogWarning("User {User} is not a member of the configured admin group.", context.User.Identity?.Name ?? "Unknown");
        }

        return Task.CompletedTask;
    }
}
