using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TruKare.Reports.Authorization;
using TruKare.Reports.DTOs;
using TruKare.Reports.Services;

namespace TruKare.Reports.Controllers;

[ApiController]
[Authorize]
[Route("reports")]
public class ReportsController : ControllerBase
{
    private readonly IReportVaultService _reportVaultService;
    private readonly IUserContextAccessor _userContextAccessor;

    public ReportsController(IReportVaultService reportVaultService, IUserContextAccessor userContextAccessor)
    {
        _reportVaultService = reportVaultService;
        _userContextAccessor = userContextAccessor;
    }

    [HttpGet]
    public IActionResult Search([FromQuery] SearchReportsRequest request)
    {
        var results = _reportVaultService.SearchReports(request);
        return Ok(results);
    }

    [HttpGet("{id:guid}/status")]
    public IActionResult GetStatus(Guid id)
    {
        var status = _reportVaultService.GetReportStatus(id);
        return Ok(status);
    }

    [HttpPost("checkout")]
    public async Task<IActionResult> Checkout([FromBody] CheckoutRequest request, CancellationToken cancellationToken)
    {
        var userContext = _userContextAccessor.GetCurrentUser(HttpContext);
        var response = await _reportVaultService.CheckoutAsync(request, userContext, cancellationToken);
        return Ok(response);
    }

    [HttpPost("override-checkout")]
    [Authorize(Policy = AdminPolicies.AdminGroup)]
    public async Task<IActionResult> OverrideCheckout([FromBody] OverrideCheckoutRequest request, CancellationToken cancellationToken)
    {
        var userContext = _userContextAccessor.GetCurrentUser(HttpContext);
        var response = await _reportVaultService.OverrideCheckoutAsync(request, userContext, cancellationToken);
        return Ok(response);
    }

    [HttpPost("checkin")]
    public async Task<IActionResult> Checkin([FromBody] CheckinRequest request, CancellationToken cancellationToken)
    {
        var userContext = _userContextAccessor.GetCurrentUser(HttpContext);
        await _reportVaultService.CheckinAsync(request, userContext, cancellationToken);
        return Ok();
    }

    [HttpPost("finalize")]
    [RequireAdmin]
    public async Task<IActionResult> Finalize([FromBody] FinalizeRequest request, CancellationToken cancellationToken)
    {
        var userContext = _userContextAccessor.GetCurrentUser(HttpContext);
        await _reportVaultService.FinalizeAsync(request, userContext, cancellationToken);
        return Ok();
    }

    [HttpGet("{id:guid}/audit")]
    public IActionResult GetAudit(Guid id)
    {
        var audit = _reportVaultService.GetAuditTrail(id);
        return Ok(audit);
    }
}
