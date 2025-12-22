using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TruKare.Reports.Authorization;
using TruKare.Reports.DTOs;
using TruKare.Reports.Services;

namespace TruKare.Reports.Controllers;

[ApiController]
[Route("reports")]
public class ReportsController : ControllerBase
{
    private readonly IReportVaultService _reportVaultService;
    private readonly IAdminAuthorizationService _adminAuthorizationService;

    public ReportsController(IReportVaultService reportVaultService, IAdminAuthorizationService adminAuthorizationService)
    {
        _reportVaultService = reportVaultService;
        _adminAuthorizationService = adminAuthorizationService;
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
        var response = await _reportVaultService.CheckoutAsync(request, cancellationToken);
        return Ok(response);
    }

    [HttpPost("override-checkout")]
    [RequireAdmin]
    public async Task<IActionResult> OverrideCheckout([FromBody] OverrideCheckoutRequest request, CancellationToken cancellationToken)
    {
        try
        {
            request.AdminUser = _adminAuthorizationService.GetCurrentAdminUser(HttpContext);
            var response = await _reportVaultService.OverrideCheckoutAsync(request, cancellationToken);
            return Ok(response);
        }
        catch (AdminAuthorizationException ex)
        {
            return StatusCode(StatusCodes.Status403Forbidden, ErrorResponse.Forbidden(ex.Message));
        }
    }

    [HttpPost("checkin")]
    public async Task<IActionResult> Checkin([FromBody] CheckinRequest request, CancellationToken cancellationToken)
    {
        await _reportVaultService.CheckinAsync(request, cancellationToken);
        return Ok();
    }

    [HttpPost("finalize")]
    [RequireAdmin]
    public async Task<IActionResult> Finalize([FromBody] FinalizeRequest request, CancellationToken cancellationToken)
    {
        try
        {
            request.User = _adminAuthorizationService.GetCurrentAdminUser(HttpContext);
            await _reportVaultService.FinalizeAsync(request, cancellationToken);
            return Ok();
        }
        catch (AdminAuthorizationException ex)
        {
            return StatusCode(StatusCodes.Status403Forbidden, ErrorResponse.Forbidden(ex.Message));
        }
    }

    [HttpGet("{id:guid}/audit")]
    public IActionResult GetAudit(Guid id)
    {
        var audit = _reportVaultService.GetAuditTrail(id);
        return Ok(audit);
    }
}
