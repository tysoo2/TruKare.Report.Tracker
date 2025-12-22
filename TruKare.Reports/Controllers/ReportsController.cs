using Microsoft.AspNetCore.Mvc;
using TruKare.Reports.DTOs;
using TruKare.Reports.Services;

namespace TruKare.Reports.Controllers;

[ApiController]
[Route("reports")]
public class ReportsController : ControllerBase
{
    private readonly IReportVaultService _reportVaultService;

    public ReportsController(IReportVaultService reportVaultService)
    {
        _reportVaultService = reportVaultService;
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
    public async Task<IActionResult> OverrideCheckout([FromBody] OverrideCheckoutRequest request, CancellationToken cancellationToken)
    {
        var response = await _reportVaultService.OverrideCheckoutAsync(request, cancellationToken);
        return Ok(response);
    }

    [HttpPost("checkin")]
    public async Task<IActionResult> Checkin([FromBody] CheckinRequest request, CancellationToken cancellationToken)
    {
        await _reportVaultService.CheckinAsync(request, cancellationToken);
        return Ok();
    }

    [HttpPost("finalize")]
    public async Task<IActionResult> Finalize([FromBody] FinalizeRequest request, CancellationToken cancellationToken)
    {
        await _reportVaultService.FinalizeAsync(request, cancellationToken);
        return Ok();
    }

    [HttpGet("{id:guid}/audit")]
    public IActionResult GetAudit(Guid id)
    {
        var audit = _reportVaultService.GetAuditTrail(id);
        return Ok(audit);
    }

    [HttpGet("dashboard")]
    public IActionResult GetDashboard()
    {
        var summary = _reportVaultService.GetDashboardSummary();
        return Ok(summary);
    }

    [HttpGet("conflicts")]
    public IActionResult ListConflicts()
    {
        var issues = _reportVaultService.GetConflicts();
        return Ok(issues);
    }

    [HttpGet("orphans")]
    public IActionResult ListOrphans()
    {
        var issues = _reportVaultService.GetOrphans();
        return Ok(issues);
    }
}
