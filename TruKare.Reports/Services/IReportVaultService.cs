using TruKare.Reports.DTOs;
using TruKare.Reports.Models;
using TruKare.Reports.Authorization;

namespace TruKare.Reports.Services;

public interface IReportVaultService
{
    IEnumerable<Report> SearchReports(SearchReportsRequest request);

    ReportStatusResponse GetReportStatus(Guid reportId);

    Task<CheckoutResponse> CheckoutAsync(CheckoutRequest request, RequestUserContext userContext, CancellationToken cancellationToken);

    Task<CheckoutResponse> OverrideCheckoutAsync(OverrideCheckoutRequest request, RequestUserContext userContext, CancellationToken cancellationToken);

    Task CheckinAsync(CheckinRequest request, RequestUserContext userContext, CancellationToken cancellationToken);

    Task FinalizeAsync(FinalizeRequest request, RequestUserContext userContext, CancellationToken cancellationToken);

    IEnumerable<AuditEvent> GetAuditTrail(Guid reportId);
}
