using TruKare.Reports.DTOs;
using TruKare.Reports.Models;

namespace TruKare.Reports.Services;

public interface IReportVaultService
{
    IEnumerable<Report> SearchReports(SearchReportsRequest request);

    ReportStatusResponse GetReportStatus(Guid reportId);

    Task<CheckoutResponse> CheckoutAsync(CheckoutRequest request, CancellationToken cancellationToken);

    Task<CheckoutResponse> OverrideCheckoutAsync(OverrideCheckoutRequest request, CancellationToken cancellationToken);

    Task CheckinAsync(CheckinRequest request, CancellationToken cancellationToken);

    Task FinalizeAsync(FinalizeRequest request, CancellationToken cancellationToken);

    IEnumerable<AuditEvent> GetAuditTrail(Guid reportId);

    /// <summary>
    /// Ingests a new report from the intake folder (used for initial report creation or external uploads) into the canonical vault.
    /// </summary>
    Task<Report> IngestIntakeAsync(IngestIntakeRequest request, CancellationToken cancellationToken);
}
