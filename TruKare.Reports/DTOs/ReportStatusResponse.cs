using TruKare.Reports.Models;

namespace TruKare.Reports.DTOs;

public class ReportStatusResponse
{
    public Guid ReportId { get; set; }

    public ReportStatus Status { get; set; }

    public ReportLock? Lock { get; set; }
}
