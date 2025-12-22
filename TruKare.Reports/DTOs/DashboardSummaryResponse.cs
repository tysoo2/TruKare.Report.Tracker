namespace TruKare.Reports.DTOs;

public class DashboardSummaryResponse
{
    public DashboardStatusCounts Totals { get; set; } = new();

    public IEnumerable<DashboardGroupBreakdown> ByCustomer { get; set; } = Array.Empty<DashboardGroupBreakdown>();

    public IEnumerable<DashboardGroupBreakdown> ByUnit { get; set; } = Array.Empty<DashboardGroupBreakdown>();

    public IEnumerable<DashboardGroupBreakdown> ByLockedBy { get; set; } = Array.Empty<DashboardGroupBreakdown>();
}
