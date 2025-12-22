namespace TruKare.Reports.DTOs;

public class DashboardGroupBreakdown
{
    public string Key { get; set; } = string.Empty;

    public int InProgress { get; set; }

    public int Done { get; set; }

    public int Archived { get; set; }

    public int Locked { get; set; }
}
