namespace TruKare.Reports.DTOs;

public class CheckoutResponse
{
    public Guid SessionId { get; set; }

    public Guid ReportId { get; set; }

    public string LocalPath { get; set; } = string.Empty;

    public string Message { get; set; } = string.Empty;
}
