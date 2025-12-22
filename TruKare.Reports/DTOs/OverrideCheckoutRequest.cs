using System.ComponentModel.DataAnnotations;

namespace TruKare.Reports.DTOs;

public class OverrideCheckoutRequest
{
    [Required]
    public Guid ReportId { get; set; }

    [Required]
    public string Reason { get; set; } = string.Empty;
}
