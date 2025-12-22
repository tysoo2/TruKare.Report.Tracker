using System.ComponentModel.DataAnnotations;

namespace TruKare.Reports.DTOs;

public class CheckoutRequest
{
    [Required]
    public Guid ReportId { get; set; }

    public string? OverrideReason { get; set; }
}
