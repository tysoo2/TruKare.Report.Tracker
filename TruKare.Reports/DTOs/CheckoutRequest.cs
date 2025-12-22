using System.ComponentModel.DataAnnotations;

namespace TruKare.Reports.DTOs;

public class CheckoutRequest
{
    [Required]
    public Guid ReportId { get; set; }

    [Required]
    public string User { get; set; } = string.Empty;

    [Required]
    public string Host { get; set; } = string.Empty;

    public bool IsAdmin { get; set; }

    public string? OverrideReason { get; set; }
}
