using System.ComponentModel.DataAnnotations;

namespace TruKare.Reports.DTOs;

public class OverrideCheckoutRequest
{
    [Required]
    public Guid ReportId { get; set; }

    [Required]
    public string AdminUser { get; set; } = string.Empty;

    [Required]
    public string Host { get; set; } = string.Empty;

    [Required]
    public string Reason { get; set; } = string.Empty;
}
