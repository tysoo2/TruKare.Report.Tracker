using System.ComponentModel.DataAnnotations;

namespace TruKare.Reports.DTOs;

public class CheckinRequest
{
    [Required]
    public Guid SessionId { get; set; }

    [Required]
    public string User { get; set; } = string.Empty;
}
