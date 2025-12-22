using System.ComponentModel.DataAnnotations;

namespace TruKare.Reports.DTOs;

public class FinalizeRequest
{
    [Required]
    public Guid SessionId { get; set; }
}
