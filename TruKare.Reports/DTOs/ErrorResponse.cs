namespace TruKare.Reports.DTOs;

public record ErrorResponse
{
    public string Code { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public static ErrorResponse Forbidden(string message) => new() { Code = "forbidden", Message = message };
}
