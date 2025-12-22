namespace TruKare.Reports.Desktop.Models;

public record CheckoutReminder(Guid SessionId, string ReportName, DateTime StartedAt, string LocalPath);
