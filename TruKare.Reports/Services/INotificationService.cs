namespace TruKare.Reports.Services;

public interface INotificationService
{
    Task NotifyAsync(string user, string subject, string message, CancellationToken cancellationToken);
}
