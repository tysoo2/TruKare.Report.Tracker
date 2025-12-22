namespace TruKare.Reports.Services;

public interface INotificationService
{
    Task NotifyAsync(NotificationRequest request, CancellationToken cancellationToken);
}
