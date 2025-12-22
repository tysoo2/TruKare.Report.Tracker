using System.Collections.Concurrent;

namespace TruKare.Reports.Services;

public class FanOutNotificationService : INotificationService
{
    private static readonly ConcurrentQueue<NotificationRequest> Outgoing = new();
    private static readonly NotificationChannel[] DefaultChannels =
        { NotificationChannel.Email, NotificationChannel.Teams, NotificationChannel.DesktopToast };

    public Task NotifyAsync(NotificationRequest request, CancellationToken cancellationToken)
    {
        Outgoing.Enqueue(request);

        var channels = request.Channels != null && request.Channels.Count > 0
            ? request.Channels
            : DefaultChannels;

        foreach (var channel in channels)
        {
            // In a real implementation, this would call an out-of-process dispatcher
            // so delivery does not depend on the desktop app running.
            Console.WriteLine($"[Notify:{channel}] To: {request.User} | {request.Subject} | {request.Message}");
        }

        return Task.CompletedTask;
    }
}
