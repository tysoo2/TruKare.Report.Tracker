namespace TruKare.Reports.Services;

public class ConsoleNotificationService : INotificationService
{
    public Task NotifyAsync(string user, string subject, string message, CancellationToken cancellationToken)
    {
        Console.WriteLine($"[Notify] To: {user} | {subject} | {message}");
        return Task.CompletedTask;
    }
}
