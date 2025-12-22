namespace TruKare.Reports.Services;

public class NotificationRequest
{
    public string User { get; init; } = string.Empty;

    public string Subject { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public IReadOnlyCollection<NotificationChannel> Channels { get; init; } =
        new[] { NotificationChannel.Email, NotificationChannel.Teams, NotificationChannel.DesktopToast };

    public IDictionary<string, string>? Metadata { get; init; }
}
