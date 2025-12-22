namespace TruKare.Reports.Options;

public enum NotificationChannel
{
    Console,
    Email,
    Teams
}

public class NotificationOptions
{
    public NotificationChannel Channel { get; set; } = NotificationChannel.Console;

    public SmtpOptions Smtp { get; set; } = new();

    public TeamsOptions Teams { get; set; } = new();

    public Dictionary<string, string> UserDirectory { get; set; } = new();
}

public class SmtpOptions
{
    public string Host { get; set; } = string.Empty;

    public int Port { get; set; } = 25;

    public string Sender { get; set; } = string.Empty;

    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public bool UseSsl { get; set; } = true;
}

public class TeamsOptions
{
    public string WebhookUrl { get; set; } = string.Empty;
}
