using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Options;
using TruKare.Reports.Options;

namespace TruKare.Reports.Services;

public class EmailNotificationService : INotificationService
{
    private readonly NotificationOptions _options;
    private readonly IUserDirectoryService _userDirectory;
    private readonly ILogger<EmailNotificationService> _logger;

    public EmailNotificationService(
        IOptions<NotificationOptions> options,
        IUserDirectoryService userDirectory,
        ILogger<EmailNotificationService> logger)
    {
        _options = options.Value;
        _userDirectory = userDirectory;
        _logger = logger;
    }

    public async Task NotifyAsync(string user, string subject, string message, CancellationToken cancellationToken)
    {
        var recipient = await _userDirectory.ResolveContactAsync(user, cancellationToken);
        if (string.IsNullOrWhiteSpace(recipient))
        {
            _logger.LogWarning("Unable to resolve contact for user {User}. Notification skipped.", user);
            return;
        }

        if (string.IsNullOrWhiteSpace(_options.Smtp.Host) || string.IsNullOrWhiteSpace(_options.Smtp.Sender))
        {
            _logger.LogWarning("SMTP settings are incomplete; skipping email notification for {User}.", user);
            return;
        }

        using var mailMessage = new MailMessage(_options.Smtp.Sender, recipient, subject, message);
        using var smtpClient = new SmtpClient(_options.Smtp.Host, _options.Smtp.Port)
        {
            EnableSsl = _options.Smtp.UseSsl
        };

        if (!string.IsNullOrWhiteSpace(_options.Smtp.Username))
        {
            smtpClient.Credentials = new NetworkCredential(_options.Smtp.Username, _options.Smtp.Password);
        }

        cancellationToken.ThrowIfCancellationRequested();
        await smtpClient.SendMailAsync(mailMessage);
        _logger.LogInformation("Sent email notification to {Recipient} for user {User}.", recipient, user);
    }
}
