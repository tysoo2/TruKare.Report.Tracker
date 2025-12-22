using System.Net.Http.Json;
using System.Text;
using Microsoft.Extensions.Options;
using TruKare.Reports.Options;

namespace TruKare.Reports.Services;

public class TeamsNotificationService : INotificationService
{
    private readonly HttpClient _httpClient;
    private readonly NotificationOptions _options;
    private readonly IUserDirectoryService _userDirectory;
    private readonly ILogger<TeamsNotificationService> _logger;

    public TeamsNotificationService(
        HttpClient httpClient,
        IOptions<NotificationOptions> options,
        IUserDirectoryService userDirectory,
        ILogger<TeamsNotificationService> logger)
    {
        _httpClient = httpClient;
        _options = options.Value;
        _userDirectory = userDirectory;
        _logger = logger;
    }

    public async Task NotifyAsync(string user, string subject, string message, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.Teams.WebhookUrl))
        {
            _logger.LogWarning("Teams webhook URL not configured; skipping notification for {User}.", user);
            return;
        }

        var contact = await _userDirectory.ResolveContactAsync(user, cancellationToken) ?? user;
        var cardText = new StringBuilder()
            .AppendLine($"**To:** {contact}")
            .AppendLine($"**Subject:** {subject}")
            .AppendLine(message)
            .ToString();

        var payload = new { text = cardText };
        try
        {
            var response = await _httpClient.PostAsJsonAsync(_options.Teams.WebhookUrl, payload, cancellationToken);
            response.EnsureSuccessStatusCode();
            _logger.LogInformation("Sent Teams notification for user {User} to contact {Contact}.", user, contact);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send Teams notification for user {User}.", user);
        }
    }
}
