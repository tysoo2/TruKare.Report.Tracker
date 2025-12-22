using Microsoft.Extensions.Options;
using TruKare.Reports.Options;

namespace TruKare.Reports.Services;

public class ConfigurationUserDirectoryService : IUserDirectoryService
{
    private readonly Dictionary<string, string> _directory;

    public ConfigurationUserDirectoryService(IOptions<NotificationOptions> options)
    {
        _directory = new Dictionary<string, string>(options.Value.UserDirectory, StringComparer.OrdinalIgnoreCase);
    }

    public string NormalizeUser(string user)
    {
        return user?.Trim() ?? string.Empty;
    }

    public Task<string?> ResolveContactAsync(string user, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(user))
        {
            return Task.FromResult<string?>(null);
        }

        var normalized = NormalizeUser(user);
        if (_directory.TryGetValue(normalized, out var mapped))
        {
            return Task.FromResult<string?>(mapped);
        }

        var shortNameIndex = normalized.IndexOf('\\');
        if (shortNameIndex >= 0)
        {
            var shortName = normalized[(shortNameIndex + 1)..];
            if (_directory.TryGetValue(shortName, out var shortMapped))
            {
                return Task.FromResult<string?>(shortMapped);
            }
        }

        return Task.FromResult<string?>(null);
    }
}
