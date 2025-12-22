namespace TruKare.Reports.Services;

public interface IUserDirectoryService
{
    string NormalizeUser(string user);

    Task<string?> ResolveContactAsync(string user, CancellationToken cancellationToken);
}
