namespace TruKare.Reports.Options;

public class AuthOptions
{
    /// <summary>
    /// Fully-qualified Active Directory group name (e.g., DOMAIN\\Group) used to grant admin privileges.
    /// </summary>
    public string AdminGroup { get; set; } = string.Empty;
}
