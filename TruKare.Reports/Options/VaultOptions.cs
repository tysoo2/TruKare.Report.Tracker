namespace TruKare.Reports.Options;

public class VaultOptions
{
    public string CanonicalRoot { get; set; } = string.Empty;

    public string FinalRoot { get; set; } = string.Empty;

    public string ArchiveRoot { get; set; } = string.Empty;

    public string ConflictsRoot { get; set; } = string.Empty;

    /// <summary>
    /// Root folder for intake files used during initial report creation or external uploads before they are ingested into the canonical vault.
    /// </summary>
    public string IntakeRoot { get; set; } = string.Empty;

    public string WorkspaceRoot { get; set; } = string.Empty;
}
