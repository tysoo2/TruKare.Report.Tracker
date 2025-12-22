namespace TruKare.Reports.Options;

public class AccessControlOptions
{
    public List<string> FinalWriteIdentities { get; set; } = new();

    public List<string> CanonicalWriteIdentities { get; set; } = new();
}
