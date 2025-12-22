using System.Diagnostics;
using TruKare.Reports.Desktop.ViewModels;

namespace TruKare.Reports.Desktop.Services;

public class WorkspaceService
{
    private const string RootFolder = "TruKareReports";
    private const string WorkFolder = "Work";

    public string WorkspaceRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        RootFolder,
        WorkFolder);

    public string PrepareWorkspace(CheckoutSessionViewModel session, string? remotePath = null)
    {
        var directory = Path.Combine(WorkspaceRoot, session.ReportId.ToString());
        Directory.CreateDirectory(directory);
        var fileName = !string.IsNullOrWhiteSpace(remotePath)
            ? Path.GetFileName(remotePath)
            : $"{session.ReportId}.pdf";
        var localPath = Path.Combine(directory, fileName);

        if (!string.IsNullOrWhiteSpace(remotePath) && File.Exists(remotePath))
        {
            File.Copy(remotePath, localPath, overwrite: true);
        }
        else if (!File.Exists(localPath))
        {
            File.WriteAllText(localPath, $"Placeholder for {session.ReportName}. Replace with the synced PDF if needed.");
        }

        return localPath;
    }

    public void EnsureFileClosed(string path)
    {
        try
        {
            using var stream = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException ex)
        {
            throw new InvalidOperationException("Please save and close the PDF before checking back in.", ex);
        }
    }

    public void LaunchAdobe(string localPath)
    {
        if (!File.Exists(localPath))
        {
            throw new FileNotFoundException("Local copy not found.", localPath);
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = localPath,
            UseShellExecute = true
        };

        Process.Start(startInfo);
    }

    public void DeleteWorkspace(Guid reportId)
    {
        var directory = Path.Combine(WorkspaceRoot, reportId.ToString());
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
