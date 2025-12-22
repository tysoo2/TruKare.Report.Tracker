using System.Windows;
using TruKare.Reports.Desktop.Api;
using TruKare.Reports.Desktop.Services;
using TruKare.Reports.Desktop.ViewModels;

namespace TruKare.Reports.Desktop;

public partial class MainWindow : Window
{
    private readonly ReminderService _reminderService;

    public MainWindow()
    {
        InitializeComponent();
        _reminderService = new ReminderService();
        var viewModel = new MainViewModel(new ReportApiClient(), new WorkspaceService(), _reminderService);
        DataContext = viewModel;

        _reminderService.RestoreRequested += (_, _) =>
        {
            if (WindowState == WindowState.Minimized)
            {
                WindowState = WindowState.Normal;
            }

            Activate();
            Topmost = true;
            Topmost = false;
        };
    }

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e);
        _reminderService.Dispose();
    }
}
