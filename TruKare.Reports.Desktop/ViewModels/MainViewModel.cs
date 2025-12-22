using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TruKare.Reports.Desktop.Api;
using TruKare.Reports.Desktop.Models;
using TruKare.Reports.Desktop.Services;

namespace TruKare.Reports.Desktop.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly ReportApiClient _apiClient;
    private readonly WorkspaceService _workspaceService;
    private readonly ReminderService _reminderService;
    private readonly IAsyncRelayCommand _searchCommand;
    private readonly IAsyncRelayCommand _checkoutSelectedCommand;
    private readonly IAsyncRelayCommand _checkinSelectedCommand;
    private readonly IAsyncRelayCommand _refreshStatusesCommand;
    private readonly RelayCommand _openLocalCopyCommand;

    [ObservableProperty] private string apiBaseUrl = "https://localhost:5001";
    [ObservableProperty] private string currentUser = Environment.UserName;
    [ObservableProperty] private string hostName = Environment.MachineName;
    [ObservableProperty] private string? customerName;
    [ObservableProperty] private string? unitNumber;
    [ObservableProperty] private string? reportType;
    [ObservableProperty] private bool includeArchived;
    [ObservableProperty] private string bannerText = "Ready.";
    [ObservableProperty] private string bannerSeverity = "Info";
    [ObservableProperty] private ReportItemViewModel? selectedReport;
    [ObservableProperty] private CheckoutSessionViewModel? selectedCheckout;

    public MainViewModel(ReportApiClient apiClient, WorkspaceService workspaceService, ReminderService reminderService)
    {
        _apiClient = apiClient;
        _workspaceService = workspaceService;
        _reminderService = reminderService;

        Reports = new ObservableCollection<ReportItemViewModel>();
        Reports.CollectionChanged += (_, _) => _refreshStatusesCommand.NotifyCanExecuteChanged();
        ActiveCheckouts = new ObservableCollection<CheckoutSessionViewModel>();
        ActiveCheckouts.CollectionChanged += (_, _) => SyncReminders();

        _reminderService.CheckBackInRequested += async (_, sessionId) => await CheckinBySessionId(sessionId);

        _searchCommand = new AsyncRelayCommand(SearchAsync);
        _checkoutSelectedCommand = new AsyncRelayCommand(CheckoutSelectedAsync, CanCheckoutSelected);
        _checkinSelectedCommand = new AsyncRelayCommand(CheckinSelectedAsync, () => SelectedCheckout != null);
        _refreshStatusesCommand = new AsyncRelayCommand(RefreshStatusesAsync, () => Reports.Count > 0);
        _openLocalCopyCommand = new RelayCommand(OpenLocalCopy, () => SelectedCheckout != null);
    }

    public ObservableCollection<ReportItemViewModel> Reports { get; }

    public ObservableCollection<CheckoutSessionViewModel> ActiveCheckouts { get; }

    public IAsyncRelayCommand SearchCommand => _searchCommand;

    public IAsyncRelayCommand CheckoutSelectedCommand => _checkoutSelectedCommand;

    public IAsyncRelayCommand CheckinSelectedCommand => _checkinSelectedCommand;

    public IAsyncRelayCommand RefreshStatusesCommand => _refreshStatusesCommand;

    public RelayCommand OpenLocalCopyCommand => _openLocalCopyCommand;

    partial void OnSelectedReportChanged(ReportItemViewModel? value) => CheckoutSelectedCommand.NotifyCanExecuteChanged();

    partial void OnSelectedCheckoutChanged(CheckoutSessionViewModel? value)
    {
        CheckinSelectedCommand.NotifyCanExecuteChanged();
        OpenLocalCopyCommand.NotifyCanExecuteChanged();
    }

    private async Task SearchAsync()
    {
        try
        {
            var request = new SearchReportsRequestDto(CustomerName, UnitNumber, ReportType, IncludeArchived);
            var reports = await _apiClient.SearchReportsAsync(ApiBaseUrl, request, CancellationToken.None);
            Reports.Clear();
            foreach (var report in reports.OrderBy(r => r.CustomerName))
            {
                Reports.Add(new ReportItemViewModel(report));
            }

            await RefreshStatusesAsync();
            _refreshStatusesCommand.NotifyCanExecuteChanged();
            SetBanner("Search completed.", "Success");
        }
        catch (Exception ex)
        {
            SetBanner(ex.Message, "Error");
        }
    }

    private async Task RefreshStatusesAsync()
    {
        if (Reports.Count == 0)
        {
            return;
        }

        try
        {
            var tasks = Reports.Select(async report =>
            {
                var status = await _apiClient.GetStatusAsync(ApiBaseUrl, report.ReportId, CancellationToken.None);
                report.UpdateStatus(status, CurrentUser);
            });

            await Task.WhenAll(tasks);
            SetBanner("Statuses refreshed.", "Info");
            _checkoutSelectedCommand.NotifyCanExecuteChanged();
        }
        catch (Exception ex)
        {
            SetBanner($"Unable to refresh: {ex.Message}", "Error");
        }
    }

    private bool CanCheckoutSelected() => SelectedReport != null && !SelectedReport.IsLocked;

    private async Task CheckoutSelectedAsync()
    {
        if (SelectedReport == null)
        {
            return;
        }

        try
        {
            var response = await _apiClient.CheckoutAsync(ApiBaseUrl, new CheckoutRequestDto
            {
                Host = HostName,
                ReportId = SelectedReport.ReportId,
                User = CurrentUser
            }, CancellationToken.None);

            var session = new CheckoutSessionViewModel(response.SessionId, response.ReportId, SelectedReport.DisplayName, string.Empty, DateTime.Now);
            var localPath = _workspaceService.PrepareWorkspace(session, response.LocalPath);
            session = new CheckoutSessionViewModel(response.SessionId, response.ReportId, SelectedReport.DisplayName, localPath, DateTime.Now);
            ActiveCheckouts.Add(session);
            SelectedCheckout = session;

            _workspaceService.LaunchAdobe(localPath);
            await RefreshStatusesAsync();
            SetBanner("Checkout complete. Adobe Reader launched for the local copy.", "Success");
            _checkoutSelectedCommand.NotifyCanExecuteChanged();
        }
        catch (Exception ex)
        {
            SetBanner($"Checkout failed: {ex.Message}", "Error");
        }
    }

    private async Task CheckinSelectedAsync()
    {
        if (SelectedCheckout == null)
        {
            return;
        }

        await CheckinBySessionId(SelectedCheckout.SessionId);
    }

    private async Task CheckinBySessionId(Guid sessionId)
    {
        var session = ActiveCheckouts.FirstOrDefault(s => s.SessionId == sessionId);
        if (session == null)
        {
            return;
        }

        try
        {
            _workspaceService.EnsureFileClosed(session.LocalPath);
            await _apiClient.CheckinAsync(ApiBaseUrl, new CheckinRequestDto
            {
                SessionId = session.SessionId,
                User = CurrentUser
            }, CancellationToken.None);

            ActiveCheckouts.Remove(session);
            _workspaceService.DeleteWorkspace(session.ReportId);
            await RefreshStatusesAsync();
            SetBanner($"Checked in {session.ReportName}.", "Success");
            _checkoutSelectedCommand.NotifyCanExecuteChanged();
        }
        catch (Exception ex)
        {
            SetBanner($"Check-in failed: {ex.Message}", "Error");
        }
    }

    private void OpenLocalCopy()
    {
        if (SelectedCheckout == null || !File.Exists(SelectedCheckout.LocalPath))
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = SelectedCheckout.LocalPath,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            SetBanner($"Unable to open file: {ex.Message}", "Error");
        }
    }

    private void SyncReminders()
    {
        var reminders = ActiveCheckouts
            .Select(s => new CheckoutReminder(s.SessionId, s.ReportName, s.StartedAt, s.LocalPath))
            .ToList();
        _reminderService.UpdateSessions(reminders);
    }

    private void SetBanner(string message, string severity)
    {
        BannerText = message;
        BannerSeverity = severity;
    }
}
