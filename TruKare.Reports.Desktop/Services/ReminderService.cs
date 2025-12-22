using System.Windows.Forms;
using System.Windows.Threading;
using TruKare.Reports.Desktop.Models;

namespace TruKare.Reports.Desktop.Services;

public sealed class ReminderService : IDisposable
{
    private readonly NotifyIcon _notifyIcon;
    private readonly DispatcherTimer _timer;
    private List<CheckoutReminder> _currentReminders = [];

    public event EventHandler? RestoreRequested;
    public event EventHandler<Guid>? CheckBackInRequested;

    public ReminderService()
    {
        _notifyIcon = new NotifyIcon
        {
            Icon = System.Drawing.SystemIcons.Information,
            Visible = true,
            Text = "TruKare Reports"
        };
        _notifyIcon.DoubleClick += (_, _) => RestoreRequested?.Invoke(this, EventArgs.Empty);
        _notifyIcon.ContextMenuStrip = BuildMenu();

        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMinutes(5)
        };
        _timer.Tick += (_, _) => ShowReminder();
        _timer.Start();
    }

    public void UpdateSessions(IEnumerable<CheckoutReminder> sessions)
    {
        _currentReminders = sessions.ToList();
        _notifyIcon.Text = _currentReminders.Count == 0
            ? "TruKare Reports (no active checkouts)"
            : $"TruKare Reports ({_currentReminders.Count} active)";
        RefreshMenu();
    }

    public void Dispose()
    {
        _timer.Stop();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
    }

    private ContextMenuStrip BuildMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open Desktop App", null, (_, _) => RestoreRequested?.Invoke(this, EventArgs.Empty));
        menu.Items.Add("Check Back In", null, (_, _) =>
        {
            var session = _currentReminders.FirstOrDefault();
            if (session != null)
            {
                CheckBackInRequested?.Invoke(this, session.SessionId);
            }
        });
        return menu;
    }

    private void RefreshMenu()
    {
        if (_notifyIcon.ContextMenuStrip == null || _notifyIcon.ContextMenuStrip.Items.Count < 2)
        {
            return;
        }

        _notifyIcon.ContextMenuStrip.Items[1].Enabled = _currentReminders.Any();
    }

    private void ShowReminder()
    {
        if (_currentReminders.Count == 0)
        {
            return;
        }

        var summary = string.Join(Environment.NewLine, _currentReminders.Take(3).Select(r =>
            $"{r.ReportName} since {r.StartedAt:t}"));
        _notifyIcon.ShowBalloonTip(5000, "Active checkouts", summary, ToolTipIcon.Info);
    }
}
