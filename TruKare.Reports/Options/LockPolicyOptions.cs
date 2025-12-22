namespace TruKare.Reports.Options;

public class LockPolicyOptions
{
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromMinutes(1);

    public List<TimeOnly> ReminderTimes { get; set; } = new();

    public List<TimeOnly> AutoReleaseTimes { get; set; } = new();

    public TimeOnly? DailySweepTime { get; set; } = new TimeOnly(3, 0);

    public TimeSpan MinimumLockAgeBeforeRelease { get; set; } = TimeSpan.FromMinutes(15);

    public TimeSpan MaxLockAge { get; set; } = TimeSpan.FromHours(24);
}
