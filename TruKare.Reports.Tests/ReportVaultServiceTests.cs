using FluentAssertions;
using Microsoft.Extensions.Options;
using TruKare.Reports.DTOs;
using TruKare.Reports.Models;
using TruKare.Reports.Options;
using TruKare.Reports.Repositories;
using TruKare.Reports.Services;

namespace TruKare.Reports.Tests;

public class ReportVaultServiceTests : IDisposable
{
    private readonly string _testRoot;
    private readonly VaultOptions _options;
    private readonly InMemoryReportRepository _repository;
    private readonly IHashService _hashService;
    private readonly INotificationService _notificationService;
    private readonly ReportVaultService _service;

    public ReportVaultServiceTests()
    {
        _testRoot = Path.Combine(Path.GetTempPath(), "ReportVaultServiceTests", Guid.NewGuid().ToString());
        _options = new VaultOptions
        {
            CanonicalRoot = Path.Combine(_testRoot, "Canonical"),
            FinalRoot = Path.Combine(_testRoot, "Final"),
            ArchiveRoot = Path.Combine(_testRoot, "Archive"),
            ConflictsRoot = Path.Combine(_testRoot, "Conflicts"),
            IntakeRoot = Path.Combine(_testRoot, "Intake"),
            WorkspaceRoot = Path.Combine(_testRoot, "Workspace")
        };

        _repository = new InMemoryReportRepository();
        _hashService = new Sha256HashService();
        _notificationService = new StubNotificationService();

        _service = new ReportVaultService(_repository, Options.Create(_options), _hashService, _notificationService);
    }

    [Fact]
    public async Task CheckoutAsync_creates_session_lock_and_copies_file()
    {
        var report = new Report
        {
            ReportId = Guid.NewGuid(),
            CanonicalPath = Path.Combine(_options.CanonicalRoot, "Acme", "Safety", "report.pdf"),
            CustomerName = "Acme Construction",
            UnitNumber = "Unit-123",
            ReportType = "Safety",
            CreatedAt = DateTime.UtcNow
        };

        _repository.UpsertReport(report);

        var response = await _service.CheckoutAsync(new CheckoutRequest
        {
            ReportId = report.ReportId,
            User = "alice",
            Host = "workstation-01"
        }, CancellationToken.None);

        File.Exists(response.LocalPath).Should().BeTrue();
        File.Exists(report.CanonicalPath).Should().BeTrue("checkout seeds a missing canonical copy");

        var reportLock = _repository.GetLock(report.ReportId);
        reportLock.Should().NotBeNull();
        reportLock!.LockedBy.Should().Be("alice");

        var session = _repository.GetSession(response.SessionId);
        session.Should().NotBeNull();
        session!.BaseHash.Should().Be(_hashService.ComputeHash(response.LocalPath));

        var updatedReport = _repository.GetReport(report.ReportId);
        updatedReport!.CurrentHash.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task CheckinAsync_without_changes_releases_lock_and_cleans_workspace()
    {
        var report = new Report
        {
            ReportId = Guid.NewGuid(),
            CanonicalPath = Path.Combine(_options.CanonicalRoot, "BuildRight", "Inspection", "report.pdf"),
            CustomerName = "BuildRight Partners",
            UnitNumber = "Unit-456",
            ReportType = "Inspection",
            CreatedAt = DateTime.UtcNow
        };

        _repository.UpsertReport(report);

        var checkout = await _service.CheckoutAsync(new CheckoutRequest
        {
            ReportId = report.ReportId,
            User = "bob",
            Host = "laptop-02"
        }, CancellationToken.None);

        var workspaceDirectory = Path.GetDirectoryName(checkout.LocalPath)!;

        await _service.CheckinAsync(new CheckinRequest
        {
            SessionId = checkout.SessionId,
            User = "bob"
        }, CancellationToken.None);

        _repository.GetLock(report.ReportId).Should().BeNull("lock is released after check-in without changes");
        _repository.GetSession(checkout.SessionId)!.EndReason.Should().Be(SessionEndReason.NoChanges);
        Directory.Exists(workspaceDirectory).Should().BeFalse();
    }

    public void Dispose()
    {
        if (Directory.Exists(_testRoot))
        {
            Directory.Delete(_testRoot, recursive: true);
        }
    }

    private class StubNotificationService : INotificationService
    {
        public Task NotifyAsync(string user, string subject, string message, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
