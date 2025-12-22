using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using TruKare.Reports.Authorization;
using TruKare.Reports.Models;
using TruKare.Reports.Options;
using TruKare.Reports.Repositories;
using TruKare.Reports.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
    .AddNegotiate();

builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    options.AddPolicy(AdminPolicies.AdminGroup, policy =>
    {
        policy.Requirements.Add(new AdminGroupRequirement());
    });
});
builder.Services.AddScoped<IAuthorizationHandler, AdminGroupHandler>();
builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection("Auth"));
builder.Services.AddScoped<IAdminGroupValidator, WindowsAdminGroupValidator>();
builder.Services.AddScoped<IUserContextAccessor, HttpContextUserContextAccessor>();
builder.Services.AddHttpContextAccessor();

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.Configure<VaultOptions>(builder.Configuration.GetSection("Vault"));
builder.Services.AddHttpContextAccessor();
builder.Services.PostConfigure<VaultOptions>(options =>
{
    var baseVault = Path.Combine(builder.Environment.ContentRootPath, "Vault");
    options.CanonicalRoot = string.IsNullOrWhiteSpace(options.CanonicalRoot) ? Path.Combine(baseVault, "Canonical") : options.CanonicalRoot;
    options.FinalRoot = string.IsNullOrWhiteSpace(options.FinalRoot) ? Path.Combine(baseVault, "Final") : options.FinalRoot;
    options.ArchiveRoot = string.IsNullOrWhiteSpace(options.ArchiveRoot) ? Path.Combine(baseVault, "Archive") : options.ArchiveRoot;
    options.ConflictsRoot = string.IsNullOrWhiteSpace(options.ConflictsRoot) ? Path.Combine(baseVault, "Conflicts") : options.ConflictsRoot;
    options.IntakeRoot = string.IsNullOrWhiteSpace(options.IntakeRoot) ? Path.Combine(baseVault, "Intake") : options.IntakeRoot;
    options.WorkspaceRoot = string.IsNullOrWhiteSpace(options.WorkspaceRoot) ? Path.Combine(baseVault, "Workspace") : options.WorkspaceRoot;
});
builder.Services.AddSingleton<IReportRepository, PostgresReportRepository>();
builder.Services.AddSingleton<IHashService, Sha256HashService>();
builder.Services.AddSingleton<INotificationService, ConsoleNotificationService>();
builder.Services.AddSingleton<IAdminAuthorizationService, AdminAuthorizationService>();
builder.Services.AddSingleton<IReportVaultService, ReportVaultService>();
builder.Services.AddHostedService<LockPolicyBackgroundService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwaggerUI();
    app.UseSwagger();

}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

SeedVault(app.Services, app.Environment.ContentRootPath);

app.Run();

static void SeedVault(IServiceProvider services, string contentRoot)
{
    using var scope = services.CreateScope();
    var options = scope.ServiceProvider.GetRequiredService<IOptions<VaultOptions>>();
    var repository = scope.ServiceProvider.GetRequiredService<IReportRepository>();
    var hashService = scope.ServiceProvider.GetRequiredService<IHashService>();

    var baseVault = Path.Combine(contentRoot, "Vault");
    var configured = options.Value;
    configured.CanonicalRoot = string.IsNullOrWhiteSpace(configured.CanonicalRoot) ? Path.Combine(baseVault, "Canonical") : configured.CanonicalRoot;
    configured.FinalRoot = string.IsNullOrWhiteSpace(configured.FinalRoot) ? Path.Combine(baseVault, "Final") : configured.FinalRoot;
    configured.ArchiveRoot = string.IsNullOrWhiteSpace(configured.ArchiveRoot) ? Path.Combine(baseVault, "Archive") : configured.ArchiveRoot;
    configured.ConflictsRoot = string.IsNullOrWhiteSpace(configured.ConflictsRoot) ? Path.Combine(baseVault, "Conflicts") : configured.ConflictsRoot;
    configured.IntakeRoot = string.IsNullOrWhiteSpace(configured.IntakeRoot) ? Path.Combine(baseVault, "Intake") : configured.IntakeRoot;
    configured.WorkspaceRoot = string.IsNullOrWhiteSpace(configured.WorkspaceRoot) ? Path.Combine(baseVault, "Workspace") : configured.WorkspaceRoot;

    Directory.CreateDirectory(configured.CanonicalRoot);
    Directory.CreateDirectory(configured.FinalRoot);
    Directory.CreateDirectory(configured.ArchiveRoot);
    Directory.CreateDirectory(configured.ConflictsRoot);
    Directory.CreateDirectory(configured.IntakeRoot);
    Directory.CreateDirectory(configured.WorkspaceRoot);

    var reports = new[]
    {
        new Report
        {
            ReportId = Guid.Parse("8f0c2cce-3d08-4d1f-9abc-77fd88bf8197"),
            CustomerName = "Acme Construction",
            UnitNumber = "Unit-1001",
            ReportType = "Safety",
            CreatedAt = DateTime.UtcNow.AddDays(-10),
            CanonicalPath = Path.Combine(configured.CanonicalRoot, "Acme", "Unit-1001", "Safety", "safety-report.pdf"),
            Status = ReportStatus.InProgress,
            CurrentRevision = 1
        },
        new Report
        {
            ReportId = Guid.Parse("e7b8c36a-8464-4ffd-b0a7-8fc25c6998c8"),
            CustomerName = "BuildRight Partners",
            UnitNumber = "Unit-2005",
            ReportType = "Inspection",
            CreatedAt = DateTime.UtcNow.AddDays(-4),
            CanonicalPath = Path.Combine(configured.CanonicalRoot, "BuildRight", "Unit-2005", "Inspection", "inspection-report.pdf"),
            Status = ReportStatus.InProgress,
            CurrentRevision = 2
        }
    };

    foreach (var report in reports)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(report.CanonicalPath)!);
        if (!File.Exists(report.CanonicalPath))
        {
            File.WriteAllText(report.CanonicalPath, $"Initial content for {report.ReportType} report");
        }

        report.CurrentHash = hashService.ComputeHash(report.CanonicalPath);
        repository.UpsertReport(report);
    }
}
