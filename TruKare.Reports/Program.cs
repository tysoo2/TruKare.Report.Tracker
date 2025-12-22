using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TruKare.Reports.Data;
using TruKare.Reports.Options;
using TruKare.Reports.Repositories;
using TruKare.Reports.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("Reports");

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.Configure<VaultOptions>(builder.Configuration.GetSection("Vault"));
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
if (string.IsNullOrWhiteSpace(connectionString))
{
    builder.Services.AddSingleton<IReportRepository, InMemoryReportRepository>();
}
else
{
    builder.Services.AddSingleton<IReportRepository>(_ => new PostgresReportRepository(connectionString));
}
builder.Services.AddSingleton<IHashService, Sha256HashService>();
builder.Services.AddSingleton<INotificationService, ConsoleNotificationService>();
builder.Services.AddSingleton<IReportVaultService, ReportVaultService>();

var app = builder.Build();

if (!string.IsNullOrWhiteSpace(connectionString))
{
    var loggerFactory = app.Services.GetRequiredService<ILoggerFactory>();
    var logger = loggerFactory.CreateLogger("DatabaseMigrator");
    DatabaseMigrator.UpgradeDatabase(connectionString, logger);
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwaggerUI();
    app.UseSwagger();

}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
