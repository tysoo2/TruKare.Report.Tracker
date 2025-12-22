using System.Reflection;
using DbUp;
using DbUp.Engine.Output;
using Microsoft.Extensions.Logging;

namespace TruKare.Reports.Data;

public static class DatabaseMigrator
{
    public static void UpgradeDatabase(string? connectionString, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            logger.LogWarning("No database connection string configured. Skipping migrations.");
            return;
        }

        var upgrader = DeployChanges.To
            .PostgresqlDatabase(connectionString)
            .WithScriptsEmbeddedInAssembly(Assembly.GetExecutingAssembly(), scriptName => scriptName.Contains(".Migrations."))
            .LogTo(new DbUpToILogger(logger))
            .WithTransaction()
            .Build();

        var result = upgrader.PerformUpgrade();
        if (!result.Successful)
        {
            logger.LogError(result.Error, "Database migration failed.");
            throw result.Error;
        }

        logger.LogInformation("Database migrations applied successfully.");
    }

    private sealed class DbUpToILogger : IUpgradeLog
    {
        private readonly ILogger _logger;

        public DbUpToILogger(ILogger logger)
        {
            _logger = logger;
        }

        public void WriteError(string format, params object[] args)
        {
            _logger.LogError(format, args);
        }

        public void WriteInformation(string format, params object[] args)
        {
            _logger.LogInformation(format, args);
        }

        public void WriteWarning(string format, params object[] args)
        {
            _logger.LogWarning(format, args);
        }
    }
}
