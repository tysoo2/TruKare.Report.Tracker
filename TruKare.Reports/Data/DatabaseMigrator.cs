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
            .WithScriptsEmbeddedInAssembly(
                Assembly.GetExecutingAssembly(),
                scriptName => scriptName.Contains(".Migrations."))
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

    /// <summary>
    /// Adapter from DbUp's IUpgradeLog to Microsoft.Extensions.Logging.ILogger.
    /// Matches newer DbUp versions that require Log* methods.
    /// </summary>
    private sealed class DbUpToILogger : IUpgradeLog
    {
        private readonly ILogger _logger;

        public DbUpToILogger(ILogger logger) => _logger = logger;

        public void LogTrace(string format, params object[] args)
            => LogSafely(LogLevel.Trace, null, format, args);

        public void LogDebug(string format, params object[] args)
            => LogSafely(LogLevel.Debug, null, format, args);

        public void LogInformation(string format, params object[] args)
            => LogSafely(LogLevel.Information, null, format, args);

        public void LogWarning(string format, params object[] args)
            => LogSafely(LogLevel.Warning, null, format, args);

        public void LogError(string format, params object[] args)
            => LogSafely(LogLevel.Error, null, format, args);

        public void LogError(Exception exception, string format, params object[] args)
            => LogSafely(LogLevel.Error, exception, format, args);

        /// <summary>
        /// DbUp provides "format + args" where the "format" is often already formatted text,
        /// and may contain braces. Logging frameworks treat braces as templates.
        /// This helper avoids template issues by formatting first when args are provided.
        /// </summary>
        private void LogSafely(LogLevel level, Exception? ex, string format, object[] args)
        {
            // If args exist, treat "format" as a .NET format string.
            // If no args, log the message as plain text (not a template).
            var message = (args is { Length: > 0 })
                ? string.Format(format, args)
                : format;

            if (ex is null)
            {
                _logger.Log(level, "{Message}", message);
            }
            else
            {
                _logger.Log(level, ex, "{Message}", message);
            }
        }
    }
}
