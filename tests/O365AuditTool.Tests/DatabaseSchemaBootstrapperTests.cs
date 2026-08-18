using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using O365AuditTool.Data;
using Xunit;

namespace O365AuditTool.Tests;

public class DatabaseSchemaBootstrapperTests
{
    [Fact]
    public void ConfigureConcurrentAccess_EnablesWalForFileDatabase()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"o365audit-wal-{Guid.NewGuid():N}.db");
        try
        {
            var options = new DbContextOptionsBuilder<AuditDbContext>()
                .UseSqlite($"Data Source={databasePath}")
                .Options;
            using var db = new AuditDbContext(options);
            db.Database.EnsureCreated();

            DatabaseSchemaBootstrapper.ConfigureConcurrentAccess(db);

            using var command = db.Database.GetDbConnection().CreateCommand();
            db.Database.OpenConnection();
            command.CommandText = "PRAGMA journal_mode;";
            Assert.Equal("wal", Convert.ToString(command.ExecuteScalar()));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var suffix in new[] { string.Empty, "-wal", "-shm" })
            {
                var path = databasePath + suffix;
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
        }
    }

    [Fact]
    public void EnsureCurrentSchema_AddsCopyAndLegacyTablesToExistingDatabase()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();

        using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                CREATE TABLE "Devices" (
                    "Id" INTEGER NOT NULL CONSTRAINT "PK_Devices" PRIMARY KEY AUTOINCREMENT
                );
                """;
            command.ExecuteNonQuery();
        }

        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;

        using var db = new AuditDbContext(options);
        DatabaseSchemaBootstrapper.EnsureCurrentSchema(db);

        using var tableCommand = connection.CreateCommand();
        tableCommand.CommandText =
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('LegacyFiles', 'ArtifactCopyJobs', 'ArtifactCopyItems') ORDER BY name;";

        using var reader = tableCommand.ExecuteReader();
        var tables = new List<string>();
        while (reader.Read())
        {
            tables.Add(reader.GetString(0));
        }

        Assert.Equal(["ArtifactCopyItems", "ArtifactCopyJobs", "LegacyFiles"], tables);
    }

    [Fact]
    public void EnsureCurrentSchema_AddsInventoryColumnsIdempotentlyToExistingDatabase()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();

        using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                CREATE TABLE "Devices" (
                    "Id" INTEGER NOT NULL CONSTRAINT "PK_Devices" PRIMARY KEY AUTOINCREMENT
                );
                CREATE TABLE "Profiles" (
                    "Id" INTEGER NOT NULL CONSTRAINT "PK_Profiles" PRIMARY KEY AUTOINCREMENT,
                    "DeviceInventoryId" INTEGER NOT NULL,
                    "Sid" TEXT NOT NULL,
                    "ProfileName" TEXT NOT NULL
                );
                CREATE TABLE "PstFiles" (
                    "Id" INTEGER NOT NULL CONSTRAINT "PK_PstFiles" PRIMARY KEY AUTOINCREMENT,
                    "DeviceInventoryId" INTEGER NOT NULL,
                    "Sid" TEXT NOT NULL,
                    "Path" TEXT NOT NULL
                );
                CREATE TABLE "OfficeProcesses" (
                    "Id" INTEGER NOT NULL CONSTRAINT "PK_OfficeProcesses" PRIMARY KEY AUTOINCREMENT,
                    "DeviceInventoryId" INTEGER NOT NULL,
                    "ProcessName" TEXT NOT NULL
                );
                CREATE TABLE "Disks" (
                    "Id" INTEGER NOT NULL CONSTRAINT "PK_Disks" PRIMARY KEY AUTOINCREMENT,
                    "DeviceInventoryId" INTEGER NOT NULL,
                    "Model" TEXT NULL
                );
                CREATE TABLE "OfficeProducts" (
                    "Id" INTEGER NOT NULL CONSTRAINT "PK_OfficeProducts" PRIMARY KEY AUTOINCREMENT,
                    "DeviceInventoryId" INTEGER NOT NULL,
                    "Name" TEXT NOT NULL
                );
                CREATE TABLE "MailAccounts" (
                    "Id" INTEGER NOT NULL CONSTRAINT "PK_MailAccounts" PRIMARY KEY AUTOINCREMENT,
                    "DeviceInventoryId" INTEGER NOT NULL,
                    "Sid" TEXT NOT NULL,
                    "AccountType" TEXT NOT NULL
                );
                CREATE TABLE "RetryQueue" (
                    "Id" INTEGER NOT NULL CONSTRAINT "PK_RetryQueue" PRIMARY KEY AUTOINCREMENT,
                    "DeviceName" TEXT NOT NULL,
                    "ScanJobId" TEXT NOT NULL,
                    "Attempt" INTEGER NOT NULL,
                    "NextAttemptUtc" TEXT NOT NULL,
                    "CreatedUtc" TEXT NOT NULL
                );
                """;
            command.ExecuteNonQuery();
        }

        var options = new DbContextOptionsBuilder<AuditDbContext>()
            .UseSqlite(connection)
            .Options;

        using var db = new AuditDbContext(options);
        DatabaseSchemaBootstrapper.EnsureCurrentSchema(db);
        DatabaseSchemaBootstrapper.EnsureCurrentSchema(db);

        AssertColumns(connection, "Profiles", "ProfilePath", "UserName", "Loaded", "IsDefault");
        AssertColumns(connection, "PstFiles", "ProfileName");
        AssertColumns(connection, "OfficeProcesses", "Owner", "SessionId");
        AssertColumns(connection, "MailAccounts", "IsActive");
        AssertColumns(connection, "RetryQueue", "Ou", "Site");
        AssertColumns(connection, "Devices", "CurrentLoggedOnUser");
        AssertColumns(connection, "Disks", "BusType");
        AssertColumns(connection, "OfficeProducts", "Architecture", "UpdateChannel", "ProductIds", "UpdatesEnabled");

        using var insert = connection.CreateCommand();
        insert.CommandText =
            "INSERT INTO \"Profiles\" (\"DeviceInventoryId\", \"Sid\", \"ProfileName\") VALUES (1, 'sid', 'profile'); " +
            "SELECT \"Loaded\" FROM \"Profiles\" WHERE \"Id\" = last_insert_rowid();";
        Assert.Equal(0L, (long)insert.ExecuteScalar()!);
    }

    private static void AssertColumns(SqliteConnection connection, string tableName, params string[] expectedColumns)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info(\"{tableName}\");";
        using var reader = command.ExecuteReader();
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (reader.Read())
        {
            columns.Add(reader.GetString(1));
        }

        foreach (var expectedColumn in expectedColumns)
        {
            Assert.Contains(expectedColumn, columns);
        }
    }
}
