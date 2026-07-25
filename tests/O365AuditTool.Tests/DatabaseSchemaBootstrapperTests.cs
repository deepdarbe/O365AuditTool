using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using O365AuditTool.Data;
using Xunit;

namespace O365AuditTool.Tests;

public class DatabaseSchemaBootstrapperTests
{
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
}
