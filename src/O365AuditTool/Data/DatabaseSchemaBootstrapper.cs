using Microsoft.EntityFrameworkCore;
using System.Data;

namespace O365AuditTool.Data;

public static class DatabaseSchemaBootstrapper
{
    public static void EnsureCurrentSchema(AuditDbContext db)
    {
        db.Database.ExecuteSqlRaw(
            """
            CREATE TABLE IF NOT EXISTS "LegacyFiles" (
                "Id" INTEGER NOT NULL CONSTRAINT "PK_LegacyFiles" PRIMARY KEY AUTOINCREMENT,
                "DeviceInventoryId" INTEGER NOT NULL,
                "Sid" TEXT NOT NULL,
                "UserName" TEXT NULL,
                "UserPrincipalName" TEXT NULL,
                "ProfileName" TEXT NULL,
                "ArtifactType" TEXT NOT NULL,
                "Path" TEXT NOT NULL,
                "SizeBytes" INTEGER NOT NULL,
                "ExistsOnDisk" INTEGER NOT NULL,
                "LastWriteUtc" TEXT NULL,
                CONSTRAINT "FK_LegacyFiles_Devices_DeviceInventoryId"
                    FOREIGN KEY ("DeviceInventoryId") REFERENCES "Devices" ("Id") ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS "IX_LegacyFiles_DeviceInventoryId_Sid_Path"
                ON "LegacyFiles" ("DeviceInventoryId", "Sid", "Path");

            CREATE TABLE IF NOT EXISTS "ArtifactCopyJobs" (
                "Id" TEXT NOT NULL CONSTRAINT "PK_ArtifactCopyJobs" PRIMARY KEY,
                "RequestedBy" TEXT NOT NULL,
                "ExecutedBy" TEXT NULL,
                "TargetRoot" TEXT NOT NULL,
                "CreatedUtc" TEXT NOT NULL,
                "StartedUtc" TEXT NULL,
                "QueuedUtc" TEXT NULL,
                "CompletedUtc" TEXT NULL,
                "Status" INTEGER NOT NULL,
                "Notes" TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS "IX_ArtifactCopyJobs_Status_CreatedUtc"
                ON "ArtifactCopyJobs" ("Status", "CreatedUtc");

            CREATE TABLE IF NOT EXISTS "ArtifactCopyItems" (
                "Id" INTEGER NOT NULL CONSTRAINT "PK_ArtifactCopyItems" PRIMARY KEY AUTOINCREMENT,
                "ArtifactCopyJobId" TEXT NOT NULL,
                "DeviceName" TEXT NOT NULL,
                "UserKey" TEXT NOT NULL,
                "ProfileName" TEXT NULL,
                "ArtifactType" TEXT NOT NULL,
                "SourcePath" TEXT NOT NULL,
                "SourceSizeBytes" INTEGER NOT NULL,
                "SourceLastWriteUtc" TEXT NULL,
                "DestinationPath" TEXT NOT NULL,
                "Status" INTEGER NOT NULL,
                "Attempts" INTEGER NOT NULL,
                "ErrorMessage" TEXT NULL,
                "CopiedUtc" TEXT NULL,
                "DestinationSizeBytes" INTEGER NULL,
                "Sha256" TEXT NULL,
                CONSTRAINT "FK_ArtifactCopyItems_ArtifactCopyJobs_ArtifactCopyJobId"
                    FOREIGN KEY ("ArtifactCopyJobId") REFERENCES "ArtifactCopyJobs" ("Id") ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS "IX_ArtifactCopyItems_ArtifactCopyJobId_Status"
                ON "ArtifactCopyItems" ("ArtifactCopyJobId", "Status");
            """);

        AddColumnIfMissing(db, "Profiles", "ProfilePath", "TEXT NULL");
        AddColumnIfMissing(db, "Profiles", "UserName", "TEXT NULL");
        AddColumnIfMissing(db, "Profiles", "Loaded", "INTEGER NOT NULL DEFAULT 0");
        AddColumnIfMissing(db, "Profiles", "IsDefault", "INTEGER NOT NULL DEFAULT 0");
        AddColumnIfMissing(db, "PstFiles", "ProfileName", "TEXT NULL");
        AddColumnIfMissing(db, "OfficeProcesses", "Owner", "TEXT NULL");
        AddColumnIfMissing(db, "OfficeProcesses", "SessionId", "INTEGER NULL");
        AddColumnIfMissing(db, "MailAccounts", "IsActive", "INTEGER NOT NULL DEFAULT 0");
        AddColumnIfMissing(db, "ArtifactCopyJobs", "ExecutedBy", "TEXT NULL");
        AddColumnIfMissing(db, "ArtifactCopyJobs", "QueuedUtc", "TEXT NULL");
        AddColumnIfMissing(db, "RetryQueue", "Ou", "TEXT NULL");
        AddColumnIfMissing(db, "RetryQueue", "Site", "TEXT NULL");
        AddColumnIfMissing(db, "Devices", "CurrentLoggedOnUser", "TEXT NULL");
        AddColumnIfMissing(db, "Disks", "BusType", "TEXT NULL");
        AddColumnIfMissing(db, "OfficeProducts", "Architecture", "TEXT NULL");
        AddColumnIfMissing(db, "OfficeProducts", "UpdateChannel", "TEXT NULL");
        AddColumnIfMissing(db, "OfficeProducts", "ProductIds", "TEXT NULL");
        AddColumnIfMissing(db, "OfficeProducts", "UpdatesEnabled", "INTEGER NULL");
    }

    private static void AddColumnIfMissing(AuditDbContext db, string tableName, string columnName, string definition)
    {
        var connection = db.Database.GetDbConnection();
        var closeConnection = connection.State != ConnectionState.Open;
        if (closeConnection)
        {
            connection.Open();
        }

        try
        {
            using var columnsCommand = connection.CreateCommand();
            columnsCommand.CommandText = $"PRAGMA table_info(\"{tableName}\");";

            var tableExists = false;
            using (var reader = columnsCommand.ExecuteReader())
            {
                while (reader.Read())
                {
                    tableExists = true;
                    if (string.Equals(reader.GetString(1), columnName, StringComparison.OrdinalIgnoreCase))
                    {
                        return;
                    }
                }
            }

            if (!tableExists)
            {
                return;
            }

            using var alterCommand = connection.CreateCommand();
            alterCommand.CommandText = $"ALTER TABLE \"{tableName}\" ADD COLUMN \"{columnName}\" {definition};";
            alterCommand.ExecuteNonQuery();
        }
        finally
        {
            if (closeConnection)
            {
                connection.Close();
            }
        }
    }
}
