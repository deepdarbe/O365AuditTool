using Microsoft.EntityFrameworkCore;
using System.Data;

namespace O365AuditTool.Data;

public static class DatabaseSchemaBootstrapper
{
    private static readonly IReadOnlyDictionary<string, string[]> RequiredSchema =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["ScanJobs"] = ["Id", "Status", "CreatedUtc"],
            ["Devices"] = ["Id", "ScanJobId", "DeviceName", "Status", "CollectedUtc", "CurrentLoggedOnUser"],
            ["RetryQueue"] = ["Id", "ScanJobId", "DeviceName", "NextAttemptUtc", "Ou", "Site"],
            ["Profiles"] = ["Id", "DeviceInventoryId", "Sid", "ProfilePath", "UserName", "Loaded", "IsDefault"],
            ["MailAccounts"] = ["Id", "DeviceInventoryId", "Address", "IsActive"],
            ["PstFiles"] = ["Id", "DeviceInventoryId", "Path", "SizeBytes", "ProfileName"],
            ["LegacyFiles"] = ["Id", "DeviceInventoryId", "Sid", "ArtifactType", "Path", "SizeBytes"],
            ["Volumes"] = ["Id", "DeviceInventoryId", "Name", "TotalBytes", "FreeBytes"],
            ["Disks"] = ["Id", "DeviceInventoryId", "Model", "BusType"],
            ["OfficeProducts"] = ["Id", "DeviceInventoryId", "Name", "Version", "Architecture"],
            ["OfficeProcesses"] = ["Id", "DeviceInventoryId", "ProcessName", "Owner", "SessionId"],
            ["ArtifactCopyJobs"] = ["Id", "TargetRoot", "Status", "CreatedUtc", "ExecutedBy", "QueuedUtc"],
            ["ArtifactCopyItems"] = ["Id", "ArtifactCopyJobId", "SourcePath", "DestinationPath", "Status"]
        };

    public static void ConfigureConcurrentAccess(AuditDbContext db)
    {
        db.Database.ExecuteSqlRaw("PRAGMA journal_mode=WAL;");
        db.Database.ExecuteSqlRaw("PRAGMA synchronous=NORMAL;");
    }

    public static void EnsureCurrentSchema(AuditDbContext db)
    {
        RenameTableIfNeeded(db, "StorageVolume", "Volumes");
        RenameTableIfNeeded(db, "DiskInfo", "Disks");
        RenameTableIfNeeded(db, "OfficeProduct", "OfficeProducts");
        RenameTableIfNeeded(db, "OfficeProcess", "OfficeProcesses");
        RenameTableIfNeeded(db, "MailProfile", "Profiles");

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
        AddColumnIfMissing(db, "Devices", "PsExecExitCode", "INTEGER NULL");
        AddColumnIfMissing(db, "Disks", "BusType", "TEXT NULL");
        AddColumnIfMissing(db, "OfficeProducts", "Architecture", "TEXT NULL");
        AddColumnIfMissing(db, "OfficeProducts", "UpdateChannel", "TEXT NULL");
        AddColumnIfMissing(db, "OfficeProducts", "ProductIds", "TEXT NULL");
        AddColumnIfMissing(db, "OfficeProducts", "UpdatesEnabled", "INTEGER NULL");
    }

    public static void ValidateCurrentSchema(AuditDbContext db)
    {
        var failures = GetSchemaFailures(db);
        if (failures.Count > 0)
        {
            throw new InvalidOperationException(
                $"Audit database schema is incomplete or incompatible: {string.Join("; ", failures)}");
        }
    }

    public static IReadOnlyList<string> GetSchemaFailures(AuditDbContext db)
    {
        var connection = db.Database.GetDbConnection();
        var closeConnection = connection.State != ConnectionState.Open;
        if (closeConnection)
        {
            connection.Open();
        }

        try
        {
            var failures = new List<string>();
            foreach (var (tableName, requiredColumns) in RequiredSchema)
            {
                var existingColumns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                using var columnsCommand = connection.CreateCommand();
                columnsCommand.CommandText = $"PRAGMA table_info(\"{tableName}\");";
                using var reader = columnsCommand.ExecuteReader();
                while (reader.Read())
                {
                    existingColumns.Add(reader.GetString(1));
                }

                if (existingColumns.Count == 0)
                {
                    failures.Add($"missing table {tableName}");
                    continue;
                }

                var missingColumns = requiredColumns
                    .Where(column => !existingColumns.Contains(column))
                    .ToArray();
                if (missingColumns.Length > 0)
                {
                    failures.Add($"{tableName} missing [{string.Join(", ", missingColumns)}]");
                }
            }

            return failures;
        }
        finally
        {
            if (closeConnection)
            {
                connection.Close();
            }
        }
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

    private static void RenameTableIfNeeded(AuditDbContext db, string oldName, string newName)
    {
        var connection = db.Database.GetDbConnection();
        var closeConnection = connection.State != ConnectionState.Open;
        if (closeConnection)
        {
            connection.Open();
        }

        try
        {
            using var tableCommand = connection.CreateCommand();
            tableCommand.CommandText =
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ($oldName, $newName);";
            var oldParameter = tableCommand.CreateParameter();
            oldParameter.ParameterName = "$oldName";
            oldParameter.Value = oldName;
            tableCommand.Parameters.Add(oldParameter);
            var newParameter = tableCommand.CreateParameter();
            newParameter.ParameterName = "$newName";
            newParameter.Value = newName;
            tableCommand.Parameters.Add(newParameter);

            var tables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using (var reader = tableCommand.ExecuteReader())
            {
                while (reader.Read())
                {
                    tables.Add(reader.GetString(0));
                }
            }

            if (tables.Contains(oldName) && !tables.Contains(newName))
            {
                using var renameCommand = connection.CreateCommand();
                renameCommand.CommandText = $"ALTER TABLE \"{oldName}\" RENAME TO \"{newName}\";";
                renameCommand.ExecuteNonQuery();
            }
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
