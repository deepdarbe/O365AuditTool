using Microsoft.EntityFrameworkCore;
using O365AuditTool.Models;

namespace O365AuditTool.Data;

public class AuditDbContext(DbContextOptions<AuditDbContext> options) : DbContext(options)
{
    public DbSet<ScanJob> ScanJobs => Set<ScanJob>();
    public DbSet<DeviceInventory> Devices => Set<DeviceInventory>();
    public DbSet<RetryQueueItem> RetryQueue => Set<RetryQueueItem>();
    public DbSet<PstFileRecord> PstFiles => Set<PstFileRecord>();
    public DbSet<MailAccount> MailAccounts => Set<MailAccount>();
    public DbSet<LegacyMailFileRecord> LegacyFiles => Set<LegacyMailFileRecord>();
    public DbSet<ArtifactCopyJob> ArtifactCopyJobs => Set<ArtifactCopyJob>();
    public DbSet<ArtifactCopyItem> ArtifactCopyItems => Set<ArtifactCopyItem>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Keep table names stable across releases; these names were used by the original schema.
        modelBuilder.Entity<StorageVolume>().ToTable("Volumes");
        modelBuilder.Entity<DiskInfo>().ToTable("Disks");
        modelBuilder.Entity<OfficeProduct>().ToTable("OfficeProducts");
        modelBuilder.Entity<OfficeProcess>().ToTable("OfficeProcesses");
        modelBuilder.Entity<MailProfile>().ToTable("Profiles");

        modelBuilder.Entity<ScanJob>()
            .HasMany(x => x.Devices)
            .WithOne()
            .HasForeignKey(x => x.ScanJobId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<DeviceInventory>()
            .HasIndex(x => new { x.DeviceName, x.CollectedUtc });

        modelBuilder.Entity<PstFileRecord>()
            .HasIndex(x => new { x.UserPrincipalName, x.Sid });

        modelBuilder.Entity<LegacyMailFileRecord>()
            .HasIndex(x => new { x.DeviceInventoryId, x.Sid, x.Path });

        modelBuilder.Entity<ArtifactCopyJob>()
            .HasMany(x => x.Items)
            .WithOne()
            .HasForeignKey(x => x.ArtifactCopyJobId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<ArtifactCopyJob>()
            .HasIndex(x => new { x.Status, x.CreatedUtc });

        modelBuilder.Entity<ArtifactCopyItem>()
            .HasIndex(x => new { x.ArtifactCopyJobId, x.Status });

        modelBuilder.Entity<RetryQueueItem>()
            .HasIndex(x => x.NextAttemptUtc);

        base.OnModelCreating(modelBuilder);
    }
}
