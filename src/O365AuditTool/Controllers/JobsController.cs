using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using O365AuditTool.Data;
using O365AuditTool.Models;
using O365AuditTool.Services;

namespace O365AuditTool.Controllers;

[ApiController]
[Route("api/jobs")]
[Authorize(Policy = "AuditReader")]
public class JobsController(IScanJobCoordinator coordinator, AuditDbContext dbContext) : ControllerBase
{
    [HttpPost("scan")]
    [Authorize(Policy = "AuditAdmin")]
    public async Task<IActionResult> StartScan([FromBody] StartScanRequest request, CancellationToken cancellationToken)
    {
        var requestedBy = User?.Identity?.Name ?? "manual";
        var jobId = await coordinator.EnqueueManualScanAsync(requestedBy, request.OuFilter, request.SiteFilter, cancellationToken);
        return Accepted(new { jobId });
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetJob(Guid id, CancellationToken cancellationToken)
    {
        var job = await dbContext.ScanJobs
            .AsNoTracking()
            .Include(x => x.Devices)
            .SingleOrDefaultAsync(x => x.Id == id, cancellationToken);

        if (job is null)
        {
            return NotFound();
        }

        return Ok(new
        {
            job.Id,
            job.Status,
            job.CreatedUtc,
            job.StartedUtc,
            job.CompletedUtc,
            job.Notes,
            deviceStats = new
            {
                total = job.Devices.Count,
                success = job.Devices.Count(x => x.Status == DeviceScanStatus.Success),
                offline = job.Devices.Count(x => x.Status == DeviceScanStatus.Offline),
                error = job.Devices.Count(x => x.Status == DeviceScanStatus.Error)
            }
        });
    }
}
