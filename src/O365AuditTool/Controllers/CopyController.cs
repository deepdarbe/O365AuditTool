using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using O365AuditTool.Models;
using O365AuditTool.Services;

namespace O365AuditTool.Controllers;

[ApiController]
[Route("api/copy/plans")]
public sealed class CopyController(IArtifactCopyPlanService copyPlanService) : ControllerBase
{
    [HttpGet]
    [Authorize(Policy = "AuditReader")]
    public async Task<IActionResult> ListPlans(
        [FromQuery] int take = 50,
        CancellationToken cancellationToken = default)
    {
        var jobs = await copyPlanService.ListPlansAsync(take, cancellationToken);
        return Ok(jobs.Select(BuildSummary));
    }

    [HttpPost]
    [Authorize(Policy = "MigrationPlanner")]
    public async Task<IActionResult> CreatePlan(
        [FromBody] CreateCopyPlanRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var requestedBy = User?.Identity?.Name ?? "unknown";
            var job = await copyPlanService.CreatePlanAsync(
                request,
                requestedBy,
                cancellationToken);
            return CreatedAtAction(
                nameof(GetPlan),
                new { id = job.Id },
                BuildResponse(job));
        }
        catch (ArtifactCopyValidationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    [HttpGet("{id:guid}")]
    [Authorize(Policy = "AuditReader")]
    public async Task<IActionResult> GetPlan(Guid id, CancellationToken cancellationToken)
    {
        var job = await copyPlanService.GetPlanAsync(id, cancellationToken);
        return job is null ? NotFound() : Ok(BuildResponse(job));
    }

    [HttpPost("{id:guid}/execute")]
    [Authorize(Policy = "AuditAdmin")]
    public async Task<IActionResult> ExecutePlan(Guid id, CancellationToken cancellationToken)
    {
        try
        {
            var executedBy = User?.Identity?.Name ?? "unknown";
            var job = await copyPlanService.QueuePlanAsync(id, executedBy, cancellationToken);
            return job is null
                ? NotFound()
                : AcceptedAtAction(nameof(GetPlan), new { id = job.Id }, BuildResponse(job));
        }
        catch (ArtifactCopyDisabledException ex)
        {
            return Conflict(new { error = ex.Message });
        }
        catch (ArtifactCopyConflictException ex)
        {
            return Conflict(new { error = ex.Message });
        }
        catch (ArtifactCopyValidationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    private static object BuildResponse(ArtifactCopyJob job)
    {
        return new
        {
            job.Id,
            job.RequestedBy,
            job.ExecutedBy,
            job.TargetRoot,
            job.CreatedUtc,
            job.StartedUtc,
            job.QueuedUtc,
            job.CompletedUtc,
            job.Status,
            job.Notes,
            itemStats = new
            {
                total = job.Items.Count,
                planned = job.Items.Count(x => x.Status == CopyItemStatus.Planned),
                queued = job.Items.Count(x => x.Status == CopyItemStatus.Queued),
                copying = job.Items.Count(x => x.Status == CopyItemStatus.Copying),
                completed = job.Items.Count(x => x.Status == CopyItemStatus.Completed),
                skipped = job.Items.Count(x => x.Status == CopyItemStatus.Skipped),
                failed = job.Items.Count(x => x.Status == CopyItemStatus.Failed)
            },
            items = job.Items
                .OrderBy(x => x.DeviceName)
                .ThenBy(x => x.UserKey)
                .ThenBy(x => x.SourcePath)
                .Select(x => new
                {
                    x.Id,
                    x.DeviceName,
                    x.UserKey,
                    x.ProfileName,
                    x.ArtifactType,
                    x.SourcePath,
                    x.SourceSizeBytes,
                    x.SourceLastWriteUtc,
                    x.DestinationPath,
                    x.Status,
                    x.Attempts,
                    x.ErrorMessage,
                    x.CopiedUtc,
                    x.DestinationSizeBytes,
                    x.Sha256
                })
        };
    }

    private static object BuildSummary(ArtifactCopyJob job)
    {
        return new
        {
            job.Id,
            job.RequestedBy,
            job.ExecutedBy,
            job.TargetRoot,
            job.CreatedUtc,
            job.StartedUtc,
            job.QueuedUtc,
            job.CompletedUtc,
            job.Status,
            job.Notes,
            totalItems = job.Items.Count,
            completedItems = job.Items.Count(x =>
                x.Status is CopyItemStatus.Completed or CopyItemStatus.Skipped),
            failedItems = job.Items.Count(x => x.Status == CopyItemStatus.Failed)
        };
    }
}
