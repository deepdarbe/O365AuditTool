using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using O365AuditTool.Services;

namespace O365AuditTool.Controllers;

[ApiController]
[Route("api/export")]
[Authorize(Policy = "AuditReader")]
public class ExportController(IInventoryQueryService queryService) : ControllerBase
{
    [HttpGet("csv")]
    public async Task<IActionResult> ExportCsv(
        [FromQuery] string? ou,
        [FromQuery] string? site,
        [FromQuery] string? device,
        [FromQuery] string? user,
        [FromQuery] string? diskType,
        [FromQuery] string? officeVersion,
        [FromQuery] string? status,
        [FromQuery] long? pstMinBytes,
        [FromQuery] long? pstMaxBytes,
        CancellationToken cancellationToken)
    {
        var bytes = await queryService.BuildDevicesCsvAsync(ou, site, device, user, diskType, officeVersion, status, pstMinBytes, pstMaxBytes, cancellationToken);
        return File(bytes, "text/csv; charset=utf-8", $"inventory-{DateTime.UtcNow:yyyyMMddHHmmss}.csv");
    }

    [HttpGet("executive-pdf")]
    [Authorize(Policy = "MigrationPlanner")]
    public async Task<IActionResult> ExportExecutivePdf(
        [FromQuery] string? ou,
        [FromQuery] string? site,
        [FromQuery] string? device,
        [FromQuery] string? user,
        [FromQuery] string? diskType,
        [FromQuery] string? officeVersion,
        [FromQuery] string? status,
        [FromQuery] long? pstMinBytes,
        [FromQuery] long? pstMaxBytes,
        CancellationToken cancellationToken)
    {
        var bytes = await queryService.BuildExecutivePdfAsync(ou, site, device, user, diskType, officeVersion, status, pstMinBytes, pstMaxBytes, cancellationToken);
        return File(bytes, "application/pdf", $"executive-summary-{DateTime.UtcNow:yyyyMMddHHmmss}.pdf");
    }
}
