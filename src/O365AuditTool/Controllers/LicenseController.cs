using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using O365AuditTool.Services;

namespace O365AuditTool.Controllers;

[ApiController]
[Route("api/licenses")]
[Authorize(Policy = "MigrationPlanner")]
public class LicenseController(IInventoryQueryService queryService) : ControllerBase
{
    [HttpGet("recommendations")]
    public async Task<IActionResult> GetRecommendations(CancellationToken cancellationToken)
    {
        var data = await queryService.GetLicenseRecommendationsAsync(cancellationToken);
        return Ok(data);
    }
}
