using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using O365AuditTool.Services;

namespace O365AuditTool.Controllers;

[ApiController]
[Route("api/directory")]
[Authorize(Policy = "AuditReader")]
public sealed class DirectoryController(
    IActiveDirectoryStructureProvider structureProvider,
    ILogger<DirectoryController> logger) : ControllerBase
{
    [HttpGet("structure")]
    public async Task<IActionResult> GetStructure(CancellationToken cancellationToken)
    {
        try
        {
            return Ok(await structureProvider.GetStructureAsync(cancellationToken));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ActiveDirectoryStructureDiscoveryException ex)
        {
            logger.LogError(ex, "Active Directory OU/site structure could not be loaded");
            return Problem(
                statusCode: StatusCodes.Status503ServiceUnavailable,
                title: "Active Directory yapısı yüklenemedi",
                detail: "Domain bağlantısını ve O365AuditTool servis hesabının AD okuma yetkisini kontrol edin.");
        }
    }
}
