using Client_app.Models;
using Client_app.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Client_app.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/[controller]")]
    public sealed class AccountManagementController : ControllerBase
    {
        private readonly IAccountProvisioningService _accounts;

        public AccountManagementController(IAccountProvisioningService accounts)
        {
            _accounts = accounts;
        }

        [HttpPost("staff")]
        [Authorize(Roles = "registrar")]
        public async Task<IActionResult> CreateStaff([FromBody] StaffAccountRequest request, CancellationToken cancellationToken)
        {
            try
            {
                var result = await _accounts.CreateStaffAsync(request, RequiredActor(), HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken);
                return CreatedAtAction(nameof(CreateStaff), new { id = result.Id }, new { status = "Success", data = result });
            }
            catch (ArgumentException ex) { return BadRequest(new { status = "Error", message = ex.Message }); }
            catch (InvalidOperationException ex) { return Conflict(new { status = "Error", message = ex.Message }); }
        }

        [HttpGet("registrars")]
        [Authorize(Roles = "system_admin")]
        public async Task<IActionResult> GetRegistrars(CancellationToken cancellationToken)
        {
            return Ok(new { status = "Success", data = await _accounts.GetRegistrarsAsync(cancellationToken) });
        }

        [HttpPost("registrars")]
        [Authorize(Roles = "system_admin")]
        public async Task<IActionResult> CreateRegistrar([FromBody] RegistrarAccountRequest request, CancellationToken cancellationToken)
        {
            try
            {
                var result = await _accounts.CreateRegistrarAsync(request, RequiredActor(), HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken);
                return CreatedAtAction(nameof(GetRegistrars), new { id = result.Id }, new { status = "Success", data = result });
            }
            catch (ArgumentException ex) { return BadRequest(new { status = "Error", message = ex.Message }); }
            catch (InvalidOperationException ex) { return Conflict(new { status = "Error", message = ex.Message }); }
        }

        [HttpPut("registrars/{userId:int}")]
        [Authorize(Roles = "system_admin")]
        public async Task<IActionResult> UpdateRegistrar(int userId, [FromBody] UpdateRegistrarAccountRequest request, CancellationToken cancellationToken)
        {
            try
            {
                var result = await _accounts.UpdateRegistrarAsync(userId, request, RequiredActor(), HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken);
                return Ok(new { status = "Success", data = result });
            }
            catch (KeyNotFoundException ex) { return NotFound(new { status = "Error", message = ex.Message }); }
            catch (ArgumentException ex) { return BadRequest(new { status = "Error", message = ex.Message }); }
            catch (InvalidOperationException ex) { return Conflict(new { status = "Error", message = ex.Message }); }
        }

        [HttpDelete("registrars/{userId:int}")]
        [Authorize(Roles = "system_admin")]
        public async Task<IActionResult> DeleteRegistrar(int userId, CancellationToken cancellationToken)
        {
            try
            {
                var result = await _accounts.DeleteRegistrarAsync(
                    userId, RequiredActor(), HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken);
                return Ok(new
                {
                    status = "Success",
                    message = "Registrar account deleted. A new Registrar account can now be created.",
                    data = result
                });
            }
            catch (KeyNotFoundException ex) { return NotFound(new { status = "Error", message = ex.Message }); }
            catch (InvalidOperationException ex) { return Conflict(new { status = "Error", message = ex.Message }); }
        }

        [HttpPut("users/{userId:int}/password")]
        [Authorize(Roles = "registrar,system_admin")]
        public async Task<IActionResult> ResetPassword(int userId, [FromBody] ManualPasswordResetRequest request, CancellationToken cancellationToken)
        {
            try
            {
                var result = await _accounts.ResetPasswordAsync(
                    userId,
                    request.NewPassword,
                    RequiredActor(),
                    RequiredActorRole(),
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    cancellationToken);
                return Ok(new { status = "Success", message = $"Password reset for {result.Email}.", data = result });
            }
            catch (KeyNotFoundException ex) { return NotFound(new { status = "Error", message = ex.Message }); }
            catch (ArgumentException ex) { return BadRequest(new { status = "Error", message = ex.Message }); }
            catch (UnauthorizedAccessException ex) { return StatusCode(StatusCodes.Status403Forbidden, new { status = "Error", message = ex.Message }); }
        }

        private string RequiredActor() => User.Identity?.Name
            ?? throw new UnauthorizedAccessException("Authenticated account identity is missing.");

        private string RequiredActorRole() => (User.FindFirstValue("dbRole")
            ?? User.FindFirstValue(ClaimTypes.Role)
            ?? throw new UnauthorizedAccessException("Authenticated account role is missing."))
            .Trim().ToLowerInvariant().Replace('-', '_').Replace(' ', '_');
    }
}
