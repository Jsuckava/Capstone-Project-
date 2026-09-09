using Client_app.Models;
using Client_app.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace Client_app.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/[controller]")]
    public sealed class AccountManagementController : ControllerBase
    {
        private readonly IAccountProvisioningService _accounts;
        private readonly ILogger<AccountManagementController> _logger;

        public AccountManagementController(IAccountProvisioningService accounts, ILogger<AccountManagementController> logger)
        {
            _accounts = accounts;
            _logger = logger;
        }

        [HttpPost("staff/bulk-upload")]
        [Authorize(Roles = "registrar")]
        [Consumes("multipart/form-data")]
        [RequestSizeLimit(2 * 1024 * 1024)]
        public async Task<IActionResult> BulkCreateFaculty([FromForm] IFormFile file, CancellationToken cancellationToken)
        {
            if (file is null || file.Length == 0)
                return BadRequest(new { status = "Error", message = "A non-empty CSV faculty account file is required." });
            if (!string.Equals(Path.GetExtension(file.FileName), ".csv", StringComparison.OrdinalIgnoreCase))
                return BadRequest(new { status = "Error", message = "Faculty bulk upload currently accepts CSV files only." });

            try
            {
                List<FacultyAccountFile.FacultyAccountRow> rows;
                await using (var stream = file.OpenReadStream())
                using (var reader = new StreamReader(stream))
                    rows = FacultyAccountFile.ReadCsv(reader);

                var results = new List<BulkStaffAccountItemResult>(rows.Count);
                var actor = RequiredActor();
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
                foreach (var row in rows)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var validationResults = new List<ValidationResult>();
                    if (!Validator.TryValidateObject(row.Account, new ValidationContext(row.Account), validationResults, true))
                    {
                        results.Add(new(row.RowNumber, row.Account.StaffId, false, null,
                            string.Join(" ", validationResults.Select(result => result.ErrorMessage).Where(message => !string.IsNullOrWhiteSpace(message)))));
                        continue;
                    }
                    try
                    {
                        var account = await _accounts.CreateStaffAsync(row.Account, actor, ipAddress, cancellationToken);
                        results.Add(new(row.RowNumber, row.Account.StaffId, true, account, null));
                    }
                    catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
                    {
                        results.Add(new(row.RowNumber, row.Account.StaffId, false, null, ex.Message));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Unexpected failure creating faculty account from CSV row {RowNumber}.", row.RowNumber);
                        results.Add(new(row.RowNumber, row.Account.StaffId, false, null, "The account could not be created because an internal service failed."));
                    }
                }

                var created = results.Count(result => result.Success);
                var response = new BulkStaffAccountResult(results.Count, created, results.Count - created, results);
                return Ok(new { status = created == results.Count ? "Success" : created == 0 ? "Error" : "PartialSuccess", data = response });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { status = "Error", message = ex.Message });
            }
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
