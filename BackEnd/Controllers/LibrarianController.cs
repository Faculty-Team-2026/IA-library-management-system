// Controllers/LibrarianController.cs
using BackEnd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// Controllers/LibrarianController.cs

namespace BackEnd.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin")]
    public class LibrarianController : ControllerBase
    {
        private readonly ILibrarianService _librarianService;

        public LibrarianController(ILibrarianService librarianService)
        {
            _librarianService = librarianService ?? throw new ArgumentNullException(nameof(librarianService));
        }

        [HttpGet("requests")]
        public async Task<IActionResult> GetLibrarianRequests([FromQuery] string? status)
        {
            var requests = await _librarianService.GetLibrarianRequests(status);
            return Ok(requests);
        }

        [HttpPost("approve/{requestId}")]
        public async Task<IActionResult> ApproveLibrarianRequest(long requestId)
        {
            try
            {
                var adminId = long.Parse(User.FindFirst("userId").Value);
                var request = await _librarianService.ApproveLibrarianRequest(requestId, adminId);
                return Ok(request);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("reject/{requestId}")]
        public async Task<IActionResult> RejectLibrarianRequest(long requestId)
        {
            try
            {
                var adminId = long.Parse(User.FindFirst("userId").Value);
                var request = await _librarianService.RejectLibrarianRequest(requestId, adminId);
                return Ok(request);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetAllLibrarians()
        {
            var librarians = await _librarianService.GetAllLibrarians();
            return Ok(librarians);
        }

        [HttpDelete("{librarianId}")]
        public async Task<IActionResult> DeleteLibrarian(long librarianId)
        {
            try
            {
                var result = await _librarianService.DeleteLibrarian(librarianId);
                return Ok(new { success = result });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
    }
}

