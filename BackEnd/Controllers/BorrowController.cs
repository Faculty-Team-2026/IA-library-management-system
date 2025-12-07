// Controllers/BorrowController.cs
using BackEnd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

// Controllers/BorrowController.cs

namespace BackEnd.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class BorrowController : ControllerBase
    {
        private readonly IBorrowService _borrowService;
        private readonly ILoggerService _loggerService;

        public BorrowController(IBorrowService borrowService, ILoggerService loggerService)
        {
            _borrowService = borrowService ?? throw new ArgumentNullException(nameof(borrowService));
            _loggerService = loggerService ?? throw new ArgumentNullException(nameof(loggerService));
        }

        [HttpPost("request/{bookId}")]
        public async Task<IActionResult> RequestBorrow(long bookId)
        {
            try
            {
                var userIdClaim = User?.FindFirst("userId");
                if (userIdClaim == null)
                    return Unauthorized(new { message = "User ID claim not found. Please log in again." });

                if (!long.TryParse(userIdClaim.Value, out var userId))
                    return BadRequest(new { message = "Invalid user ID format" });

                var userNameClaim = User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier) ?? User?.FindFirst(JwtRegisteredClaimNames.Sub);
                var request = await _borrowService.RequestBorrow(userId, bookId);
                
                // Log borrow request
                await _loggerService.LogAsync(
                    "info",
                    $"Borrow Request: Book ID {bookId}",
                    "Book Borrowing",
                    userId.ToString(),
                    userNameClaim?.Value ?? "Unknown"
                );
                
                return Ok(request);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [Authorize(Roles = "Librarian")]
        [HttpGet("requests")]
        public async Task<IActionResult> GetBorrowRequests([FromQuery] string? status)
        {
            var requests = await _borrowService.GetBorrowRequests(status);
            return Ok(requests);
        }

        [Authorize(Roles = "Librarian")]
        [HttpPost("approve/{requestId}")]
        public async Task<IActionResult> ApproveBorrowRequest(long requestId)
        {
            try
            {
                var librarianId = long.Parse(User.FindFirst("userId").Value);
                var librarianName = User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? User?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                
                var request = await _borrowService.ApproveBorrowRequest(requestId, librarianId);
                
                // Log borrow approval
                await _loggerService.LogAsync(
                    "info",
                    $"Borrow Request Approved: {request.BookTitle} | User: {request.Username}",
                    "Book Borrowing",
                    librarianId.ToString(),
                    librarianName ?? "Librarian"
                );
                
                return Ok(request);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [Authorize(Roles = "Librarian")]
        [HttpPost("reject/{requestId}")]
        public async Task<IActionResult> RejectBorrowRequest(long requestId)
        {
            try
            {
                var librarianId = long.Parse(User.FindFirst("userId").Value);
                var librarianName = User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? User?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                
                var request = await _borrowService.RejectBorrowRequest(requestId, librarianId);
                
                // Log borrow rejection
                await _loggerService.LogAsync(
                    "info",
                    $"Borrow Request Rejected: {request.BookTitle} | User: {request.Username}",
                    "Book Borrowing",
                    librarianId.ToString(),
                    librarianName ?? "Librarian"
                );
                
                return Ok(request);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [Authorize(Roles = "Librarian")]
        [HttpPost("return/{recordId}")]
        public async Task<IActionResult> ReturnBook(long recordId)
        {
            try
            {
                var librarianId = long.Parse(User.FindFirst("userId").Value);
                var librarianName = User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? User?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                
                var record = await _borrowService.ReturnBook(recordId, librarianId);
                
                // Log book return
                await _loggerService.LogAsync(
                    "info",
                    $"Book Returned: {record.BookTitle} | User: {record.Username}",
                    "Book Borrowing",
                    librarianId.ToString(),
                    librarianName ?? "Librarian"
                );
                
                return Ok(record);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [Authorize(Roles = "Admin,Librarian")]
        [HttpGet("records")]
        public async Task<IActionResult> GetBorrowRecords()
        {
            var records = await _borrowService.GetBorrowRecords();
            return Ok(records);
        }

        [HttpGet("my-records")]
        public async Task<IActionResult> GetUserBorrowRecords()
        {
            try
            {
                var userId = long.Parse(User.FindFirst("userId").Value);
                var records = await _borrowService.GetUserBorrowRecords(userId);
                return Ok(records);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
    }
}
