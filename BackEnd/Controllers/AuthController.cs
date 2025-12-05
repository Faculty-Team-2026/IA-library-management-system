// Controllers/AuthController.cs
using BackEnd.DTOs;
using BackEnd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BackEnd.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
        }

        /// <summary>
        /// Extracts the client IP address from HttpContext
        /// </summary>
        private string GetClientIpAddress()
        {
            try
            {
                // Check for X-Forwarded-For header (from proxy/load balancer)
                var xForwardedFor = HttpContext?.Request?.Headers["X-Forwarded-For"].ToString();
                if (!string.IsNullOrEmpty(xForwardedFor))
                {
                    var ips = xForwardedFor.Split(',');
                    return ips[0].Trim();
                }

                // Fall back to remote IP address
                return HttpContext?.Connection?.RemoteIpAddress?.ToString() ?? "unknown";
            }
            catch
            {
                return "unknown";
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDTO)
        {
            try
            {
                if (loginDTO == null)
                    return BadRequest(new { message = "Login request cannot be null" });

                var ipAddress = GetClientIpAddress();
                var response = await _authService.Login(loginDTO, ipAddress);
                return Ok(response);
            }
            catch (Exception ex)
            {
                // Check if this is a rate limiting error
                if (ex.Message.Contains("Too many login attempts"))
                {
                    return StatusCode(429, new { message = ex.Message });
                }
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO registerDTO)
        {
            try
            {
                if (registerDTO == null)
                    return BadRequest(new { message = "Register request cannot be null" });

                var response = await _authService.Register(registerDTO);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [Authorize]
        [HttpPost("request-librarian")]
        public async Task<IActionResult> RequestLibrarianRole([FromBody] LibrarianRequestDTO request)
        {
            try
            {
                if (request == null)
                    return BadRequest(new { message = "Request cannot be null" });

                var userIdClaim = User?.FindFirst("userId");
                if (userIdClaim == null)
                    return Unauthorized(new { message = "User ID claim not found. Please log in again." });

                if (!long.TryParse(userIdClaim.Value, out var userId))
                    return BadRequest(new { message = "Invalid user ID format" });

                var result = await _authService.RequestLibrarianRole(userId, request.RequestMessage);
                return Ok(new { success = result });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
    }
}

