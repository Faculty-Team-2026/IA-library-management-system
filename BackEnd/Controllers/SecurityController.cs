using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using BackEnd.Services;

namespace BackEnd.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Policy = "AdminOnly")]
    public class SecurityController : ControllerBase
    {
        private readonly IRateLimitingService _rateLimitingService;
        private readonly ILogger<SecurityController> _logger;

        public SecurityController(
            IRateLimitingService rateLimitingService,
            ILogger<SecurityController> logger)
        {
            _rateLimitingService = rateLimitingService;
            _logger = logger;
        }

        /// <summary>
        /// Get remaining login attempts for a user
        /// </summary>
        /// <param name="username">The username to check</param>
        /// <param name="ipAddress">The IP address to check (optional, uses client IP if not provided)</param>
        /// <returns>Number of remaining attempts before account lockout</returns>
        [HttpGet("login-attempts/{username}")]
        public IActionResult GetRemainingAttempts(string username, [FromQuery] string? ipAddress = null)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    return BadRequest(new { error = "Username is required" });

                ipAddress ??= HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                int remaining = _rateLimitingService.GetRemainingAttempts(username, ipAddress);
                bool isLockedOut = _rateLimitingService.IsAccountLockedOut(username, ipAddress);

                _logger.LogInformation(
                    $"Admin checked login attempts for user '{username}' from IP {ipAddress}. " +
                    $"Remaining attempts: {remaining}, Locked out: {isLockedOut}"
                );

                return Ok(new
                {
                    username,
                    ipAddress,
                    remainingAttempts = remaining,
                    isLockedOut,
                    timestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error checking login attempts for user '{username}'");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        /// <summary>
        /// Get all active IPs accessing a user account
        /// </summary>
        /// <param name="username">The username to check</param>
        /// <returns>List of IP addresses that have logged in successfully in the last 24 hours</returns>
        [HttpGet("active-ips/{username}")]
        public IActionResult GetActiveIPs(string username)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    return BadRequest(new { error = "Username is required" });

                var activeIPs = _rateLimitingService.GetUserActiveIPs(username);
                bool hasCompromiseRisk = _rateLimitingService.HasExcessiveIPCount(username);

                _logger.LogInformation(
                    $"Admin viewed active IPs for user '{username}'. " +
                    $"Found {activeIPs.Count} IPs. Compromise risk: {hasCompromiseRisk}"
                );

                return Ok(new
                {
                    username,
                    activeIPCount = activeIPs.Count,
                    activeIPs,
                    hasCompromiseRisk,
                    maxConcurrentIPs = 10,
                    timestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error retrieving active IPs for user '{username}'");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        /// <summary>
        /// Get current login delay (exponential backoff) for an IP address
        /// </summary>
        /// <param name="ipAddress">The IP address to check (optional, uses client IP if not provided)</param>
        /// <returns>Number of seconds to delay before next login attempt</returns>
        [HttpGet("login-delay")]
        public IActionResult GetLoginDelay([FromQuery] string? ipAddress = null)
        {
            try
            {
                ipAddress ??= HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                int delaySeconds = _rateLimitingService.GetLoginDelaySeconds(ipAddress);

                if (delaySeconds > 0)
                {
                    _logger.LogWarning(
                        $"Login delay queried for IP {ipAddress}. " +
                        $"Current delay: {delaySeconds} seconds"
                    );
                }

                return Ok(new
                {
                    ipAddress,
                    delaySeconds,
                    message = delaySeconds > 0 
                        ? $"IP is rate limited. Wait {delaySeconds} seconds before trying again."
                        : "No current rate limit",
                    timestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving login delay");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        /// <summary>
        /// Reset login attempts for a user (emergency admin action)
        /// </summary>
        /// <param name="username">The username to reset</param>
        /// <param name="ipAddress">The IP address to reset (optional, resets all if not provided)</param>
        /// <returns>Confirmation of reset</returns>
        [HttpPost("reset-attempts/{username}")]
        public IActionResult ResetLoginAttempts(string username, [FromQuery] string? ipAddress = null)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    return BadRequest(new { error = "Username is required" });

                ipAddress ??= HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                _rateLimitingService.ResetLoginAttempts(username, ipAddress);

                _logger.LogCritical(
                    $"⚠️ ADMIN ACTION: Login attempts reset for user '{username}' " +
                    $"(IP: {ipAddress}). This should only happen in emergency situations. " +
                    $"Requester IP: {HttpContext.Connection.RemoteIpAddress}"
                );

                return Ok(new
                {
                    username,
                    resetFor = ipAddress ?? "all IPs",
                    message = "Login attempts have been reset",
                    timestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error resetting login attempts for user '{username}'");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }
    }
}
