using BackEnd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace BackEnd.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class LogsController : ControllerBase
    {
        private readonly ILoggerService _loggerService;

        public LogsController(ILoggerService loggerService)
        {
            _loggerService = loggerService;
        }

        /// <summary>
        /// Get all logs (Admin only)
        /// </summary>
        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetAllLogs(int limit = 100)
        {
            var logs = await _loggerService.GetAllLogsAsync(limit);
            return Ok(logs);
        }

        /// <summary>
        /// Get logs by level (Admin only)
        /// </summary>
        [HttpGet("by-level/{level}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetLogsByLevel(string level, int limit = 100)
        {
            var logs = await _loggerService.GetLogsByLevelAsync(level, limit);
            return Ok(logs);
        }

        /// <summary>
        /// Get logs for current user
        /// </summary>
        [HttpGet("my-logs")]
        [Authorize]
        public async Task<IActionResult> GetMyLogs(int limit = 100)
        {
            var userId = User.FindFirst("userId")?.Value ?? User.FindFirst("sub")?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("User ID not found in token");
            }

            var logs = await _loggerService.GetLogsByUserAsync(userId, limit);
            return Ok(logs);
        }

        /// <summary>
        /// Save a log entry from frontend
        /// </summary>
        [HttpPost]
        [Authorize]
        public async Task<IActionResult> SaveLog([FromBody] LogRequest logRequest)
        {
            if (logRequest == null || string.IsNullOrEmpty(logRequest.Message))
            {
                return BadRequest("Message is required");
            }

            var userId = User.FindFirst("userId")?.Value ?? User.FindFirst("sub")?.Value;
            var username = User.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")?.Value
                        ?? User.FindFirst("unique_name")?.Value
                        ?? User.FindFirst("sub")?.Value
                        ?? "Unknown";

            await _loggerService.LogAsync(
                logRequest.Level ?? "info",
                logRequest.Message,
                logRequest.Source ?? "Frontend",
                userId,
                username
            );

            return Ok(new { message = "Log saved successfully" });
        }

        /// <summary>
        /// Get log statistics (Admin only)
        /// </summary>
        [HttpGet("statistics")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetStatistics()
        {
            var statistics = await _loggerService.GetLogStatisticsAsync();
            return Ok(statistics);
        }

        /// <summary>
        /// Clear all logs (Admin only)
        /// </summary>
        [HttpDelete]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> ClearLogs()
        {
            await _loggerService.ClearLogsAsync();
            return Ok(new { message = "All logs cleared successfully" });
        }
    }

    public class LogRequest
    {
        public string Level { get; set; }
        public string Message { get; set; }
        public string Source { get; set; }
    }
}
