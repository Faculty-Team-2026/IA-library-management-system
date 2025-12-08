using BackEnd.Data;
using BackEnd.Models;
using Microsoft.EntityFrameworkCore;

namespace BackEnd.Services
{
    public class AnomalyDetectionService : IAnomalyDetectionService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILoggerService _loggerService;
        private const int MaxIpsPerDay = 10;
        private const int RapidLocationChangeMinutes = 60; // Alert if location changes within 60 minutes
        private const int UnusualHourStart = 0; // 12 AM
        private const int UnusualHourEnd = 5; // 5 AM

        public AnomalyDetectionService(ApplicationDbContext context, ILoggerService loggerService)
        {
            _context = context;
            _loggerService = loggerService;
        }

        public async Task<bool> DetectSuspiciousActivityAsync(string username, string ipAddress, string? userAgent = null)
        {
            var anomalies = new List<string>();
            var now = DateTime.UtcNow;
            var last24Hours = now.AddHours(-24);

            // Get recent login activities for this user
            var recentLogs = await _context.SystemLogs
                .Where(l => l.Username == username && 
                           l.Timestamp >= last24Hours &&
                           l.Message.Contains("Login"))
                .OrderByDescending(l => l.Timestamp)
                .ToListAsync();

            // 1. Detect multiple IPs in 24 hours
            // Extract IPs from log messages (assuming format contains "IP: x.x.x.x")
            var uniqueIps = recentLogs
                .Select(l => ExtractIpFromMessage(l.Message))
                .Where(ip => !string.IsNullOrEmpty(ip))
                .Distinct()
                .Count();

            if (uniqueIps >= MaxIpsPerDay)
            {
                anomalies.Add($"Multiple IP addresses detected: {uniqueIps} different IPs in last 24 hours");
                
                await _loggerService.LogAsync(
                    "warning",
                    $"Anomaly: User '{username}' accessed from {uniqueIps} different IP addresses in 24 hours. Current IP: {ipAddress}",
                    "Security",
                    null,
                    username
                );
            }

            // 2. Detect rapid location changes (simplified - using IP changes as proxy)
            var lastTwoLogins = recentLogs.Take(2).ToList();
            if (lastTwoLogins.Count == 2)
            {
                var timeDiff = (lastTwoLogins[0].Timestamp - lastTwoLogins[1].Timestamp).TotalMinutes;
                var ip1 = ExtractIpFromMessage(lastTwoLogins[0].Message);
                var ip2 = ExtractIpFromMessage(lastTwoLogins[1].Message);
                var differentIp = !string.IsNullOrEmpty(ip1) && !string.IsNullOrEmpty(ip2) && ip1 != ip2;

                if (differentIp && timeDiff <= RapidLocationChangeMinutes)
                {
                    anomalies.Add($"Rapid location change: IP changed from {ip2} to {ip1} in {timeDiff:F0} minutes");
                    
                    await _loggerService.LogAsync(
                        "warning",
                        $"Anomaly: User '{username}' logged in from different location within {timeDiff:F0} minutes. IPs: {ip2} -> {ip1}",
                        "Security",
                        null,
                        username
                    );
                }
            }

            // 3. Detect unusual login times (late night / early morning)
            var currentHour = now.Hour;
            if (currentHour >= UnusualHourStart && currentHour < UnusualHourEnd)
            {
                anomalies.Add($"Unusual login time: {now:HH:mm} UTC (between {UnusualHourStart}:00 and {UnusualHourEnd}:00)");
                
                await _loggerService.LogAsync(
                    "info",
                    $"Anomaly: User '{username}' logged in at unusual hour: {now:HH:mm} UTC from IP: {ipAddress}",
                    "Security",
                    null,
                    username
                );
            }

            // 4. Detect unusual user agent changes
            if (recentLogs.Any() && !string.IsNullOrEmpty(userAgent))
            {
                var lastUserAgent = recentLogs.FirstOrDefault()?.Message;
                if (!string.IsNullOrEmpty(lastUserAgent) && 
                    !lastUserAgent.Contains(userAgent) && 
                    !userAgent.Contains("unknown"))
                {
                    anomalies.Add($"Device/Browser change detected");
                    
                    await _loggerService.LogAsync(
                        "info",
                        $"Anomaly: User '{username}' logged in from different device/browser. IP: {ipAddress}",
                        "Security",
                        null,
                        username
                    );
                }
            }

            // If any anomalies detected, log comprehensive alert
            if (anomalies.Any())
            {
                await _loggerService.LogAsync(
                    "error",
                    $"SECURITY ALERT - Multiple anomalies detected for user '{username}' from IP {ipAddress}: {string.Join("; ", anomalies)}",
                    "Security",
                    null,
                    username
                );

                return true; // Suspicious activity detected
            }

            return false; // No suspicious activity
        }

        public async Task RecordLoginActivityAsync(string username, string ipAddress, DateTime loginTime)
        {
            // The login activity is already recorded by LoggerService
            // This method can be used for additional tracking if needed
            await Task.CompletedTask;
        }

        public async Task<List<string>> GetAnomalyReportAsync(string username)
        {
            var last24Hours = DateTime.UtcNow.AddHours(-24);
            
            var anomalyLogs = await _context.SystemLogs
                .Where(l => l.Username == username && 
                           l.Timestamp >= last24Hours &&
                           (l.Message.Contains("Anomaly") || l.Message.Contains("SECURITY ALERT")))
                .OrderByDescending(l => l.Timestamp)
                .Select(l => $"[{l.Timestamp:yyyy-MM-dd HH:mm:ss}] {l.Level}: {l.Message}")
                .ToListAsync();

            return anomalyLogs;
        }

        private string? ExtractIpFromMessage(string message)
        {
            // Extract IP from message format "... IP: x.x.x.x ..."
            var ipMatch = System.Text.RegularExpressions.Regex.Match(message, @"IP:\s*([0-9.]+)");
            return ipMatch.Success ? ipMatch.Groups[1].Value : null;
        }
    }
}
