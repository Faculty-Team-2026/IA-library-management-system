using BackEnd.Data;
using BackEnd.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BackEnd.Services
{
    public class LoggerService : ILoggerService
    {
        private readonly ApplicationDbContext _context;

        public LoggerService(ApplicationDbContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Log a message to the database
        /// </summary>
        public async Task LogAsync(string level, string message, string source, string userId = null, string username = null)
        {
            try
            {
                var log = new SystemLog
                {
                    Level = level,
                    Message = message,
                    Source = source,
                    UserId = userId,
                    Username = username ?? "Unknown",
                    Timestamp = DateTime.UtcNow
                };

                _context.SystemLogs.Add(log);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                // Log failed - don't throw, just swallow the exception to prevent infinite loops
                System.Console.WriteLine($"Failed to log: {ex.Message}");
            }
        }

        /// <summary>
        /// Get all logs (most recent first)
        /// </summary>
        public async Task<List<SystemLog>> GetAllLogsAsync(int limit = 100)
        {
            return await _context.SystemLogs
                .OrderByDescending(l => l.Timestamp)
                .Take(limit)
                .ToListAsync();
        }

        /// <summary>
        /// Get logs filtered by level
        /// </summary>
        public async Task<List<SystemLog>> GetLogsByLevelAsync(string level, int limit = 100)
        {
            return await _context.SystemLogs
                .Where(l => l.Level == level)
                .OrderByDescending(l => l.Timestamp)
                .Take(limit)
                .ToListAsync();
        }

        /// <summary>
        /// Get logs for a specific user
        /// </summary>
        public async Task<List<SystemLog>> GetLogsByUserAsync(string userId, int limit = 100)
        {
            return await _context.SystemLogs
                .Where(l => l.UserId == userId)
                .OrderByDescending(l => l.Timestamp)
                .Take(limit)
                .ToListAsync();
        }

        /// <summary>
        /// Clear all logs from database
        /// </summary>
        public async Task ClearLogsAsync()
        {
            try
            {
                _context.SystemLogs.RemoveRange(_context.SystemLogs);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                System.Console.WriteLine($"Failed to clear logs: {ex.Message}");
            }
        }

        /// <summary>
        /// Get statistics about logs
        /// </summary>
        public async Task<dynamic> GetLogStatisticsAsync()
        {
            var logs = await _context.SystemLogs.ToListAsync();

            return new
            {
                TotalLogs = logs.Count,
                Errors = logs.Count(l => l.Level == "error"),
                Warnings = logs.Count(l => l.Level == "warning"),
                Info = logs.Count(l => l.Level == "info"),
                Debug = logs.Count(l => l.Level == "debug"),
                Sources = logs.GroupBy(l => l.Source)
                    .ToDictionary(g => g.Key, g => g.Count()),
                OldestLog = logs.OrderBy(l => l.Timestamp).FirstOrDefault()?.Timestamp,
                NewestLog = logs.OrderByDescending(l => l.Timestamp).FirstOrDefault()?.Timestamp
            };
        }
    }
}
