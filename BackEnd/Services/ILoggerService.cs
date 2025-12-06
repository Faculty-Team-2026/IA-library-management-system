using BackEnd.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace BackEnd.Services
{
    public interface ILoggerService
    {
        Task LogAsync(string level, string message, string source, string userId = null, string username = null);
        Task<List<SystemLog>> GetAllLogsAsync(int limit = 100);
        Task<List<SystemLog>> GetLogsByLevelAsync(string level, int limit = 100);
        Task<List<SystemLog>> GetLogsByUserAsync(string userId, int limit = 100);
        Task ClearLogsAsync();
        Task<dynamic> GetLogStatisticsAsync();
    }
}
