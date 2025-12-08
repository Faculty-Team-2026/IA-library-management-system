using BackEnd.Data;
using Microsoft.EntityFrameworkCore;

namespace BackEnd.Services
{
    public class AccountLockoutService : IAccountLockoutService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILoggerService _loggerService;
        private const int MaxFailedAttempts = 5;
        private const int LockoutDurationMinutes = 30;

        public AccountLockoutService(ApplicationDbContext context, ILoggerService loggerService)
        {
            _context = context;
            _loggerService = loggerService;
        }

        public async Task<bool> IsAccountLockedAsync(string username)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null) return false;

            // Check if lockout time has expired
            if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow)
            {
                return true;
            }

            // If lockout has expired, reset failed attempts
            if (user.LockoutEnd.HasValue && user.LockoutEnd.Value <= DateTime.UtcNow)
            {
                user.FailedLoginAttempts = 0;
                user.LockoutEnd = null;
                await _context.SaveChangesAsync();
            }

            return false;
        }

        public async Task RecordFailedLoginAttemptAsync(string username, string ipAddress)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null) return;

            user.FailedLoginAttempts++;
            user.LastFailedLoginTime = DateTime.UtcNow;

            if (user.FailedLoginAttempts >= MaxFailedAttempts)
            {
                user.LockoutEnd = DateTime.UtcNow.AddMinutes(LockoutDurationMinutes);
                
                await _loggerService.LogAsync(
                    "warning",
                    $"Account '{username}' locked due to {MaxFailedAttempts} failed login attempts from IP: {ipAddress}",
                    "Security",
                    user.Id.ToString(),
                    username
                );
            }
            else
            {
                await _loggerService.LogAsync(
                    "info",
                    $"Failed login attempt #{user.FailedLoginAttempts} for account '{username}' from IP: {ipAddress}",
                    "Security",
                    user.Id.ToString(),
                    username
                );
            }

            await _context.SaveChangesAsync();
        }

        public async Task ResetFailedLoginAttemptsAsync(string username)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null) return;

            if (user.FailedLoginAttempts > 0 || user.LockoutEnd.HasValue)
            {
                user.FailedLoginAttempts = 0;
                user.LockoutEnd = null;
                user.LastFailedLoginTime = null;
                await _context.SaveChangesAsync();
            }
        }

        public async Task<int> GetFailedLoginAttemptsAsync(string username)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            return user?.FailedLoginAttempts ?? 0;
        }

        public async Task<DateTime?> GetLockoutEndTimeAsync(string username)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            return user?.LockoutEnd;
        }
    }
}
