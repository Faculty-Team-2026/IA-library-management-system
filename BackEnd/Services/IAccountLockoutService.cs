namespace BackEnd.Services
{
    public interface IAccountLockoutService
    {
        Task<bool> IsAccountLockedAsync(string username);
        Task RecordFailedLoginAttemptAsync(string username, string ipAddress);
        Task ResetFailedLoginAttemptsAsync(string username);
        Task<int> GetFailedLoginAttemptsAsync(string username);
        Task<DateTime?> GetLockoutEndTimeAsync(string username);
    }
}
