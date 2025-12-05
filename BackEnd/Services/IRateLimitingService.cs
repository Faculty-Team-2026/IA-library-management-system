namespace BackEnd.Services
{
    public interface IRateLimitingService
    {
        /// <summary>
        /// Check if account/IP is locked out due to too many failed attempts
        /// </summary>
        bool IsAccountLockedOut(string username, string ipAddress);

        /// <summary>
        /// Check if account has excessive concurrent IP addresses (possible compromise)
        /// </summary>
        bool HasExcessiveIPCount(string username);

        /// <summary>
        /// Record a failed login attempt
        /// </summary>
        void RecordLoginAttempt(string username, string ipAddress);

        /// <summary>
        /// Record a successful login
        /// </summary>
        void RecordSuccessfulLogin(string username, string ipAddress);

        /// <summary>
        /// Reset login attempts after successful login
        /// </summary>
        void ResetLoginAttempts(string username, string ipAddress);

        /// <summary>
        /// Get remaining login attempts before lockout
        /// </summary>
        int GetRemainingAttempts(string username, string ipAddress);

        /// <summary>
        /// Get list of active IPs for a user account
        /// </summary>
        List<string> GetUserActiveIPs(string username);

        /// <summary>
        /// Calculate login delay (exponential backoff) to slow down brute force attacks
        /// </summary>
        int GetLoginDelaySeconds(string ipAddress);
    }
}
