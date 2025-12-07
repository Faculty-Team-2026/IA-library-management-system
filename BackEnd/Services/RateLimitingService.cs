using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace BackEnd.Services
{
    public class RateLimitingService : IRateLimitingService
    {
        // Dictionary to track login attempts per IP address (IP -> list of timestamps)
        private readonly Dictionary<string, List<DateTime>> _ipLoginAttempts = new();
        
        // Dictionary to track login attempts per username (username -> list of timestamps)
        private readonly Dictionary<string, List<DateTime>> _usernameLoginAttempts = new();
        
        // Dictionary to track successful logins per user and IP combination (username:ip -> list of timestamps)
        private readonly Dictionary<string, List<DateTime>> _userIpLoginHistory = new();
        
        // Track login delays per IP to implement exponential backoff
        private readonly Dictionary<string, DateTime> _ipLastFailedAttempt = new();
        
        private readonly ILogger<RateLimitingService> _logger;
        
        // Lock for thread-safe access to dictionaries
        private readonly object _lock = new object();
        
        private readonly int _maxAttemptsPerIP = 5;
        private readonly int _maxAttemptsPerUsername = 5;
        private readonly int _maxConcurrentIPsPerAccount = 10;
        private readonly TimeSpan _lockoutDuration = TimeSpan.FromMinutes(1);
        private readonly TimeSpan _ipHistoryDuration = TimeSpan.FromHours(24);
        
        public RateLimitingService(ILogger<RateLimitingService> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public bool IsAccountLockedOut(string username, string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(ipAddress))
                return false;

            lock (_lock)
            {
                // Check IP-based rate limiting
                if (_ipLoginAttempts.ContainsKey(ipAddress))
                {
                    var ipAttempts = _ipLoginAttempts[ipAddress];
                    var recentIpAttempts = ipAttempts.Where(a => DateTime.UtcNow - a < _lockoutDuration).ToList();
                    
                    if (recentIpAttempts.Count >= _maxAttemptsPerIP)
                    {
                        _logger.LogWarning($"Login blocked: IP {ipAddress} | Attempts: {recentIpAttempts.Count}/{_maxAttemptsPerIP}");
                        _ipLoginAttempts[ipAddress] = recentIpAttempts;
                        return true;
                    }
                    
                    _ipLoginAttempts[ipAddress] = recentIpAttempts;
                }

                // Check username-based rate limiting (independent of IP)
                if (_usernameLoginAttempts.ContainsKey(username))
                {
                    var usernameAttempts = _usernameLoginAttempts[username];
                    var recentUsernameAttempts = usernameAttempts.Where(a => DateTime.UtcNow - a < _lockoutDuration).ToList();
                    
                    if (recentUsernameAttempts.Count >= _maxAttemptsPerUsername)
                    {
                        _logger.LogWarning($"Login blocked: {username} | Attempts: {recentUsernameAttempts.Count}/{_maxAttemptsPerUsername}");
                        _usernameLoginAttempts[username] = recentUsernameAttempts;
                        return true;
                    }
                    
                    _usernameLoginAttempts[username] = recentUsernameAttempts;
                }

                return false;
            }
        }

        public bool HasExcessiveIPCount(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            lock (_lock)
            {
                // Get all IP addresses used by this username in the last 24 hours
                var userIpPrefix = $"{username}:";
                var recentIPs = _userIpLoginHistory
                    .Where(kvp => kvp.Key.StartsWith(userIpPrefix))
                    .Select(kvp => new { 
                        Key = kvp.Key, 
                        Logins = kvp.Value.Where(t => DateTime.UtcNow - t < _ipHistoryDuration).ToList() 
                    })
                    .Where(x => x.Logins.Count > 0)
                    .Count();

                return recentIPs > _maxConcurrentIPsPerAccount;
            }
        }

        public void RecordLoginAttempt(string username, string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(ipAddress))
                return;

            lock (_lock)
            {
                // Track IP attempt
                if (!_ipLoginAttempts.ContainsKey(ipAddress))
                    _ipLoginAttempts[ipAddress] = new List<DateTime>();

                _ipLoginAttempts[ipAddress].Add(DateTime.UtcNow);
                _ipLoginAttempts[ipAddress] = _ipLoginAttempts[ipAddress]
                    .Where(a => DateTime.UtcNow - a < _lockoutDuration)
                    .ToList();

                // Track username attempt
                if (!_usernameLoginAttempts.ContainsKey(username))
                    _usernameLoginAttempts[username] = new List<DateTime>();

                _usernameLoginAttempts[username].Add(DateTime.UtcNow);
                _usernameLoginAttempts[username] = _usernameLoginAttempts[username]
                    .Where(a => DateTime.UtcNow - a < _lockoutDuration)
                    .ToList();

                // Track for login delay (progressive backoff)
                _ipLastFailedAttempt[ipAddress] = DateTime.UtcNow;

                // Log failed attempt
                int ipAttemptsCount = _ipLoginAttempts[ipAddress].Count;
                int usernameAttemptsCount = _usernameLoginAttempts[username].Count;
                
                _logger.LogWarning(
                    $"Login failed: {username} | IP: {ipAddress} | IP attempts: {ipAttemptsCount}/{_maxAttemptsPerIP} | Username attempts: {usernameAttemptsCount}/{_maxAttemptsPerUsername}"
                );

                // Alert on excessive attempts
                if (ipAttemptsCount >= 3 || usernameAttemptsCount >= 3)
                {
                    _logger.LogError(
                        $"⚠️ SECURITY ALERT: {username} | IP: {ipAddress} | IP attempts: {ipAttemptsCount} | Username attempts: {usernameAttemptsCount}"
                    );
                }
            }
        }

        public void RecordSuccessfulLogin(string username, string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(ipAddress))
                return;

            lock (_lock)
            {
                var key = $"{username}:{ipAddress}";

                if (!_userIpLoginHistory.ContainsKey(key))
                    _userIpLoginHistory[key] = new List<DateTime>();

                _userIpLoginHistory[key].Add(DateTime.UtcNow);

                // Clean up old history
                _userIpLoginHistory[key] = _userIpLoginHistory[key]
                    .Where(a => DateTime.UtcNow - a < _ipHistoryDuration)
                    .ToList();
            }
        }

        public void ResetLoginAttempts(string username, string ipAddress)
        {
            lock (_lock)
            {
                if (!string.IsNullOrWhiteSpace(ipAddress))
                {
                    if (_ipLoginAttempts.ContainsKey(ipAddress))
                        _ipLoginAttempts[ipAddress].Clear();
                        
                    if (_ipLastFailedAttempt.ContainsKey(ipAddress))
                        _ipLastFailedAttempt.Remove(ipAddress);
                }

                if (!string.IsNullOrWhiteSpace(username))
                {
                    if (_usernameLoginAttempts.ContainsKey(username))
                        _usernameLoginAttempts[username].Clear();
                }

                _logger.LogInformation($"Login reset: {username} | IP: {ipAddress}");
            }
        }

        public int GetRemainingAttempts(string username, string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return _maxAttemptsPerIP;

            lock (_lock)
            {
                int ipRemaining = _maxAttemptsPerIP;
                int usernameRemaining = _maxAttemptsPerUsername;

                if (_ipLoginAttempts.ContainsKey(ipAddress))
                {
                    var ipAttempts = _ipLoginAttempts[ipAddress]
                        .Where(a => DateTime.UtcNow - a < _lockoutDuration)
                        .Count();
                    ipRemaining = Math.Max(0, _maxAttemptsPerIP - ipAttempts);
                }

                if (!string.IsNullOrWhiteSpace(username) && _usernameLoginAttempts.ContainsKey(username))
                {
                    var usernameAttempts = _usernameLoginAttempts[username]
                        .Where(a => DateTime.UtcNow - a < _lockoutDuration)
                        .Count();
                    usernameRemaining = Math.Max(0, _maxAttemptsPerUsername - usernameAttempts);
                }

                // Return the minimum of both (stricter limit applies)
                return Math.Min(ipRemaining, usernameRemaining);
            }
        }

        /// <summary>
        /// Calculate login delay (exponential backoff) based on failed attempts
        /// </summary>
        public int GetLoginDelaySeconds(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress) || !_ipLastFailedAttempt.ContainsKey(ipAddress))
                return 0;

            lock (_lock)
            {
                if (!_ipLoginAttempts.ContainsKey(ipAddress))
                    return 0;

                var attempts = _ipLoginAttempts[ipAddress]
                    .Where(a => DateTime.UtcNow - a < _lockoutDuration)
                    .Count();

                // Exponential backoff: 0s, 1s, 2s, 4s, 8s, 15s (max)
                int delaySeconds = attempts switch
                {
                    0 => 0,
                    1 => 0,
                    2 => 1,
                    3 => 2,
                    4 => 4,
                    5 => 8,
                    _ => 15
                };

                return delaySeconds;
            }
        }

        public List<string> GetUserActiveIPs(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return new List<string>();

            lock (_lock)
            {
                var userIpPrefix = $"{username}:";
                return _userIpLoginHistory
                    .Where(kvp => kvp.Key.StartsWith(userIpPrefix) && 
                                 kvp.Value.Any(t => DateTime.UtcNow - t < _ipHistoryDuration))
                    .Select(kvp => kvp.Key.Split(':')[1])
                    .Distinct()
                    .ToList();
            }
        }
    }
}
