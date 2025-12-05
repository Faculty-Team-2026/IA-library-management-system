using System;
using System.Collections.Generic;
using System.Linq;

namespace BackEnd.Services
{
    public class RateLimitingService : IRateLimitingService
    {
        private readonly Dictionary<string, List<DateTime>> _loginAttempts = new();
        private readonly int _maxAttempts = 5;
        private readonly TimeSpan _lockoutDuration = TimeSpan.FromMinutes(15);

        public bool IsAccountLockedOut(string username)
        {
            if (!_loginAttempts.ContainsKey(username))
                return false;

            var attempts = _loginAttempts[username];
            var recentAttempts = attempts.Where(a => DateTime.UtcNow - a < _lockoutDuration).ToList();

            if (recentAttempts.Count >= _maxAttempts)
                return true;

            // Clean up old attempts
            _loginAttempts[username] = recentAttempts;
            return false;
        }

        public void RecordLoginAttempt(string username)
        {
            if (!_loginAttempts.ContainsKey(username))
                _loginAttempts[username] = new List<DateTime>();

            _loginAttempts[username].Add(DateTime.UtcNow);

            // Clean up old attempts
            _loginAttempts[username] = _loginAttempts[username]
                .Where(a => DateTime.UtcNow - a < _lockoutDuration)
                .ToList();
        }

        public void ResetLoginAttempts(string username)
        {
            if (_loginAttempts.ContainsKey(username))
                _loginAttempts[username].Clear();
        }

        public int GetRemainingAttempts(string username)
        {
            if (!_loginAttempts.ContainsKey(username))
                return _maxAttempts;

            var attempts = _loginAttempts[username]
                .Where(a => DateTime.UtcNow - a < _lockoutDuration)
                .Count();

            return Math.Max(0, _maxAttempts - attempts);
        }
    }

    public interface IRateLimitingService
    {
        bool IsAccountLockedOut(string username);
        void RecordLoginAttempt(string username);
        void ResetLoginAttempts(string username);
        int GetRemainingAttempts(string username);
    }
}
