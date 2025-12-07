using BackEnd.Data;
using BackEnd.DTOs;
using BackEnd.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.SignalR;

namespace BackEnd.Services
{
    public class AuthService : IAuthService
    {
        private readonly IHubContext<BackEnd.Hubs.SessionHub, BackEnd.Hubs.ISessionHubClient> _sessionHubContext;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IValidationService _validationService;
        private readonly IEncryptionService _encryptionService;
        private readonly IRateLimitingService _rateLimitingService;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            ApplicationDbContext context, 
            IConfiguration configuration,
            IValidationService validationService,
            IEncryptionService encryptionService,
            IRateLimitingService rateLimitingService,
            ILogger<AuthService> logger,
            IHubContext<BackEnd.Hubs.SessionHub, BackEnd.Hubs.ISessionHubClient> sessionHubContext)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _validationService = validationService ?? throw new ArgumentNullException(nameof(validationService));
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
            _rateLimitingService = rateLimitingService ?? throw new ArgumentNullException(nameof(rateLimitingService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _sessionHubContext = sessionHubContext ?? throw new ArgumentNullException(nameof(sessionHubContext));
        }

        public async Task<AuthResponseDTO> Login(LoginDTO loginDTO, string ipAddress = "unknown")
        {
            if (loginDTO == null)
                throw new ArgumentNullException(nameof(loginDTO));

            // Get username and password (no validation during login, only sanitization)
            var username = _validationService.SanitizeHtmlInput(loginDTO.Username?.Trim());
            var password = loginDTO.Password;

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Username and password are required.");

            // Ensure IP address is not null
            ipAddress = string.IsNullOrWhiteSpace(ipAddress) ? "unknown" : ipAddress;

            // Check rate limiting based on IP address and username
            if (_rateLimitingService.IsAccountLockedOut(username, ipAddress))
            {
                _logger.LogWarning($"Login blocked: {username} | IP: {ipAddress}");
                throw new Exception("Too many login attempts. Try again later.");
            }

            // Apply login delay (exponential backoff) to slow down brute force attacks
            int delaySeconds = _rateLimitingService.GetLoginDelaySeconds(ipAddress);
            if (delaySeconds > 0)
            {
                _logger.LogInformation($"Login delay: {username} | IP: {ipAddress} | Delay: {delaySeconds}s");
                await Task.Delay(delaySeconds * 1000);
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.Password))
            {
                _rateLimitingService.RecordLoginAttempt(username, ipAddress);
                int remainingAttempts = _rateLimitingService.GetRemainingAttempts(username, ipAddress);
                
                _logger.LogWarning(
                    $"Login failed: {username} | IP: {ipAddress} | Attempts remaining: {remainingAttempts}"
                );

                throw new Exception($"Invalid username or password. Attempts remaining: {remainingAttempts}");
            }

            // Check if account has excessive concurrent IPs (possible account compromise)
            if (_rateLimitingService.HasExcessiveIPCount(username))
            {
                var activeIPs = _rateLimitingService.GetUserActiveIPs(username);
                _logger.LogError(
                    $"⚠️ SECURITY ALERT: {username} | IP: {ipAddress} | Multiple IPs: {activeIPs.Count} in 24h | Active IPs: {string.Join(", ", activeIPs)}"
                );
                // Could implement additional security measures here like requiring email verification
            }

            // Reset login attempts on successful login and record this IP
            _rateLimitingService.ResetLoginAttempts(username, ipAddress);
            _rateLimitingService.RecordSuccessfulLogin(username, ipAddress);
            
            // If user is already logged in from a different device, send force logout to previous session
            if (!string.IsNullOrEmpty(user.LastActiveToken) && user.LastLoginTime.HasValue)
            {
                // Only force logout if the new login is from a different device/IP
                if (user.LastLoginDevice != ipAddress)
                {
                    _logger.LogInformation($"Force logout: {username} | Previous IP: {user.LastLoginDevice} | New IP: {ipAddress}");
                    try
                    {
                        await _sessionHubContext.Clients.User(user.Id.ToString()).ForceLogout(user.Id.ToString());
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Failed to send force logout signal (user may not be connected): {ex.Message}");
                        // Don't fail the login if the force logout signal fails
                    }
                }
            }
            
            _logger.LogInformation($"Login: {username} | IP: {ipAddress}");

            var token = GenerateJwtToken(user);
            
            // Update user's session information
            user.LastActiveToken = token;
            user.LastLoginTime = DateTime.UtcNow;
            user.LastLoginDevice = ipAddress;
            await _context.SaveChangesAsync();
            
            return new AuthResponseDTO
            {
                Token = token,
                Username = user.Username,
                Role = user.Role,
                Id = user.Id
            };
        }

        public async Task<AuthResponseDTO> Register(RegisterDTO registerDTO)
        {
            if (registerDTO == null)
                throw new ArgumentNullException(nameof(registerDTO));

            // Validate input
            var usernameValidation = _validationService.ValidateUsername(registerDTO.Username);
            if (!usernameValidation.IsValid)
                throw new Exception(usernameValidation.Message);

            var emailValidation = _validationService.ValidateEmail(registerDTO.Email);
            if (!emailValidation.IsValid)
                throw new Exception(emailValidation.Message);

            var passwordValidation = _validationService.ValidatePassword(registerDTO.Password);
            if (!passwordValidation.IsValid)
                throw new Exception(passwordValidation.Message);

            var phoneValidation = _validationService.ValidatePhoneNumber(registerDTO.PhoneNumber ?? "");
            if (!phoneValidation.IsValid)
                throw new Exception(phoneValidation.Message);

            var ssnValidation = _validationService.ValidateSSN(registerDTO.SSN);
            if (!ssnValidation.IsValid)
                throw new Exception(ssnValidation.Message);

            // Sanitize inputs
            var username = _validationService.SanitizeHtmlInput(registerDTO.Username);
            var email = _validationService.SanitizeHtmlInput(registerDTO.Email);
            var firstName = _validationService.SanitizeHtmlInput(registerDTO.FirstName);
            var lastName = _validationService.SanitizeHtmlInput(registerDTO.LastName);

            // Check for duplicates
            if (await _context.Users.AnyAsync(u => u.Username == username))
                throw new Exception("Username already exists");

            if (await _context.Users.AnyAsync(u => u.Email == email))
                throw new Exception("Email already exists");

            // Encrypt sensitive data
            var encryptedSSN = _encryptionService.Encrypt(registerDTO.SSN);
            var encryptedPhone = string.IsNullOrEmpty(registerDTO.PhoneNumber) 
                ? null 
                : _encryptionService.Encrypt(registerDTO.PhoneNumber);

            var user = new User
            {
                Username = username,
                Password = BCrypt.Net.BCrypt.HashPassword(registerDTO.Password),
                Role = "User",
                Email = email,
                CreatedAt = DateTime.UtcNow,
                FirstName = firstName,
                LastName = lastName,
                SSN = encryptedSSN,
                PhoneNumber = encryptedPhone
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            var token = GenerateJwtToken(user);
            
            // Update user's session information (same as login)
            user.LastActiveToken = token;
            user.LastLoginTime = DateTime.UtcNow;
            user.LastLoginDevice = "unknown"; // We don't have IP during registration
            await _context.SaveChangesAsync();
            
            return new AuthResponseDTO
            {
                Token = token,
                Username = user.Username,
                Role = user.Role,
                Id = user.Id
            };
        }

        public async Task<(bool success, string message)> RequestLibrarianRole(long userId, string requestMessage)
        {
            if (userId <= 0)
                return (false, "User ID must be greater than 0.");

            var sanitizedMessage = _validationService.SanitizeHtmlInput(requestMessage?.Trim() ?? string.Empty);
            if (string.IsNullOrWhiteSpace(sanitizedMessage))
                return (false, "Request message is required.");

            // Enforce database length constraint proactively to avoid SQL truncation errors
            if (sanitizedMessage.Length > 500)
                sanitizedMessage = sanitizedMessage.Substring(0, 500);

            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                return (false, "User not found");
            }

            if (user.Role != "User")
            {
                return (false, "Only regular users can request librarian role");
            }

            var existingRequest = await _context.LibrarianRequests
                .FirstOrDefaultAsync(lr => lr.UserId == userId && lr.Status == "Pending");

            if (existingRequest != null)
            {
                return (true, "You already have a pending request. We will review it shortly.");
            }

            var request = new LibrarianRequest
            {
                UserId = userId,
                RequestDate = DateTime.UtcNow,
                Status = "Pending",
                RequestMessage = sanitizedMessage
            };

            _context.LibrarianRequests.Add(request);
            await _context.SaveChangesAsync();
            return (true, "Your request has been submitted successfully.");
        }

        private string GenerateJwtToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim("userId", user.Id.ToString(), ClaimValueTypes.Integer64),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString(), ClaimValueTypes.Integer64)
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(12),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}

