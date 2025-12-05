using BackEnd.Data;
using BackEnd.DTOs;
using BackEnd.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace BackEnd.Services
{
    public class AuthService : IAuthService
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IValidationService _validationService;
        private readonly IEncryptionService _encryptionService;
        private readonly IRateLimitingService _rateLimitingService;

        public AuthService(
            ApplicationDbContext context, 
            IConfiguration configuration,
            IValidationService validationService,
            IEncryptionService encryptionService,
            IRateLimitingService rateLimitingService)
        {
            _context = context;
            _configuration = configuration;
            _validationService = validationService;
            _encryptionService = encryptionService;
            _rateLimitingService = rateLimitingService;
        }

        public async Task<AuthResponseDTO> Login(LoginDTO loginDTO)
        {
            // Sanitize input
            var username = _validationService.SanitizeHtmlInput(loginDTO.Username);
            var password = loginDTO.Password;

            // Check rate limiting
            if (_rateLimitingService.IsAccountLockedOut(username))
            {
                throw new Exception("Account locked due to too many login attempts. Try again later.");
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.Password))
            {
                _rateLimitingService.RecordLoginAttempt(username);
                throw new Exception("Invalid username or password");
            }

            // Reset login attempts on successful login
            _rateLimitingService.ResetLoginAttempts(username);

            var token = GenerateJwtToken(user);
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
            return new AuthResponseDTO
            {
                Token = token,
                Username = user.Username,
                Role = user.Role,
                Id = user.Id
            };
        }

        public async Task<bool> RequestLibrarianRole(long userId, string requestMessage)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                throw new Exception("User not found");
            }

            if (user.Role != "User")
            {
                throw new Exception("Only regular users can request librarian role");
            }

            var existingRequest = await _context.LibrarianRequests
                .FirstOrDefaultAsync(lr => lr.UserId == userId && lr.Status == "Pending");

            if (existingRequest != null)
            {
                throw new Exception("You already have a pending request");
            }

            var request = new LibrarianRequest
            {
                UserId = userId,
                RequestDate = DateTime.UtcNow,
                Status = "Pending",
                RequestMessage = requestMessage
            };

            _context.LibrarianRequests.Add(request);
            await _context.SaveChangesAsync();
            return true;
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
                new Claim("userId", user.Id.ToString(), ClaimValueTypes.Integer64)
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

