using BackEnd.Data;
using BackEnd.DTOs;
using BackEnd.Models;
using BackEnd.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace BackEnd.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SSOController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IAuthService _authService;
        private readonly IValidationService _validationService;
        private readonly IEncryptionService _encryptionService;

        public SSOController(
            ApplicationDbContext context,
            IAuthService authService,
            IValidationService validationService,
            IEncryptionService encryptionService)
        {
            _context = context;
            _authService = authService;
            _validationService = validationService;
            _encryptionService = encryptionService;
        }

        /// <summary>
        /// Google OAuth2 callback endpoint
        /// </summary>
        [HttpPost("google")]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginDTO googleLogin)
        {
            try
            {
                if (string.IsNullOrEmpty(googleLogin?.GoogleToken))
                {
                    return BadRequest(new { message = "Google token is required" });
                }

                // In production, verify the Google token with Google's servers
                // For now, we'll extract the email from the token payload (in real scenario, verify with Google API)
                var email = ExtractEmailFromGoogleToken(googleLogin.GoogleToken);

                if (string.IsNullOrEmpty(email))
                {
                    return BadRequest(new { message = "Invalid Google token" });
                }

                // Check if user exists
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);

                if (user == null)
                {
                    // Create new user from Google login
                    var username = email.Split('@')[0]; // Use email prefix as username
                    
                    // Ensure username is unique
                    var baseUsername = username;
                    int counter = 1;
                    while (await _context.Users.AnyAsync(u => u.Username == username))
                    {
                        username = $"{baseUsername}{counter}";
                        counter++;
                    }

                    user = new User
                    {
                        Username = username,
                        Email = email,
                        Password = BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString()), // Random password
                        Role = "User",
                        CreatedAt = DateTime.UtcNow,
                        FirstName = googleLogin.FirstName ?? email.Split('@')[0],
                        LastName = googleLogin.LastName ?? "GoogleUser",
                        SSN = _encryptionService.Encrypt($"SSO-GOOGLE-{email}"), // Unique per user
                        PhoneNumber = null
                    };

                    _context.Users.Add(user);
                    await _context.SaveChangesAsync();
                }

                // Generate JWT token
                var token = GenerateJwtTokenForUser(user);

                return Ok(new
                {
                    token = token,
                    username = user.Username,
                    role = user.Role,
                    id = user.Id,
                    email = user.Email,
                    ssoProvider = "Google"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "SSO login failed", error = ex.Message });
            }
        }

        /// <summary>
        /// GitHub OAuth2 callback endpoint
        /// </summary>
        [HttpPost("github")]
        public async Task<IActionResult> GitHubLogin([FromBody] GitHubLoginDTO githubLogin)
        {
            try
            {
                if (string.IsNullOrEmpty(githubLogin?.GitHubToken))
                {
                    return BadRequest(new { message = "GitHub token is required" });
                }

                // In production, verify the GitHub token with GitHub's API
                var email = ExtractEmailFromGitHubToken(githubLogin.GitHubToken);

                if (string.IsNullOrEmpty(email))
                {
                    return BadRequest(new { message = "Invalid GitHub token" });
                }

                // Check if user exists
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);

                if (user == null)
                {
                    // Create new user from GitHub login
                    var username = githubLogin.GitHubUsername ?? email.Split('@')[0];
                    
                    // Ensure username is unique
                    var baseUsername = username;
                    int counter = 1;
                    while (await _context.Users.AnyAsync(u => u.Username == username))
                    {
                        username = $"{baseUsername}{counter}";
                        counter++;
                    }

                    user = new User
                    {
                        Username = username,
                        Email = email,
                        Password = BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString()), // Random password
                        Role = "User",
                        CreatedAt = DateTime.UtcNow,
                        FirstName = githubLogin.FirstName ?? username,
                        LastName = githubLogin.LastName ?? "GitHubUser",
                        SSN = _encryptionService.Encrypt($"SSO-GITHUB-{email}"), // Unique per user
                        PhoneNumber = null
                    };

                    _context.Users.Add(user);
                    await _context.SaveChangesAsync();
                }

                // Generate JWT token
                var token = GenerateJwtTokenForUser(user);

                return Ok(new
                {
                    token = token,
                    username = user.Username,
                    role = user.Role,
                    id = user.Id,
                    email = user.Email,
                    ssoProvider = "GitHub"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "SSO login failed", error = ex.Message });
            }
        }

        /// <summary>
        /// Microsoft OAuth2 callback endpoint
        /// </summary>
        [HttpPost("microsoft")]
        public async Task<IActionResult> MicrosoftLogin([FromBody] MicrosoftLoginDTO microsoftLogin)
        {
            try
            {
                if (string.IsNullOrEmpty(microsoftLogin?.MicrosoftToken))
                {
                    return BadRequest(new { message = "Microsoft token is required" });
                }

                // In production, verify the Microsoft token with Microsoft's API
                var email = ExtractEmailFromMicrosoftToken(microsoftLogin.MicrosoftToken);

                if (string.IsNullOrEmpty(email))
                {
                    return BadRequest(new { message = "Invalid Microsoft token" });
                }

                // Check if user exists
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);

                if (user == null)
                {
                    // Create new user from Microsoft login
                    var username = email.Split('@')[0];
                    
                    // Ensure username is unique
                    var baseUsername = username;
                    int counter = 1;
                    while (await _context.Users.AnyAsync(u => u.Username == username))
                    {
                        username = $"{baseUsername}{counter}";
                        counter++;
                    }

                    user = new User
                    {
                        Username = username,
                        Email = email,
                        Password = BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString()), // Random password
                        Role = "User",
                        CreatedAt = DateTime.UtcNow,
                        FirstName = microsoftLogin.FirstName ?? email.Split('@')[0],
                        LastName = microsoftLogin.LastName ?? "MicrosoftUser",
                        SSN = _encryptionService.Encrypt($"SSO-MICROSOFT-{email}"), // Unique per user
                        PhoneNumber = null
                    };

                    _context.Users.Add(user);
                    await _context.SaveChangesAsync();
                }

                // Generate JWT token
                var token = GenerateJwtTokenForUser(user);

                return Ok(new
                {
                    token = token,
                    username = user.Username,
                    role = user.Role,
                    id = user.Id,
                    email = user.Email,
                    ssoProvider = "Microsoft"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "SSO login failed", error = ex.Message });
            }
        }

        /// <summary>
        /// Helper method to extract and validate email from Google JWT token
        /// Google JWT contains user info in the payload
        /// </summary>
        private string? ExtractEmailFromGoogleToken(string token)
        {
            try
            {
                // Decode the JWT manually (JWT format: header.payload.signature)
                var parts = token.Split('.');
                if (parts.Length != 3)
                    return null;

                // Decode the payload (2nd part)
                var payload = parts[1];
                
                // Add padding if needed
                payload += new string('=', (4 - payload.Length % 4) % 4);
                
                var decodedBytes = Convert.FromBase64String(payload);
                var jsonPayload = System.Text.Encoding.UTF8.GetString(decodedBytes);
                
                // Parse JSON to extract email
                var json = System.Text.Json.JsonDocument.Parse(jsonPayload);
                if (json.RootElement.TryGetProperty("email", out var emailElement))
                {
                    return emailElement.GetString();
                }
                
                return null;
            }
            catch
            {
                // In production, validate token with Google's servers:
                // https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=<token>
                return null;
            }
        }

        /// <summary>
        /// Helper method to extract email from GitHub token (simplified)
        /// </summary>
        private string? ExtractEmailFromGitHubToken(string token)
        {
            try
            {
                // This is a simplified version. In production, you should:
                // 1. Call GitHub's user endpoint: https://api.github.com/user
                // 2. Use the token as Authorization header
                // 3. Extract email from response
                
                // For now, return a placeholder - implement actual GitHub API call
                return token.Contains("@") ? token : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Helper method to extract email from Microsoft token (simplified)
        /// </summary>
        private string? ExtractEmailFromMicrosoftToken(string token)
        {
            try
            {
                // This is a simplified version. In production, you should:
                // 1. Call Microsoft's me endpoint: https://graph.microsoft.com/v1.0/me
                // 2. Use the token as Authorization header
                // 3. Extract email from response
                
                // For now, return a placeholder - implement actual Microsoft API call
                return token.Contains("@") ? token : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Generate JWT token for SSO user
        /// </summary>
        private string GenerateJwtTokenForUser(User user)
        {
            var config = HttpContext.RequestServices.GetService(typeof(IConfiguration)) as IConfiguration
                ?? throw new InvalidOperationException("Configuration not found");
            
            var jwtKey = config["Jwt:Key"] 
                ?? throw new InvalidOperationException("JWT Key not configured");
            
            var jwtKeyBytes = new System.Text.UTF8Encoding().GetBytes(jwtKey);

            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var tokenDescriptor = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new[]
                {
                    new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, user.Username),
                    new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new System.Security.Claims.Claim("userId", user.Id.ToString()),
                    new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, user.Role),
                    new System.Security.Claims.Claim("email", user.Email ?? "unknown@example.com")
                }),
                Expires = DateTime.UtcNow.AddHours(12),
                Issuer = config["Jwt:Issuer"] ?? "aalam_al_kutub",
                Audience = config["Jwt:Audience"] ?? "aalam_al_kutub_users",
                SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                    new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(jwtKeyBytes),
                    Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
