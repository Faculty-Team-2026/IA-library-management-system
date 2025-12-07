// Controllers/UsersController.cs
using BackEnd.DTOs;
using BackEnd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace BackEnd.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly ILoggerService _loggerService;

        public UsersController(IUserService userService, ILoggerService loggerService)
        {
            _userService = userService ?? throw new ArgumentNullException(nameof(userService));
            _loggerService = loggerService ?? throw new ArgumentNullException(nameof(loggerService));
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userService.GetAllUsers();
            return Ok(users);
        }

        [HttpGet("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetUserById(long id)
        {
            try
            {
                var user = await _userService.GetUserById(id);
                return Ok(user);
            }
            catch (Exception ex)
            {
                return NotFound(new { message = ex.Message });
            }
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateUser([FromBody] UserDTO userDTO)
        {
            try
            {
                var adminIdClaim = User?.FindFirst("userId");
                var adminNameClaim = User?.FindFirst(ClaimTypes.NameIdentifier) ?? User?.FindFirst(JwtRegisteredClaimNames.Sub);
                
                var user = await _userService.CreateUser(userDTO);
                
                // Log user creation
                await _loggerService.LogAsync(
                    "info",
                    $"User Created: {user.Username} | Role: {user.Role}",
                    "User Management",
                    adminIdClaim?.Value,
                    adminNameClaim?.Value ?? "Admin"
                );
                
                return CreatedAtAction(nameof(GetUserById), new { id = user.Id }, user);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPut("{id}")]
        [Authorize]
        public async Task<IActionResult> UpdateUser(long id, [FromBody] UpdateUserDTO updateUserDTO)
        {
            try
            {
                if (updateUserDTO == null)
                    return BadRequest(new { message = "Update user request cannot be null" });

                //Check if the user is updating their own profile or is an admin
                var userIdClaim = User?.FindFirst("userId");
                if (userIdClaim == null || !long.TryParse(userIdClaim.Value, out var userId))
                    return Unauthorized(new { message = "User ID claim not found. Please log in again." });

                var isAdmin = User.IsInRole("Admin");

                if (!isAdmin && userId != id)
                {
                    return Forbid();
                }

                var user = await _userService.UpdateUser(id, updateUserDTO);
                
                // Log user update
                var updaterNameClaim = User?.FindFirst(ClaimTypes.NameIdentifier) ?? User?.FindFirst(JwtRegisteredClaimNames.Sub);
                await _loggerService.LogAsync(
                    "info",
                    $"User Updated: {user.Username}",
                    "User Management",
                    userId.ToString(),
                    updaterNameClaim?.Value ?? "Unknown"
                );
                
                return Ok(user);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteUser(long id)
        {
            try
            {
                var adminIdClaim = User?.FindFirst("userId");
                var adminNameClaim = User?.FindFirst(ClaimTypes.NameIdentifier) ?? User?.FindFirst(JwtRegisteredClaimNames.Sub);
                
                // Get user info before deletion
                var userToDelete = await _userService.GetUserById(id);
                
                var result = await _userService.DeleteUser(id);
                if (result)
                {
                    // Log user deletion
                    await _loggerService.LogAsync(
                        "info",
                        $"User Deleted: {userToDelete.Username}",
                        "User Management",
                        adminIdClaim?.Value,
                        adminNameClaim?.Value ?? "Admin"
                    );
                    
                    return NoContent();
                }
                return NotFound();
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }


        }

        [HttpGet("profile")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUserProfile()
        {
            try
            {
                // Retrieve the current user's ID from claims
                var userIdClaim = User.FindFirst("userId");
                if (userIdClaim == null || !long.TryParse(userIdClaim.Value, out long userId))
                {
                    return Unauthorized(new { message = "User ID not found in token" });
                }


                // Get the user's profile
                var user = await _userService.GetCurrentUserProfile(userId);
                if (user == null)
                {
                    return NotFound(new { message = "User not found" });
                }

                return Ok(user);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while retrieving the user profile", details = ex.Message });
            }
        }

    }
}