using BackEnd.Data;
using BackEnd.DTOs;
using BackEnd.Models;
using Microsoft.EntityFrameworkCore;


namespace BackEnd.Services
{
    public class UserService : IUserService
    {
        private readonly ApplicationDbContext _context;

        public UserService(ApplicationDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public async Task<IEnumerable<UserDTO>> GetAllUsers()
        {
            return await _context.Users
                .Select(u => new UserDTO
                {
                    Id = u.Id,
                    Username = u.Username,
                    Role = u.Role,
                    CreatedAt = u.CreatedAt,
                    Email = u.Email,
                    FirstName = u.FirstName,
                    LastName = u.LastName,
                    SSN = u.SSN,
                    PhoneNumber = u.PhoneNumber
                })
                .ToListAsync();
        }

        public async Task<UserDTO> GetUserById(long id)
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Id == id);
        
            if (user == null)
            {
                throw new Exception("User not found");
            }

            return new UserDTO
            {
                Id = user.Id,
                Username = user.Username,
                Role = user.Role,
                CreatedAt = user.CreatedAt,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                SSN = user.SSN,
                PhoneNumber = user.PhoneNumber
            };
        }

        public async Task<UserDTO> CreateUser(UserDTO userDTO)
        {
            if (await _context.Users.AnyAsync(u => u.Username == userDTO.Username))
            {
                throw new Exception("Username already exists");
            }

            if (await _context.Users.AnyAsync(u => u.Email == userDTO.Email))
            {
                throw new Exception("Email already exists");
            }

            var user = new User
            {
                Username = userDTO.Username,
                Password = BCrypt.Net.BCrypt.HashPassword(userDTO.Password),
                Role = userDTO.Role,
                Email = userDTO.Email,
                CreatedAt = DateTime.UtcNow,
                FirstName = userDTO.FirstName,
                LastName = userDTO.LastName,
                SSN = userDTO.SSN,
                PhoneNumber = userDTO.PhoneNumber
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDTO
            {
                Id = user.Id,
                Username = user.Username,
                Role = user.Role,
                CreatedAt = user.CreatedAt,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                SSN = user.SSN,
                PhoneNumber = user.PhoneNumber
            };
        }

        public async Task<UserDTO> UpdateUser(long id, UpdateUserDTO updateUserDTO)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                throw new Exception("User not found");
            }

            // Check if username is being changed to one that already exists
            if (!string.IsNullOrWhiteSpace(updateUserDTO.Username) &&
                user.Username != updateUserDTO.Username &&
                await _context.Users.AnyAsync(u => u.Username == updateUserDTO.Username))
            {
                throw new Exception("Username already exists");
            }

            // Check if email is being changed to one that already exists
            if (!string.IsNullOrWhiteSpace(updateUserDTO.Email) &&
                user.Email != updateUserDTO.Email &&
                await _context.Users.AnyAsync(u => u.Email == updateUserDTO.Email))
            {
                throw new Exception("Email already exists");
            }

            // Update fields if they are provided (not null or whitespace)
            if (!string.IsNullOrWhiteSpace(updateUserDTO.Username))
                user.Username = updateUserDTO.Username;

            if (!string.IsNullOrWhiteSpace(updateUserDTO.Email))
                user.Email = updateUserDTO.Email;

            if (!string.IsNullOrWhiteSpace(updateUserDTO.FirstName))
                user.FirstName = updateUserDTO.FirstName;

            if (!string.IsNullOrWhiteSpace(updateUserDTO.LastName))
                user.LastName = updateUserDTO.LastName;

            if (!string.IsNullOrWhiteSpace(updateUserDTO.PhoneNumber))
                user.PhoneNumber = updateUserDTO.PhoneNumber;
            else 
                user.PhoneNumber = null;  // Set to null if not provided

            if (!string.IsNullOrWhiteSpace(updateUserDTO.Role))
                user.Role = updateUserDTO.Role;

            // Do not update SSN and Role

            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return new UserDTO
            {
                Id = user.Id,
                Username = user.Username,
                Role = user.Role,
                CreatedAt = user.CreatedAt,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                SSN = user.SSN, // Still not updating SSN
                PhoneNumber = user.PhoneNumber
            };
        }


        public async Task<UserDTO> GetCurrentUserProfile(long userId)
        {
            // Retrieve the user from the database
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                return null;
            }

            // Map the user to a UserDTO to ensure data privacy
            return new UserDTO
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                PhoneNumber = user.PhoneNumber,
                CreatedAt = user.CreatedAt,
                Role = user.Role
            };
        }

        public async Task<bool> DeleteUser(long id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                throw new Exception("User not found");
            }

            // Check if user has any active borrow records
            var hasActiveBorrows = await _context.BorrowRecords
                .AnyAsync(br => br.UserId == id && br.Status == "Borrowed");

            if (hasActiveBorrows)
            {
                throw new Exception("Cannot delete user with active borrows");
            }

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            return true;
        }
    }
}