using BackEnd.Data;
using BackEnd.DTOs;
using Microsoft.EntityFrameworkCore;

namespace BackEnd.Services
{
    public class LibrarianService : ILibrarianService
    {
        private readonly ApplicationDbContext _context;

        public LibrarianService(ApplicationDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public async Task<IEnumerable<LibrarianRequestDTO>> GetLibrarianRequests(string status)
        {
            return await _context.LibrarianRequests
                .Include(lr => lr.User)
                .Where(lr => string.IsNullOrEmpty(status) || lr.Status == status)
                .Select(lr => new LibrarianRequestDTO
                {
                    Id = lr.Id,
                    UserId = lr.UserId,
                    Username = lr.User.Username,
                    RequestDate = lr.RequestDate,
                    RequestMessage = lr.RequestMessage,
                    Status = lr.Status
                })
                .ToListAsync();
        }

        public async Task<LibrarianRequestDTO> ApproveLibrarianRequest(long requestId, long adminId)
        {
            var request = await _context.LibrarianRequests
                .Include(lr => lr.User)
                .FirstOrDefaultAsync(lr => lr.Id == requestId);

            if (request == null)
            {
                throw new Exception("Librarian request not found");
            }

            if (request.Status != "Pending")
            {
                throw new Exception("Only pending requests can be approved");
            }

            var user = request.User;
            if (user.Role != "User")
            {
                throw new Exception("Only regular users can be promoted to librarian");
            }

            user.Role = "Librarian";
            _context.Users.Update(user);

            request.Status = "Approved";
            _context.LibrarianRequests.Update(request);

            await _context.SaveChangesAsync();

            return new LibrarianRequestDTO
            {
                Id = request.Id,
                UserId = request.UserId,
                Username = user.Username,
                RequestDate = request.RequestDate,
                RequestMessage = request.RequestMessage,
                Status = request.Status
            };
        }

        public async Task<LibrarianRequestDTO> RejectLibrarianRequest(long requestId, long adminId)
        {
            var request = await _context.LibrarianRequests
                .Include(lr => lr.User)
                .FirstOrDefaultAsync(lr => lr.Id == requestId);

            if (request == null)
            {
                throw new Exception("Librarian request not found");
            }

            if (request.Status != "Pending")
            {
                throw new Exception("Only pending requests can be rejected");
            }

            request.Status = "Rejected";
            _context.LibrarianRequests.Update(request);
            await _context.SaveChangesAsync();

            return new LibrarianRequestDTO
            {
                Id = request.Id,
                UserId = request.UserId,
                Username = request.User.Username,
                RequestDate = request.RequestDate,
                RequestMessage = request.RequestMessage,
                Status = request.Status
            };
        }

        public async Task<IEnumerable<UserDTO>> GetAllLibrarians()
        {
            return await _context.Users
                .Where(u => u.Role == "Librarian")
                .Select(u => new UserDTO
                {
                    Id = u.Id,
                    Username = u.Username,
                    Role = u.Role,
                    CreatedAt = u.CreatedAt,
                    Email = u.Email
                })
                .ToListAsync();
        }

        public async Task<bool> DeleteLibrarian(long librarianId)
        {
            var librarian = await _context.Users.FindAsync(librarianId);
            if (librarian == null)
            {
                throw new Exception("Librarian not found");
            }

            if (librarian.Role != "Librarian")
            {
                throw new Exception("User is not a librarian");
            }

            // Check if librarian has any pending actions
            var hasPendingRequests = await _context.BorrowRequests
                .AnyAsync(br => br.Status == "Pending");

            if (hasPendingRequests)
            {
                throw new Exception("Cannot delete librarian with pending requests");
            }

            librarian.Role = "User";
            _context.Users.Update(librarian);
            await _context.SaveChangesAsync();
            return true;
        }
    }
}
