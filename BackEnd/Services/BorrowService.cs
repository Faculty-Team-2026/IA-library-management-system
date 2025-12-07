using BackEnd.Data;
using BackEnd.DTOs;
using BackEnd.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace BackEnd.Services
{
    public class BorrowService : IBorrowService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<BorrowService> _logger;

        public BorrowService(ApplicationDbContext context, ILogger<BorrowService> logger)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<BorrowRequestDTO> RequestBorrow(long userId, long bookId)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var user = await _context.Users
                    .Include(u => u.UserMemberships)
                    .ThenInclude(um => um.Membership)
                    .FirstOrDefaultAsync(u => u.Id == userId);

                if (user == null)
                {
                    throw new Exception("User not found");
                }

                var activeMembership = user.UserMemberships
                    .FirstOrDefault(um => um.IsActive &&
                                         um.Status == "Approved" &&
                                         (um.EndDate == null || um.EndDate > DateTime.UtcNow));

                if (activeMembership == null)
                {
                    throw new Exception("User does not have an active membership");
                }

                var book = await _context.Books.FindAsync(bookId);
                if (book == null)
                {
                    throw new Exception("Book not found");
                }

                if (!book.Available || book.Quantity <= 0)
                {
                    throw new Exception("Book is not available for borrowing");
                }

                var currentBorrowCount = await _context.BorrowRecords
                    .CountAsync(br => br.UserId == userId &&
                                    br.Status == "Borrowed" &&
                                    br.ReturnDate == null);

                if (currentBorrowCount >= activeMembership.Membership.BorrowLimit)
                {
                    throw new Exception($"Borrow limit reached. Your membership allows {activeMembership.Membership.BorrowLimit} books at a time.");
                }

                var existingRequest = await _context.BorrowRequests
                    .FirstOrDefaultAsync(br => br.UserId == userId &&
                                             br.BookId == bookId &&
                                             (br.Status == "Pending" || br.Status == "Approved"));

                if (existingRequest != null)
                {
                    throw new Exception("You already have a pending or approved request for this book");
                }

                book.Quantity--;
                book.Available = book.Quantity > 0;
                _context.Books.Update(book);

                var request = new BorrowRequest
                {
                    UserId = userId,
                    BookId = bookId,
                    RequestDate = DateTime.UtcNow,
                    Status = "Pending"
                };

                _context.BorrowRequests.Add(request);
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation($"Borrow request: User {userId} | Book {bookId}");

                return new BorrowRequestDTO
                {
                    Id = request.Id,
                    UserId = request.UserId,
                    Username = user.Username,
                    BookId = request.BookId,
                    BookTitle = book.Title,
                    RequestDate = request.RequestDate,
                    Status = request.Status
                };
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, $"Borrow error: Failed to request borrow | User {userId} | Book {bookId}");
                throw;
            }
        }

        public async Task<IEnumerable<BorrowRequestDTO>> GetBorrowRequests(string status)
        {
            return await _context.BorrowRequests
                .Include(br => br.User)
                .Include(br => br.Book)
                .Where(br => string.IsNullOrEmpty(status) || br.Status == status)
                .Select(br => new BorrowRequestDTO
                {
                    Id = br.Id,
                    UserId = br.UserId,
                    Username = br.User.Username,
                    BookId = br.BookId,
                    BookTitle = br.Book.Title,
                    RequestDate = br.RequestDate,
                    Status = br.Status
                })
                .ToListAsync();
        }

        public async Task<BorrowRequestDTO> ApproveBorrowRequest(long requestId, long librarianId)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var request = await _context.BorrowRequests
                    .Include(br => br.User)
                    .ThenInclude(u => u.UserMemberships)
                    .ThenInclude(um => um.Membership)
                    .Include(br => br.Book)
                    .FirstOrDefaultAsync(br => br.Id == requestId);

                if (request == null)
                {
                    throw new Exception("Borrow request not found");
                }

                if (request.Status != "Pending")
                {
                    throw new Exception("Only pending requests can be approved");
                }

                var user = request.User;
                var activeMembership = user.UserMemberships
                    .FirstOrDefault(um => um.IsActive &&
                                        um.Status == "Approved" &&
                                        (um.EndDate == null || um.EndDate > DateTime.UtcNow));

                if (activeMembership == null)
                {
                    throw new Exception("User no longer has an active membership");
                }

                var currentBorrowCount = await _context.BorrowRecords
                    .CountAsync(br => br.UserId == user.Id &&
                                    br.Status == "Borrowed" &&
                                    br.ReturnDate == null);

                if (currentBorrowCount >= activeMembership.Membership.BorrowLimit)
                {
                    throw new Exception($"User has reached their borrow limit of {activeMembership.Membership.BorrowLimit} books");
                }

                var book = request.Book;

                var record = new BorrowRecord
                {
                    UserId = request.UserId,
                    BookId = request.BookId,
                    BookTitle = book.Title,
                    BookAuthor = book.Author,
                    BookISBN = book.ISBN,
                    BorrowDate = DateTime.UtcNow,
                    DueDate = DateTime.UtcNow.AddDays(activeMembership.Membership.DurationInDays),
                    Status = "Borrowed"
                };

                _context.BorrowRecords.Add(record);

                _context.BorrowRequests.Remove(request);

                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                return new BorrowRequestDTO
                {
                    Id = request.Id,
                    UserId = request.UserId,
                    Username = user.Username,
                    BookId = request.BookId,
                    BookTitle = book.Title,
                    RequestDate = request.RequestDate,
                    Status = "Approved"
                };
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, $"Borrow error: Failed to approve request | Request {requestId}");
                throw;
            }
        }

        public async Task<BorrowRequestDTO> RejectBorrowRequest(long requestId, long librarianId)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var request = await _context.BorrowRequests
                    .Include(br => br.User)
                    .Include(br => br.Book)
                    .FirstOrDefaultAsync(br => br.Id == requestId);

                if (request == null)
                {
                    throw new Exception("Borrow request not found");
                }

                if (request.Status != "Pending")
                {
                    throw new Exception("Only pending requests can be rejected");
                }

                var book = request.Book;
                book.Quantity++;
                book.Available = true;
                _context.Books.Update(book);

                _context.BorrowRequests.Remove(request);
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation($"Borrow rejected: Request {requestId} | Book {request.BookId}");

                return new BorrowRequestDTO
                {
                    Id = request.Id,
                    UserId = request.UserId,
                    Username = request.User.Username,
                    BookId = request.BookId,
                    BookTitle = request.Book.Title,
                    RequestDate = request.RequestDate,
                    Status = "Rejected"
                };
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, $"Borrow error: Failed to reject request | Request {requestId}");
                throw;
            }
        }

        public async Task<BorrowRecordDTO> ReturnBook(long recordId, long librarianId)
        {
            try
            {
                var record = await _context.BorrowRecords
                    .Include(br => br.User)
                    .Include(br => br.Book)
                    .FirstOrDefaultAsync(br => br.Id == recordId);

                if (record == null)
                {
                    throw new Exception("Borrow record not found");
                }

                if (record.Status == "Returned")
                {
                    throw new Exception("Book has already been returned");
                }

                record.Status = "Returned";
                record.ReturnDate = DateTime.UtcNow;
                _context.BorrowRecords.Update(record);

                if (record.Book != null)
                {
                    var book = record.Book;
                    book.Quantity++;
                    book.Available = true;
                    _context.Books.Update(book);
                }

                await _context.SaveChangesAsync();

                _logger.LogInformation($"Book returned: Record {recordId} | User {record.UserId} | Book {record.BookId}");

                return new BorrowRecordDTO
                {
                    Id = record.Id,
                    UserId = record.UserId,
                    Username = record.User.Username,
                    BookId = record.BookId,
                    BookTitle = record.BookTitle ?? record.Book?.Title,
                    BookAuthor = record.BookAuthor ?? record.Book?.Author,
                    BookISBN = record.BookISBN ?? record.Book?.ISBN,
                    BorrowDate = record.BorrowDate,
                    DueDate = record.DueDate,
                    ReturnDate = record.ReturnDate,
                    Status = record.Status
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Borrow error: Failed to return book | Record {recordId}");
                throw;
            }
        }

        public async Task<IEnumerable<BorrowRecordDTO>> GetBorrowRecords()
        {
            return await _context.BorrowRecords
                .Include(br => br.User)
                .Include(br => br.Book)
                .Select(br => new BorrowRecordDTO
                {
                    Id = br.Id,
                    UserId = br.UserId,
                    Username = br.User.Username,
                    BookId = br.BookId,
                    BookTitle = br.BookTitle != null ? br.BookTitle : br.Book != null ? br.Book.Title : null,
                    BookAuthor = br.BookAuthor != null ? br.BookAuthor : br.Book != null ? br.Book.Author : null,
                    BookISBN = br.BookISBN != null ? br.BookISBN : br.Book != null ? br.Book.ISBN : null,
                    BorrowDate = br.BorrowDate,
                    DueDate = br.DueDate,
                    ReturnDate = br.ReturnDate,
                    Status = br.Status
                })
                .ToListAsync();
        }

        public async Task<IEnumerable<BorrowRecordDTO>> GetUserBorrowRecords(long userId)
        {
            return await _context.BorrowRecords
                .Include(br => br.User)
                .Include(br => br.Book)
                .Where(br => br.UserId == userId)
                .Select(br => new BorrowRecordDTO
                {
                    Id = br.Id,
                    UserId = br.UserId,
                    Username = br.User.Username,
                    BookId = br.BookId,
                    BookTitle = br.BookTitle != null ? br.BookTitle : (br.Book != null ? br.Book.Title : null),
                    BookAuthor = br.BookAuthor != null ? br.BookAuthor : (br.Book != null ? br.Book.Author : null),
                    BookISBN = br.BookISBN != null ? br.BookISBN : (br.Book != null ? br.Book.ISBN : null),
                    BorrowDate = br.BorrowDate,
                    DueDate = br.DueDate,
                    ReturnDate = br.ReturnDate,
                    Status = br.Status
                })
                .ToListAsync();
        }
    }
}
