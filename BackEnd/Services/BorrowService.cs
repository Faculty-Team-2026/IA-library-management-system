﻿using BackEnd.Data;
using BackEnd.DTOs;
using BackEnd.Models;
using Microsoft.EntityFrameworkCore;


namespace BackEnd.Services
{
    public class BorrowService : IBorrowService
    {
        private readonly ApplicationDbContext _context;

        public BorrowService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<BorrowRequestDTO> RequestBorrow(long userId, long bookId)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                throw new Exception("User not found");
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

            // Check if user already has a pending request for this book
            var existingRequest = await _context.BorrowRequests
                .FirstOrDefaultAsync(br => br.UserId == userId &&
                                         br.BookId == bookId &&
                                         br.Status == "Pending");

            if (existingRequest != null)
            {
                throw new Exception("You already have a pending request for this book");
            }

            var request = new BorrowRequest
            {
                UserId = userId,
                BookId = bookId,
                RequestDate = DateTime.UtcNow,
                Status = "Pending"
            };

            _context.BorrowRequests.Add(request);
            await _context.SaveChangesAsync();

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
                throw new Exception("Only pending requests can be approved");
            }

            var book = request.Book;
            if (!book.Available || book.Quantity <= 0)
            {
                throw new Exception("Book is no longer available for borrowing");
            }

            request.Status = "Approved";
            _context.BorrowRequests.Update(request);

            // Reduce book quantity
            book.Quantity--;
            book.Available = book.Quantity > 0;
            _context.Books.Update(book);

            // Create borrow record
            var record = new BorrowRecord
            {
                UserId = request.UserId,
                BookId = request.BookId,
                BorrowDate = DateTime.UtcNow,
                DueDate = DateTime.UtcNow.AddDays(14), // 2 weeks loan period
                Status = "Borrowed",
                BorrowRequestId = request.Id
            };

            _context.BorrowRecords.Add(record);
            await _context.SaveChangesAsync();

            return new BorrowRequestDTO
            {
                Id = request.Id,
                UserId = request.UserId,
                Username = request.User.Username,
                BookId = request.BookId,
                BookTitle = book.Title,
                RequestDate = request.RequestDate,
                Status = request.Status
            };
        }

        public async Task<BorrowRequestDTO> RejectBorrowRequest(long requestId, long librarianId)
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

            request.Status = "Rejected";
            _context.BorrowRequests.Update(request);
            await _context.SaveChangesAsync();

            return new BorrowRequestDTO
            {
                Id = request.Id,
                UserId = request.UserId,
                Username = request.User.Username,
                BookId = request.BookId,
                BookTitle = request.Book.Title,
                RequestDate = request.RequestDate,
                Status = request.Status
            };
        }

        public async Task<BorrowRecordDTO> ReturnBook(long recordId, long librarianId)
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

            // Increase book quantity
            var book = record.Book;
            book.Quantity++;
            book.Available = true;
            _context.Books.Update(book);

            await _context.SaveChangesAsync();

            return new BorrowRecordDTO
            {
                Id = record.Id,
                UserId = record.UserId,
                Username = record.User.Username,
                BookId = record.BookId,
                BookTitle = record.Book.Title,
                BorrowDate = record.BorrowDate,
                DueDate = record.DueDate,
                ReturnDate = record.ReturnDate,
                Status = record.Status
            };
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
                    BookTitle = br.Book.Title,
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
                    BookTitle = br.Book.Title,
                    BorrowDate = br.BorrowDate,
                    DueDate = br.DueDate,
                    ReturnDate = br.ReturnDate,
                    Status = br.Status
                })
                .ToListAsync();
        }
    }
}
