using Azure.Core;
using BackEnd.Data;
using BackEnd.DTOs;
using BackEnd.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace BackEnd.Services
{
    public class BookService : IBookService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<BookService> _logger;

        public BookService(ApplicationDbContext context, ILogger<BookService> logger)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<IEnumerable<BookDTO>> GetAllBooks()
        {
            return await _context.Books
                .Select(b => new BookDTO
                {
                    Id = b.Id,
                    Title = b.Title,
                    Author = b.Author,
                    ISBN = b.ISBN,
                    PublishedDate = b.PublishedDate,
                    Available = b.Available,
                    Quantity = b.Quantity,
                    Description = b.Description,
                    CoverImage = b.CoverImage != null ? Convert.ToBase64String(b.CoverImage) : null,
                    CoverImageContentType = b.CoverImageContentType
                })
                .ToListAsync();
        }

        public async Task<BookDTO> GetBookById(long id)
        {
            var book = await _context.Books.FindAsync(id);
            if (book == null)
            {
                throw new Exception("Book not found");
            }

            return new BookDTO
            {
                Id = book.Id,
                Title = book.Title,
                Author = book.Author,
                ISBN = book.ISBN,
                PublishedDate = book.PublishedDate,
                Available = book.Available,
                Quantity = book.Quantity,
                Description = book.Description,
                CoverImage = book.CoverImage != null ? Convert.ToBase64String(book.CoverImage) : null,
                CoverImageContentType = book.CoverImageContentType
            };
        }

        public async Task<BookDTO> AddBook(CreateBookDTO bookDTO)
        {
            try
            {
                var contentType = bookDTO.CoverImageFile?.ContentType;

                if (await _context.Books.AnyAsync(b => b.ISBN == bookDTO.ISBN))
                {
                    throw new Exception("A book with this ISBN already exists");
                }

                var book = new Book
                {                Title = bookDTO.Title,
                    Author = bookDTO.Author,
                    ISBN = bookDTO.ISBN,
                    PublishedDate = bookDTO.PublishedDate,
                    Available = bookDTO.Quantity > 0,
                    Quantity = bookDTO.Quantity,
                    Description = bookDTO.Description
                };

                // Handle image upload
                if (bookDTO.CoverImageFile != null && bookDTO.CoverImageFile.Length > 0)
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        await bookDTO.CoverImageFile.CopyToAsync(memoryStream);
                        book.CoverImage = memoryStream.ToArray();
                        book.CoverImageContentType = bookDTO.CoverImageFile.ContentType;
                    }
                }

                _context.Books.Add(book);
                await _context.SaveChangesAsync();

                _logger.LogInformation($"Book added: {book.Title} | ISBN: {book.ISBN} | Quantity: {book.Quantity}");

                return new BookDTO
                {
                    Id = book.Id,
                Title = book.Title,
                Author = book.Author,
                ISBN = book.ISBN,
                PublishedDate = book.PublishedDate,
                Available = book.Available,
                Quantity = book.Quantity,
                Description = book.Description,
                CoverImage = book.CoverImage != null ? Convert.ToBase64String(book.CoverImage) : null,
                CoverImageContentType = book.CoverImageContentType
            };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Book error: Failed to add book | ISBN: {bookDTO.ISBN}");
                throw;
            }
        }

        public async Task<BookDTO> UpdateBook(long id, CreateBookDTO bookDTO)
        {
            try
            {
                var book = await _context.Books.FindAsync(id);
                if (book == null)
                {
                    throw new Exception("Book not found");
                }

                if (book.ISBN != bookDTO.ISBN && await _context.Books.AnyAsync(b => b.ISBN == bookDTO.ISBN))
                {
                    throw new Exception("A book with this ISBN already exists");
                }            book.Title = bookDTO.Title;
                book.Author = bookDTO.Author;
                book.ISBN = bookDTO.ISBN;
                book.PublishedDate = bookDTO.PublishedDate;
                book.Quantity = bookDTO.Quantity;
                book.Available = bookDTO.Quantity > 0;
                book.Description = bookDTO.Description;

                // Update image if new one is provided
                if (bookDTO.CoverImageFile != null && bookDTO.CoverImageFile.Length > 0)
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        await bookDTO.CoverImageFile.CopyToAsync(memoryStream);
                        book.CoverImage = memoryStream.ToArray();
                        book.CoverImageContentType = bookDTO.CoverImageFile.ContentType;
                    }
                }

                _context.Books.Update(book);
                await _context.SaveChangesAsync();

                _logger.LogInformation($"Book updated: {book.Title} | ISBN: {book.ISBN} | ID: {id}");

                return new BookDTO
                {
                    Id = book.Id,
                    Title = book.Title,
                    Author = book.Author,
                    ISBN = book.ISBN,
                    PublishedDate = book.PublishedDate,
                    Available = book.Available,
                    Quantity = book.Quantity,
                    Description = book.Description,
                    CoverImage = book.CoverImage != null ? Convert.ToBase64String(book.CoverImage) : null,
                    CoverImageContentType = book.CoverImageContentType
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Book error: Failed to update book | ID: {id}");
                throw;
            }
        }

        public async Task<bool> DeleteBook(long id)
        {
            try
            {
                var book = await _context.Books.FindAsync(id);
                if (book == null)
                {
                    throw new Exception("Book not found");
                }

                _context.Books.Remove(book);
                await _context.SaveChangesAsync();

                _logger.LogInformation($"Book deleted: {book.Title} | ISBN: {book.ISBN} | ID: {id}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Book error: Failed to delete book | ID: {id}");
                throw;
            }
        }

        public async Task<IEnumerable<BookDTO>> SearchBooks(string searchTerm)
        {
            return await _context.Books                .Where(b => (b.Title ?? "").Contains(searchTerm) ||
                           (b.Author ?? "").Contains(searchTerm) ||
                           (b.ISBN ?? "").Contains(searchTerm))
                .Select(b => new BookDTO
                {
                    Id = b.Id,
                    Title = b.Title,
                    Author = b.Author,
                    ISBN = b.ISBN,
                    PublishedDate = b.PublishedDate,
                    Available = b.Available,
                    Quantity = b.Quantity,
                    Description = b.Description,
                    CoverImage = b.CoverImage != null ? Convert.ToBase64String(b.CoverImage) : null,
                    CoverImageContentType = b.CoverImageContentType
                })
                .ToListAsync();
        }
    }
}