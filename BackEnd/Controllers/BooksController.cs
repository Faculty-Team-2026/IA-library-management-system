// Controllers/BooksController.cs
using BackEnd.DTOs;
using BackEnd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

// Controllers/BooksController.cs


namespace BackEnd.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class BooksController : ControllerBase
    {
        private readonly IBookService _bookService;
        private readonly ILoggerService _loggerService;

        public BooksController(IBookService bookService, ILoggerService loggerService)
        {
            _bookService = bookService ?? throw new ArgumentNullException(nameof(bookService));
            _loggerService = loggerService ?? throw new ArgumentNullException(nameof(loggerService));
        }

        [HttpGet]
        public async Task<IActionResult> GetAllBooks()
        {
            var books = await _bookService.GetAllBooks();
            return Ok(books);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetBookById(long id)
        {
            try
            {
                var book = await _bookService.GetBookById(id);
                return Ok(book);
            }
            catch (Exception ex)
            {
                return NotFound(new { message = ex.Message });
            }
        }

        //[Authorize(Roles = "Admin,Librarian")]
        [HttpPost]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> AddBook([FromForm] CreateBookDTO bookDTO)
        {
            try
            {
                var userIdClaim = User?.FindFirst("userId");
                var userNameClaim = User?.FindFirst(ClaimTypes.NameIdentifier) ?? User?.FindFirst(JwtRegisteredClaimNames.Sub);
                
                var book = await _bookService.AddBook(bookDTO);
                
                // Log book creation
                await _loggerService.LogAsync(
                    "info",
                    $"Book Created: {book.Title} | Author: {book.Author}",
                    "Library Management",
                    userIdClaim?.Value,
                    userNameClaim?.Value ?? "Unknown"
                );
                
                return CreatedAtAction(nameof(GetBookById), new { id = book.Id }, book);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        //[Authorize(Roles = "Admin,Librarian")]
        [HttpPut("{id}")]
        public async Task<ActionResult<BookDTO>> UpdateBook(long id, [FromForm] CreateBookDTO bookDTO)
        {
            try
            {
                var userIdClaim = User?.FindFirst("userId");
                var userNameClaim = User?.FindFirst(ClaimTypes.NameIdentifier) ?? User?.FindFirst(JwtRegisteredClaimNames.Sub);
                
                var book = await _bookService.UpdateBook(id, bookDTO);
                
                // Log book update
                await _loggerService.LogAsync(
                    "info",
                    $"Book Updated: {book.Title}",
                    "Library Management",
                    userIdClaim?.Value,
                    userNameClaim?.Value ?? "Unknown"
                );
                
                return Ok(book);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        //[Authorize(Roles = "Admin,Librarian")]
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteBook(long id)
        {
            try
            {
                var userIdClaim = User?.FindFirst("userId");
                var userNameClaim = User?.FindFirst(ClaimTypes.NameIdentifier) ?? User?.FindFirst(JwtRegisteredClaimNames.Sub);
                
                // Get book info before deletion
                var bookToDelete = await _bookService.GetBookById(id);
                
                var result = await _bookService.DeleteBook(id);
                
                // Log book deletion
                await _loggerService.LogAsync(
                    "info",
                    $"Book Deleted: {bookToDelete.Title} | Author: {bookToDelete.Author}",
                    "Library Management",
                    userIdClaim?.Value,
                    userNameClaim?.Value ?? "Unknown"
                );
                
                return Ok(new { success = result });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpGet("search")]
        public async Task<IActionResult> SearchBooks([FromQuery] string term)
        {
            try
            {
                var books = await _bookService.SearchBooks(term);
                return Ok(books);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
    }
}
