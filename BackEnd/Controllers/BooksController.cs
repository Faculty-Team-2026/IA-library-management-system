// Controllers/BooksController.cs
using BackEnd.DTOs;
using BackEnd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// Controllers/BooksController.cs


namespace BackEnd.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class BooksController : ControllerBase
    {
        private readonly IBookService _bookService;

        public BooksController(IBookService bookService)
        {
            _bookService = bookService ?? throw new ArgumentNullException(nameof(bookService));
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
                var book = await _bookService.AddBook(bookDTO);
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
                var book = await _bookService.UpdateBook(id, bookDTO);
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
                var result = await _bookService.DeleteBook(id);
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
