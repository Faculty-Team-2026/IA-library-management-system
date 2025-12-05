import { useState, useEffect } from "react";
import { Book } from "../types/book";
import api from "../Services/api";
import { BookCard } from "../components/Book/BookCard";

export const ExploreBooks = () => {
  const [books, setBooks] = useState<Book[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchBooks = async () => {
    try {
      setLoading(true);
      const response = await api.get("/Books");
      if (Array.isArray(response.data)) {
        setBooks(response.data);
      } else {
        console.error(
          "Expected an array of books, but received:",
          response.data
        );
        setError("Invalid data format received from server");
        setBooks([]);
      }
    } catch (error) {
      console.error("Error fetching books:", error);
      setError("Failed to fetch books. Please try again later.");
      setBooks([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBooks();
  }, []);

  const filteredBooks = books.filter(
    (book) =>
      book.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      book.author.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="p-4 md:p-8 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl md:text-4xl font-poppins font-bold text-[#2c3e50] text-center mb-6">
          Explore Our Collection
        </h1>
        <div className="flex flex-col md:flex-row gap-4 justify-center mb-6">
          <input
            type="text"
            placeholder="Search by title or author..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="px-5 py-3 border border-gray-300 rounded-full bg-white text-[#2c3e50] focus:outline-none focus:ring-2 focus:ring-[#2c3e50] focus:border-transparent shadow-sm hover:shadow-md transition-all duration-200 max-w-md w-full placeholder-gray-500"
          />
        </div>
      </div>

      {loading ? (
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
          <p className="mt-4 text-gray-600">Loading books...</p>
        </div>
      ) : error ? (
        <div className="text-center py-12">
          <p className="text-red-500">{error}</p>
          <button
            onClick={() => window.location.reload()}
            className="mt-4 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors"
          >
            Try Again
          </button>
        </div>
      ) : filteredBooks.length === 0 ? (
        <div className="text-center py-12">
          <p className="text-gray-600">No books found matching your search.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6 justify-items-center">
          {filteredBooks.map((book) => (
            <BookCard key={book.id} book={book} onBorrowSuccess={fetchBooks} />
          ))}
        </div>
      )}
    </div>
  );
};
