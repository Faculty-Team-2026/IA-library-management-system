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
    <div className="p-4 md:p-8 xl:p-12 2xl:p-16 max-w-[1800px] mx-auto min-h-screen">
      <div className="mb-12">
        <h1 className="text-4xl md:text-5xl lg:text-6xl font-poppins font-bold text-[#2c3e50] text-center mb-8 tracking-tight">
          Explore Our Collection
        </h1>
        <div className="flex flex-col md:flex-row gap-4 justify-center mb-10">
          <div className="relative max-w-2xl w-full group">
            <input
              type="text"
              placeholder="Search by title or author..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="px-8 py-4 bg-white border-2 border-gray-100 rounded-full text-[#2c3e50] focus:outline-none focus:ring-4 focus:ring-blue-100 focus:border-blue-500 shadow-lg hover:shadow-xl transition-all duration-300 w-full placeholder-gray-400 text-lg"
            />
            <div className="absolute right-6 top-1/2 -translate-y-1/2 text-gray-400 group-focus-within:text-blue-500 transition-colors">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="text-center py-20">
          <div className="inline-block animate-spin rounded-full h-16 w-16 border-t-4 border-b-4 border-blue-600"></div>
          <p className="mt-6 text-xl text-gray-600 font-medium">Loading our library...</p>
        </div>
      ) : error ? (
        <div className="text-center py-20 bg-red-50 rounded-3xl border border-red-100 max-w-2xl mx-auto">
          <p className="text-red-600 text-xl font-semibold mb-6">{error}</p>
          <button
            onClick={() => window.location.reload()}
            className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3 rounded-xl shadow-lg transition-transform hover:scale-105 active:scale-95 font-bold"
          >
            Try Again
          </button>
        </div>
      ) : filteredBooks.length === 0 ? (
        <div className="text-center py-20 bg-gray-50 rounded-3xl border-2 border-dashed border-gray-200">
          <p className="text-gray-500 text-xl italic">No books found matching "{searchTerm}"</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5 3xl:grid-cols-6 gap-8 justify-items-center">
          {filteredBooks.map((book) => (
            <BookCard key={book.id} book={book} onBorrowSuccess={fetchBooks} />
          ))}
        </div>
      )}
    </div>
  );
};
