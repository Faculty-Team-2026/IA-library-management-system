import { Link, useNavigate } from "react-router-dom";
import { useState, useEffect } from "react";
import { BookCard } from "../components/Book/BookCard";
import { Book } from "../types/book";
import api from "../Services/api";
import HomeMapView from "../components/maps/HomeMapView";

export const Home = () => {
  const [books, setBooks] = useState<Book[]>([]);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const token = localStorage.getItem("token");
  const userRole = localStorage.getItem("userRole");

  useEffect(() => {
    const fetchBooks = async () => {
      try {
        const response = await api.get("/Books");
        setBooks(response.data);
      } catch (error) {
        console.error("Error fetching books:", error);
        setError("Failed to fetch books. Please try again later.");
      }
    };
    fetchBooks();
  }, []);

  // Sort books alphabetically by title, with a fallback for undefined titles
  const sortedBooks = [...books].sort((a, b) =>
    (a.title || "").localeCompare(b.title || "")
  );

  return (
    <div className="w-full min-h-screen bg-gray-50">
      {/* Hero Section */}
      <section className="px-4 sm:px-10 mt-10 lg:px-60 bg-gradient-to-br w-full h-screen">
        <div className="h-screen flex lg:flex-row md:flex-col-reverse sm:flex-col-reverse flex-col-reverse items-center 2xl:justify-between sm:justify-center justify-end gap-8 mx-auto text-center lg:text-left">
          <div className="w-full lg:w-2/3 space-y-6">
            <h1 className="sm:text-6xl text-2xl lg:leading-snug lg:text-4xl 2xl:text-6xl font-halimum font-bold text-gray-800 leading-tight mb-8 lg:mb-16">
              Where Your Book Journey Begins
            </h1>
            <p className="lg:text-base text-gray-600 text-poppins text-xs">
              Step into a world of endless stories, wisdom, and imagination.{" "}
              <br className="hidden lg:block" /> Let every page be a new
              adventure.
            </p>
            <div className="flex justify-center lg:justify-start">
              <Link
                to="/explore"
                className="inline-block font-bold bg-gradient-to-r from-emerald-600 to-teal-500 text-white hover:text-white hover:from-teal-500 hover:to-emerald-400 text-white px-4 sm:px-6 lg:px-8 py-2 sm:py-3 lg:py-4 rounded-md transition-all text-sm sm:text-base lg:text-lg"
              >
                Explore Books
              </Link>
            </div>
          </div>
          <div className="md:w-full md:h-full sm:w-1/2 w-1/2 sm:h-fit md:py-14 sm:py-0 h-fit py-0 lg:w-1/3 flex justify-center items-center">
            <div className="overflow-hidden rounded-full aspect-square flex items-center justify-center shadow-lg">
              <img
                src="/Image/header-image.jpg"
                alt="logo"
                className="w-full h-full object-cover"
              />
            </div>
          </div>
        </div>
      </section>

      {/* Services Section */}
      <section>
        <div className="px-4 sm:px-10 lg:px-60 w-full bg-white flex flex-col md:flex-row text-black items-center justify-center">
          <div className="w-full lg:w-1/2 overflow-hidden">
            <img
              src="/public/Image/students-working-study-group.jpg"
              alt="Community"
              className="hover:scale-110 transition duration-700 w-full h-auto"
            />
          </div>
          <div className="w-full lg:w-1/2 flex flex-col items-center justify-center gap-8">
            <div className="flex flex-col items-center gap-3">
              <h2 className="text-3xl sm:text-4xl lg:text-5xl text-left font-poppins font-bold italic mb-8 lg:mb-14 text-primary tracking-tight drop-shadow">
                Reader's Community
              </h2>
              <hr className="w-14 h-[3px] bg-primary rounded-full" />
            </div>
            <p className="text-center w-full sm:w-3/4 font-poppins text-base sm:text-lg md:text-sm text-gray-700 leading-relaxed">
              Join our reading community and share your thoughts with fellow
              book enthusiasts. Discover new perspectives, engage in meaningful
              discussions, and connect with like-minded readers who share your
              passion for books.
            </p>
          </div>
        </div>
        <div className="px-4 sm:px-10 lg:px-60 w-full bg-white flex flex-col md:flex-row-reverse md:text-sm text-black items-center justify-center">
          <div className="w-full lg:w-1/2 overflow-hidden">
            <img
              src="/Image/crop-hand-picking-book-from-shelf.jpg"
              alt="Community"
              className="hover:scale-110 transition duration-700 w-full h-auto"
            />
          </div>
          <div className="w-full lg:w-1/2 flex flex-col items-center justify-center gap-8">
            <div className="flex flex-col items-center gap-3">
              <h2 className="text-3xl sm:text-4xl lg:text-5xl text-left font-poppins font-bold italic mb-8 lg:mb-14 text-primary tracking-tight drop-shadow">
                Book Lending
              </h2>
              <hr className="w-14 h-[3px] bg-primary rounded-full" />
            </div>
            <p className="text-center w-full sm:w-3/4 md:text-sm font-poppins text-base sm:text-lg md:text-xl text-gray-700 leading-relaxed">
              Borrow physical books from our extensive collection, carefully
              curated to include a wide range of genres, authors, and topics to
              suit every reader's taste.
            </p>
          </div>
        </div>
      </section>

      {/* Popular Books Section - Only visible to Users */}
      {userRole === "User" && (
        <section className="mt-10 px-4 sm:px-10 lg:px-60 w-full bg-white text-black">
          <div className="w-full mx-auto">
            <h2 className="text-3xl sm:text-4xl lg:text-5xl text-left font-poppins font-bold italic mb-8 lg:mb-14 text-primary tracking-tight drop-shadow">
              Popular Books
            </h2>
            {error ? (
              <p className="text-center text-red-500">{error}</p>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 sm:gap-8 lg:gap-12 justify-items-center">
                {sortedBooks.slice(0, 6).map((book) => (
                  <BookCard book={book} key={book.id} />
                ))}
              </div>
            )}
          </div>
        </section>
      )}

      {/* Join Club Section */}
      {!token && (
        <section className="px-4 sm:px-6 lg:px-8 py-8 sm:py-12 lg:py-16">
          <div className="max-w-4xl mx-auto bg-gradient-to-r from-[#2c3e50] to-[#4a6b8a] text-white rounded-xl p-6 sm:p-8 lg:p-12 text-center shadow-lg">
            <h2 className="text-2xl font-poppins sm:text-3xl lg:text-4xl font-bold mb-4 sm:mb-6">
              Join Our Reading Community Today
            </h2>
            <p className="text-base sm:text-lg mb-6 sm:mb-8 max-w-2xl mx-auto">
              Become a member and enjoy exclusive benefits and access to our
              entire collection.
            </p>
            <Link
              to="/auth/register"
              className="inline-block bg-gradient-to-r from-emerald-600 to-teal-500 text-white px-6 sm:px-8 py-2 sm:py-3 rounded-md font-semibold hover:bg-[#1abc9c] hover:text-white transition-all duration-400 text-base sm:text-lg shadow-md hover:shadow-lg hover:from-teal-500 hover:to-emerald-400"
            >
              Join Now
            </Link>
          </div>
        </section>
      )}

      {/* Library Locations Section */}
      <section className="px-4 sm:px-10 lg:px-60 py-16 bg-white">
        <div className="w-full mx-auto">
          <h2 className="text-3xl sm:text-4xl lg:text-5xl text-left font-poppins font-bold italic mb-8 lg:mb-14 text-primary tracking-tight drop-shadow">
            Find Our Libraries
          </h2>
          <div className="w-full">
            <HomeMapView />
          </div>
        </div>
      </section>

      {token && (
        <button
          onClick={() => navigate("/chat")}
          className="fixed bottom-4 sm:bottom-8 right-4 sm:right-8 z-50 bg-blue-600 hover:bg-blue-700 text-white rounded-full shadow-lg p-4 sm:p-5 flex items-center justify-center transition-all duration-300 group"
          title="Open Community Chat"
        >
          <span className="text-xl sm:text-2xl">💬</span>
          <span className="ml-2 opacity-0 sm:opacity-100 group-hover:opacity-200 transition-opacity text-sm sm:text-base font-semibold">
            Chat
          </span>
        </button>
      )}
    </div>
  );
};
