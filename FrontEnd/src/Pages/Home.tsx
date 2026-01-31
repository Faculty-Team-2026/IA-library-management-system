import { Link, useNavigate } from "react-router-dom";
import { useState, useEffect, useMemo } from "react";
import { BookCard } from "../components/Book/BookCard";
import { Book } from "../types/book";
import api from "../Services/api";
import HomeMapView from "../components/maps/HomeMapView";
import { useAuth } from "../hooks/useAuth";

export const Home = () => {
  const [books, setBooks] = useState<Book[]>([]);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const { isAuthenticated, isLoading } = useAuth();

  useEffect(() => {
    const fetchBooks = async () => {
      try {
        const response = await api.get("/Books");
        if (Array.isArray(response.data)) {
          setBooks(response.data);
        } else {
          console.error("Home: Received non-array books data:", response.data);
          setBooks([]);
        }
      } catch (err) {
        console.error("Error fetching books:", err);
        setError("Failed to fetch books. Please try again later.");
      }
    };
    fetchBooks();
  }, []);

  // Sort books alphabetically by title
  const sortedBooks = useMemo(() => {
    return [...books].sort((a, b) => (a.title || "").localeCompare(b.title || ""));
  }, [books]);

  return (
    <div className="w-full min-h-screen bg-gray-50">
      {/* Hero Section */}
      <section className="px-4 sm:px-10 mt-10 lg:px-20 xl:px-32 2xl:px-44 bg-gradient-to-br w-full h-screen">
        <div className="max-w-[1800px] mx-auto h-screen flex lg:flex-row md:flex-col-reverse sm:flex-col-reverse flex-col-reverse items-center 2xl:justify-between sm:justify-center justify-end gap-8 text-center lg:text-left">
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
                className="inline-block font-bold bg-gradient-to-r from-emerald-600 to-teal-500 text-white hover:text-white hover:from-teal-500 hover:to-emerald-400 px-4 sm:px-6 lg:px-8 py-2 sm:py-3 lg:py-4 rounded-md transition-all text-sm sm:text-base lg:text-lg"
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
      <section className="bg-white">
        <div className="px-4 sm:px-10 lg:px-20 xl:px-32 2xl:px-44 w-full py-12">
          <div className="max-w-[1800px] mx-auto flex flex-col md:flex-row items-center justify-center gap-12">
            <div className="w-full lg:w-1/2 overflow-hidden rounded-2xl shadow-lg">
              <img
                src="/public/Image/students-working-study-group.jpg"
                alt="Community"
                className="hover:scale-110 transition duration-700 w-full h-auto"
              />
            </div>
            <div className="w-full lg:w-1/2 flex flex-col items-center lg:items-start text-center lg:text-left gap-6">
              <div className="flex flex-col items-center lg:items-start gap-3">
                <h2 className="text-3xl sm:text-4xl lg:text-5xl font-poppins font-bold italic text-primary tracking-tight">
                  Reader's Community
                </h2>
                <hr className="w-14 h-[3px] bg-primary rounded-full" />
              </div>
              <p className="font-poppins text-base sm:text-lg text-gray-700 leading-relaxed">
                Join our reading community and share your thoughts with fellow
                book enthusiasts. Discover new perspectives, engage in meaningful
                discussions, and connect with like-minded readers who share your
                passion for books.
              </p>
            </div>
          </div>
        </div>

        <div className="px-4 sm:px-10 lg:px-20 xl:px-32 2xl:px-44 w-full py-12 bg-gray-50">
          <div className="max-w-[1800px] mx-auto flex flex-col md:flex-row-reverse items-center justify-center gap-12">
            <div className="w-full lg:w-1/2 overflow-hidden rounded-2xl shadow-lg">
              <img
                src="/Image/crop-hand-picking-book-from-shelf.jpg"
                alt="Lending"
                className="hover:scale-110 transition duration-700 w-full h-auto"
              />
            </div>
            <div className="w-full lg:w-1/2 flex flex-col items-center lg:items-start text-center lg:text-left gap-6">
              <div className="flex flex-col items-center lg:items-start gap-3">
                <h2 className="text-3xl sm:text-4xl lg:text-5xl font-poppins font-bold italic text-primary tracking-tight">
                  Book Lending
                </h2>
                <hr className="w-14 h-[3px] bg-primary rounded-full" />
              </div>
              <p className="font-poppins text-base sm:text-lg text-gray-700 leading-relaxed">
                Borrow physical books from our extensive collection, carefully
                curated to include a wide range of genres, authors, and topics to
                suit every reader's taste.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Popular Books Section */}
      <section className="mt-20 px-4 sm:px-10 lg:px-20 xl:px-32 2xl:px-44 w-full text-black">
        <div className="max-w-[1800px] mx-auto">
          <h2 className="text-3xl sm:text-4xl lg:text-5xl text-left font-poppins font-bold italic mb-12 text-primary tracking-tight">
            Popular Books
          </h2>
          {error ? (
            <p className="text-center text-red-500">{error}</p>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5 gap-8 justify-items-center">
              {sortedBooks.slice(0, 10).map((book) => (
                <BookCard book={book} key={book.id} />
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Join Club Section - Only for guests */}
      {!isAuthenticated && !isLoading && (
        <section className="px-4 sm:px-10 lg:px-20 xl:px-32 2xl:px-44 py-20">
          <div className="max-w-[1200px] mx-auto bg-gradient-to-r from-[#2c3e50] to-[#4a6b8a] text-white rounded-3xl p-10 lg:p-16 text-center shadow-2xl">
            <h2 className="text-3xl sm:text-4xl lg:text-5xl font-poppins font-bold mb-6">
              Join Our Reading Community Today
            </h2>
            <p className="text-lg sm:text-xl mb-10 max-w-2xl mx-auto opacity-90">
              Become a member and enjoy exclusive benefits and access to our
              entire collection.
            </p>
            <Link
              to="/auth/register"
              className="inline-block bg-gradient-to-r from-emerald-600 to-teal-500 text-white px-10 py-4 rounded-full font-bold hover:scale-105 transition-all text-xl shadow-lg"
            >
              Join Now
            </Link>
          </div>
        </section>
      )}

      {/* Library Locations Section */}
      <section className="px-4 sm:px-10 lg:px-20 xl:px-32 2xl:px-44 py-24 bg-white">
        <div className="max-w-[1800px] mx-auto w-full">
          <h2 className="text-3xl sm:text-4xl lg:text-5xl text-left font-poppins font-bold italic mb-12 text-primary tracking-tight">
            Find Our Libraries
          </h2>
          <div className="w-full rounded-3xl overflow-hidden shadow-xl border border-gray-100">
            <HomeMapView />
          </div>
        </div>
      </section>

      {/* Chat Button - Visible to logged in users */}
      {isAuthenticated && (
        <button
          onClick={() => navigate("/chat")}
          className="fixed bottom-8 right-8 z-50 bg-blue-600 hover:bg-blue-700 text-white rounded-full shadow-2xl p-5 flex items-center justify-center transition-all duration-300 group hover:scale-110"
          title="Open Community Chat"
        >
          <span className="text-2xl">💬</span>
          <span className="ml-2 w-0 overflow-hidden group-hover:w-16 transition-all duration-300 text-lg font-bold">
            Chat
          </span>
        </button>
      )}
    </div>
  );
};
