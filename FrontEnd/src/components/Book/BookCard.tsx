import { useNavigate, useLocation } from "react-router-dom";
import { useState } from "react";
import { Book } from "../../types/book";
import BorrowRequestDialog from "./BorrowRequestDialog";
import { useAuth } from "../../hooks/useAuth";

interface BookCardProps {
  book: Book;
  onBorrowSuccess?: () => void;
}

export const BookCard = ({ book, onBorrowSuccess }: BookCardProps) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated } = useAuth();
  const [isBorrowDialogOpen, setIsBorrowDialogOpen] = useState(false);

  const handleLearnMore = () => {
    navigate(`/book/${book.id}`);
  };

  const handleBorrowClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!isAuthenticated) {
      navigate(`/auth/login?redirect=${encodeURIComponent(location.pathname)}`);
      return;
    }
    setIsBorrowDialogOpen(true);
  };

  return (
    <>
      <div className="w-72 h-[400px] bg-white rounded-xl shadow-md hover:shadow-lg transition-all duration-200 hover:-translate-y-1 flex flex-col">
        {/* Image Section */}
        <div className="h-48 w-full overflow-hidden rounded-t-xl bg-gray-100">
          <img
            src={
              book.coverImage
                ? `data:${book.coverImageContentType};base64,${book.coverImage}`
                : "/default-book-cover.jpg"
            }
            alt={`Cover of ${book.title}`}
            className="w-full h-full object-cover"
          />
        </div>

        {/* Content Section */}
        <div className="p-4 flex flex-col flex-1">
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-gray-800 mb-2 line-clamp-2">
              {book.title}
            </h3>
            <p className="text-gray-600 mb-2 text-sm line-clamp-1">
              By {book.author}
            </p>
            {book.isbn && (
              <p className="text-gray-500 text-xs mb-2">ISBN: {book.isbn}</p>
            )}
            <div className="flex items-center gap-2 mb-2">
              <span
                className={`px-3 py-1 rounded-full text-xs font-medium ${book.available && book.quantity > 0
                  ? "bg-emerald-100 text-emerald-800"
                  : "bg-red-100 text-red-800"
                  }`}
              >
                {book.available && book.quantity > 0
                  ? "Available"
                  : "Unavailable"}
              </span>
              <span className="text-gray-600 text-xs">
                ({book.quantity} copies)
              </span>
            </div>
          </div>

          {/* Button Section - Always at bottom */}
          <div className="flex gap-2 mt-auto">
            <button
              className="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200"
              onClick={handleLearnMore}
            >
              Learn More
            </button>
            {/* Show Borrow button if available */}
            {book.available && book.quantity > 0 && (
              <button
                className={`flex-1 ${isAuthenticated ? "bg-emerald-600 hover:bg-emerald-700" : "bg-amber-600 hover:bg-amber-700"
                  } text-white font-medium py-2 px-2 rounded-lg transition-colors duration-200 text-sm`}
                onClick={handleBorrowClick}
              >
                {isAuthenticated ? "Borrow" : "Login to Borrow"}
              </button>
            )}
          </div>
        </div>
      </div>

      <BorrowRequestDialog
        bookId={book.id}
        bookTitle={book.title}
        isOpen={isBorrowDialogOpen}
        onClose={() => setIsBorrowDialogOpen(false)}
        onSuccess={() => {
          // Refresh the book list and update the UI
          setIsBorrowDialogOpen(false);
          if (onBorrowSuccess) {
            onBorrowSuccess();
          }
        }}
      />
    </>
  );
};
