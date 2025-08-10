import { useParams, Link } from "react-router-dom";
import { useState, useEffect } from "react";
import { Book } from "../types/book";
import axios from "axios";
import BorrowRequestDialog from "../components/Book/BorrowRequestDialog";
import { Pause, Play, X } from "lucide-react";

axios.defaults.baseURL =
    import.meta.env.VITE_API_BASE_URL || "http://localhost:5205";

export const BookDetail = () => {
    const { id } = useParams();
    const [book, setBook] = useState<Book | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [showBorrowDialog, setShowBorrowDialog] = useState(false);
    const [isSpeaking, setIsSpeaking] = useState(false);
    const [isPaused, setIsPaused] = useState(false);

    const fetchBook = async () => {
        try {
            const response = await axios.get(`/api/Books/${id}`);
            setBook(response.data);
            setError(null); // Clear any previous errors
        } catch (err) {
            console.error("Error fetching book:", err);
            const errorMessage =
                axios.isAxiosError(err) && err.response?.data?.message
                    ? err.response.data.message
                    : "Failed to fetch book details. Please try again later.";
            setError(errorMessage);
        }
    };

    const listenToDescription = () => {
        if (book?.description) {
            const utterance = new SpeechSynthesisUtterance(book.description);
            utterance.lang = "en-US"; // Set the language
            utterance.rate = 1; // Set the speed of speech (1 is normal)
            utterance.pitch = 1; // Set the pitch of the voice
            
            const voices = speechSynthesis.getVoices();
            const selectedVoice = voices.find(voice => voice.lang === "en-US") || voices[0];
            if (selectedVoice) {
                utterance.voice = selectedVoice;
            }

            // Set the state to true when speech starts
            utterance.onstart = () => setIsSpeaking(true);
            
            // Set the state to false when speech ends
            utterance.onend = () => setIsSpeaking(false);
            
            console.log(utterance)
            speechSynthesis.speak(utterance);
        } else {
            console.error("No description available to read.");
        }
    };

    const togglePauseDescription = () => {
        if (speechSynthesis.speaking) {
            if (speechSynthesis.paused) {
                speechSynthesis.resume(); // Resume if currently paused
                setIsPaused(false);
            } else {
                speechSynthesis.pause(); // Pause if currently speaking
                setIsPaused(true);
            }
        }
    };

    const stopDescription = () => {
        if (speechSynthesis.speaking) {
            speechSynthesis.cancel();
            setIsSpeaking(false); // Reset state when speech is stopped
        }
    };

    useEffect(() => {
        fetchBook();
    }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

    if (error) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-50">
                <div className="text-center p-8 bg-white rounded-xl shadow-lg max-w-lg w-full">
                    <div className="mx-auto text-red-500 text-4xl mb-4">⚠️</div>
                    <h2 className="text-2xl font-bold text-red-500 mb-2">
                        Error
                    </h2>
                    <p className="text-red-500 text-lg">{error}</p>
                    <Link
                        to="/explore"
                        className="mt-6 inline-flex items-center text-blue-600 hover:text-blue-800"
                    >
                        ← Back to Books
                    </Link>
                </div>
            </div>
        );
    }

    if (!book) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-50">
                <div className="text-center p-8 bg-white rounded-xl shadow-lg max-w-lg w-full">
                    <div className="animate-pulse flex flex-col items-center">
                        <div className="rounded-lg bg-gray-200 h-64 w-48 mb-4"></div>
                        <div className="h-6 bg-gray-200 rounded w-3/4 mb-4"></div>
                        <div className="h-4 bg-gray-200 rounded w-1/2 mb-2"></div>
                        <div className="h-4 bg-gray-200 rounded w-1/3"></div>
                    </div>
                    <p className="text-gray-600 text-lg mt-6">
                        Loading book details...
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 py-12 px-4 sm:px-6 lg:px-8">
            <div className="max-w-7xl mx-auto">
                {/* Back button */}
                <Link
                    to="/explore"
                    className="inline-flex items-center text-blue-600 hover:text-blue-800 mb-6 transition-colors"
                >
                    ← Back to Books
                </Link>

                {/* Main content */}
                <div className="bg-white rounded-2xl shadow-xl overflow-hidden">
                    {/* Hero section with book cover as background */}
                    <div className="relative h-64 sm:h-80 bg-blue-900 overflow-hidden">
                        {book.coverImage && (
                            <div
                                className="absolute inset-0 opacity-20 blur-sm"
                                style={{
                                    backgroundImage: `url(data:${book.coverImageContentType};base64,${book.coverImage})`,
                                    backgroundSize: "cover",
                                    backgroundPosition: "center",
                                }}
                            />
                        )}
                        <div className="absolute inset-0 bg-gradient-to-r from-blue-900 via-blue-800 to-transparent opacity-80"></div>

                        {/* Book availability badge */}
                        <div className="absolute top-6 right-6">
                            <div
                                className={`px-4 py-2 rounded-full font-medium text-sm ${
                                    book.available
                                        ? "bg-green-100 text-green-800 border border-green-200"
                                        : "bg-red-100 text-red-800 border border-red-200"
                                }`}
                            >
                                {book.available ? "Available" : "Unavailable"}
                            </div>
                        </div>

                        {/* Book title and author */}
                        <div className="absolute bottom-0 left-0 p-6 sm:p-8 w-full">
                            <h1 className="text-3xl sm:text-4xl font-bold text-white mb-2 line-clamp-2">
                                {book.title}
                            </h1>
                            <h2 className="text-xl text-blue-100">
                                by {book.author}
                            </h2>
                        </div>
                    </div>

                    {/* Book details */}
                    <div className="grid grid-cols-1 lg:grid-cols-[350px_1fr] gap-8 p-6 sm:p-8">
                        {/* Left column with cover image */}
                        <div className="mx-auto lg:mx-0 w-full max-w-xs">
                            <div className="relative aspect-[2/3] rounded-xl overflow-hidden shadow-lg border border-gray-200">
                                <img
                                    src={
                                        book.coverImage
                                            ? `data:${book.coverImageContentType};base64,${book.coverImage}`
                                            : "/default-book-cover.jpg"
                                    }
                                    alt={book.title}
                                    className="w-full h-full object-cover"
                                />
                            </div>

                            {/* Borrow button */}
                            <button
                                className={`w-full mt-6 px-6 py-4 rounded-xl font-medium text-lg transition-all transform hover:scale-105 ${
                                    book.available
                                        ? "bg-secondary hover:bg-zinc-950 transition duration-300 text-white shadow-lg hover:shadow-xl"
                                        : "bg-gray-300 cursor-not-allowed text-gray-600"
                                }`}
                                disabled={!book.available}
                                onClick={() => setShowBorrowDialog(true)}
                            >
                                {book.available
                                    ? "Borrow Now"
                                    : "Currently Unavailable"}
                            </button>

                            {/* Quantity indicator */}
                            <div className="mt-4 text-center text-gray-500">
                                {book.quantity > 0 ? (
                                    <p>
                                        {book.quantity}{" "}
                                        {book.quantity === 1
                                            ? "copy"
                                            : "copies"}{" "}
                                        available
                                    </p>
                                ) : (
                                    <p>Out of stock</p>
                                )}
                            </div>
                        </div>

                        {/* Right column with book details */}
                        <div className="px-6">
                            {/* Book metadata */}
                            <div className="grid grid-cols-1 md:grid-cols-1 gap-4">
                                {book.isbn && (
                                    <div className="flex items-start">
                                        <div className="text-blue-500 mt-1 mr-3 font-bold">
                                            📕
                                        </div>
                                        <div>
                                            <h3 className="text-sm font-medium text-gray-500">
                                                ISBN
                                            </h3>
                                            <p className="text-gray-800">
                                                {book.isbn}
                                            </p>
                                        </div>
                                    </div>
                                )}

                                {book.publishedDate && (
                                    <div className="flex items-start">
                                        <div className="text-blue-500 mt-1 mr-3 font-bold">
                                            📅
                                        </div>
                                        <div>
                                            <h3 className="text-sm font-medium text-gray-500">
                                                Published
                                            </h3>
                                            <p className="text-gray-800">
                                                {new Date(
                                                    book.publishedDate
                                                ).toLocaleDateString("en-US", {
                                                    year: "numeric",
                                                    month: "long",
                                                    day: "numeric",
                                                })}
                                            </p>
                                        </div>
                                    </div>
                                )}

                                <div className="flex items-start">
                                    <div className="text-blue-500 mt-1 mr-3 font-bold">
                                        ✍️
                                    </div>
                                    <div>
                                        <h3 className="text-sm font-medium text-gray-500">
                                            Author
                                        </h3>
                                        <p className="text-gray-800">
                                            {book.author}
                                        </p>
                                    </div>
                                </div>

                                <div className="flex items-start">
                                    <div className="text-blue-500 mt-1 mr-3 font-bold">
                                        📚
                                    </div>
                                    <div>
                                        <h3 className="text-sm font-medium text-gray-500">
                                            Status
                                        </h3>
                                        <p className="text-gray-800">
                                            {book.available
                                                ? "Available for borrowing"
                                                : "Currently unavailable"}
                                        </p>
                                    </div>
                                </div>
                            </div>

                            {/* Description */}
                            {book.description && (
                                <div className="mt-8">
                                    <div className="flex justify-between items-center px-5 mb-3">
                                        <h3 className="text-lg font-semibold text-gray-800">
                                            Description
                                        </h3>
                                        <div>
                                            {!isSpeaking && (
                                                <button
                                                    className="bg-secondary hover:bg-zinc-950 transition duration-300 px-4 py-2 rounded text-white"
                                                    onClick={
                                                        listenToDescription
                                                    }
                                                >
                                                    Listen to description
                                                </button>
                                            )}
                                            {isSpeaking && (
                                                <>
                                                    <button
                                                        className="bg-yellow-500 hover:bg-yellow-600 transition duration-300 px-4 py-2 rounded text-white ml-2"
                                                        onClick={
                                                            togglePauseDescription
                                                        }
                                                    >
                                                        {isPaused ? <Play /> : <Pause />}
                                                    </button>
                                                    <button
                                                        className="bg-red-500 hover:bg-red-600 transition duration-300 px-4 py-2 rounded text-white ml-2"
                                                        onClick={
                                                            stopDescription
                                                        }
                                                    >
                                                        <X />
                                                    </button>
                                                </>
                                            )}
                                        </div>
                                    </div>
                                    <div className="bg-gray-50 p-5 rounded-xl border border-gray-100">
                                        <p className="text-gray-700 leading-relaxed">
                                            {book.description}
                                        </p>
                                    </div>
                                </div>
                            )}

                            {/* Additional details can be added here */}
                        </div>
                    </div>
                </div>
            </div>

            {/* Borrow dialog */}
            {showBorrowDialog && (
                <BorrowRequestDialog
                    bookId={book.id}
                    bookTitle={book.title}
                    isOpen={showBorrowDialog}
                    onClose={() => setShowBorrowDialog(false)}
                    onSuccess={() => {
                        setShowBorrowDialog(false);
                        // Refresh book data after successful borrow request
                        fetchBook();
                    }}
                />
            )}
        </div>
    );
};
