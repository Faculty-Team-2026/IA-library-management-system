import { useState, useEffect } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faBook,
  faExchangeAlt,
  faRotateLeft,
  faCrown,
  faUserPlus
} from "@fortawesome/free-solid-svg-icons";
import BookManagement from "../components/Book/BookManagement";
import ManageMemberShip from "../components/MemberShip/ManageMemberShip";
import SeeBorrowRequest from "../components/Librarian/SeeBorrowRequst";
import SeeReturnRequest from "../components/Librarian/SeeReturnRequst";
import AcceptSubPlan from '../components/Librarian/AcceptSubPlan';

export const Librarian = () => {
  const [selected, setSelected] = useState(0);
  const [loading, setLoading] = useState(true);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [touchStartX, setTouchStartX] = useState(0);

  // Authentication checked by ProtectedRoute
  useEffect(() => {
    setLoading(false);
  }, []);

  const handleTouchStart = (e: React.TouchEvent) => {
    setTouchStartX(e.touches[0].clientX);
  };

  const handleTouchMove = (e: React.TouchEvent) => {
    if (!touchStartX) return;

    const currentX = e.touches[0].clientX;
    const diff = currentX - touchStartX;

    // Open sidebar if swiping right from left edge
    if (touchStartX < 50 && diff > 50) {
      setIsSidebarOpen(true);
    }
    // Close sidebar if swiping left
    else if (diff < -50) {
      setIsSidebarOpen(false);
    }
  };

  const handleTouchEnd = () => {
    setTouchStartX(0);
  };

  // Board configurations
  const boards = [
    {
      name: "Manage Books",
      icon: faBook,
      content: <BookManagement
        containerClassName="w-full"
        searchBarClassName="justify-center"
        tableClassName="shadow-lg border border-gray-200"
      />,
    },
    {
      name: "Borrow Requests",
      icon: faExchangeAlt,
      content: <SeeBorrowRequest />,
    },
    {
      name: "Return Requests",
      icon: faRotateLeft,
      content: <SeeReturnRequest />,
    },
    {
      name: "Manage Memberships",
      icon: faCrown,
      content: <ManageMemberShip containerClassName="w-full" />,
    },
    {
      name: "Approve Subscriptions",
      icon: faUserPlus,
      content: <AcceptSubPlan />,
    },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div
      className="relative min-h-screen flex flex-col md:flex-row bg-gray-50"
      onTouchStart={handleTouchStart}
      onTouchMove={handleTouchMove}
      onTouchEnd={handleTouchEnd}
    >
      {/* Mobile Menu Button - Sticky (hidden when sidebar is open) */}
      <div className={`md:hidden sticky top - 4 left - 4 z - 50 float - left ml - 4 transition - opacity duration - 200 ${isSidebarOpen ? 'opacity-0 pointer-events-none' : 'opacity-100'} `}>
        <button
          className="p-3 rounded-lg bg-blue-600 text-white shadow-lg hover:bg-blue-700 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-400"
          onClick={() => setIsSidebarOpen(true)}
          aria-label="Open menu"
        >
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16m-7 6h7" />
          </svg>
        </button>
      </div>

      {/* Sidebar */}
      <nav className={`
        ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'}
transition - transform duration - 200 ease - out
        fixed md: static
w - 72 z - 50
h - screen md: h - auto
top - 0 left - 0
bg - blue - 50
md: translate - x - 0
        flex flex - col
overflow - y - auto
shadow - xl
  `}>
        {/* Navigation Header with Close Button */}
        <div className="flex items-center justify-between p-4 border-b border-blue-100">
          <h2 className="text-lg font-bold text-blue-800">NAVIGATION</h2>
          <button
            className="md:hidden p-2 rounded-full bg-blue-600 text-white hover:bg-blue-700 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-400"
            onClick={() => setIsSidebarOpen(false)}
            aria-label="Close menu"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="w-full py-2 flex flex-col gap-1">
          {boards.map((board, idx) => (
            <button
              key={board.name}
              className={`w - 11 / 12 mx - auto mb - 1 p - 3 rounded - lg text - left flex items - center transition - all duration - 200 font - semibold group shadow - sm border border - transparent ${selected === idx
                  ? "bg-blue-600 text-white shadow-md border-blue-700 scale-[1.02]"
                  : "bg-white text-blue-700 hover:bg-blue-100 hover:border-blue-300 hover:scale-[1.01]"
                } `}
              onClick={() => {
                setSelected(idx);
                if (window.innerWidth < 768) { // Close sidebar on mobile after selection
                  setIsSidebarOpen(false);
                }
              }}
            >
              <FontAwesomeIcon
                className={`size - 5 mr - 3 ${selected === idx ? 'text-white' : 'text-blue-500 group-hover:text-blue-700'
                  } `}
                icon={board.icon}
              />
              {board.name}
            </button>
          ))}
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-1 p-4 md:p-6 lg:p-8 pt-16 md:pt-6 md:mt-0">
        <div className="w-full h-full bg-white rounded-xl shadow-lg overflow-hidden">
          <div className="w-full h-full">
            {boards[selected].content}
          </div>
        </div>
      </main>

      {/* Overlay */}
      {isSidebarOpen && (
        <div
          className="md:hidden fixed inset-0 bg-black transition-opacity duration-200 ease-out bg-opacity-50 z-0"
          onClick={() => setIsSidebarOpen(false)}
        />
      )}
    </div>
  );
};
