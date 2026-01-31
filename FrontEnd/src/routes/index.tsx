import { createBrowserRouter } from "react-router-dom";
import { Home } from "../Pages/Home";
import { BookDetail } from "../Pages/BookDetail";
import Login from "../Pages/auth/Login";
import { ExploreBooks } from "../Pages/ExploreBooks";
import { Services } from "../Pages/Plans";
import RootLayout from "../Pages/Layout";
import AuthLayout from "../components/Layouts/Layout";
import AdminDashboard from "../Pages/AdminDashboard";
import { Librarian } from "../Pages/Librarian";
import UserProfile from "../Pages/UserProfile";
import Register from "../Pages/auth/Register";
import ChatePage from "../Pages/ChatePage";
import ProtectedRoute from "../components/ProtectedRoute";

/**
 * ErrorFallback component to catch and display route errors
 */
const ErrorFallback = () => {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-8 bg-gray-50 text-center">
      <div className="max-w-md w-full p-6 bg-white rounded-xl shadow-lg border border-red-100">
        <h2 className="text-2xl font-bold text-red-600 mb-4">Something went wrong</h2>
        <p className="text-gray-600 mb-6">
          We encountered an unexpected error. Please try refreshing the page or return to the home page.
        </p>
        <div className="flex flex-col gap-4">
          <button
            onClick={() => window.location.reload()}
            className="w-full px-6 py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 transition-colors"
          >
            Refresh Page
          </button>
          <a
            href="/"
            className="w-full px-6 py-3 bg-gray-200 text-gray-800 rounded-lg font-semibold hover:bg-gray-300 transition-colors"
          >
            Back to Home
          </a>
        </div>
      </div>
    </div>
  );
};

const router = createBrowserRouter(
  [
    {
      path: "/",
      element: <RootLayout />,
      errorElement: <ErrorFallback />,
      children: [
        { path: "/", element: <Home /> },
        { path: "/explore", element: <ExploreBooks /> },
        { path: "/book/:id", element: <BookDetail /> },
        { path: "/plans", element: <Services /> },
        {
          path: "/admin",
          element: (
            <ProtectedRoute requiredRole="Admin">
              <AdminDashboard />
            </ProtectedRoute>
          ),
          errorElement: <ErrorFallback />,
        },
        {
          path: "/librarian",
          element: (
            <ProtectedRoute requiredRole="Librarian">
              <Librarian />
            </ProtectedRoute>
          ),
        },
        {
          path: "/chat",
          element: (
            <ProtectedRoute>
              <ChatePage />
            </ProtectedRoute>
          ),
        },
      ],
    },
    {
      path: "/auth",
      element: <AuthLayout />,
      errorElement: <ErrorFallback />,
      children: [
        { path: "login", element: <Login /> },
        { path: "register", element: <Register /> },
        {
          path: "user/:id",
          element: (
            <ProtectedRoute>
              <UserProfile />
            </ProtectedRoute>
          ),
        },
      ],
    },
  ]
);

export { router };
