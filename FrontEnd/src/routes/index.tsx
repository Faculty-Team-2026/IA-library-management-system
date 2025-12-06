import React from "react";
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

// Optional: Simple error fallback
const ErrorFallback = () => {
  // Clear any stale data and redirect to login
  React.useEffect(() => {
    const timer = setTimeout(() => {
      window.location.href = "/auth/login";
    }, 1000);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div style={{ padding: "2rem", color: "red" }}>
      <h2>Redirecting to login...</h2>
      <p>Please wait.</p>
    </div>
  );
};

export const router = createBrowserRouter([
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
]);
