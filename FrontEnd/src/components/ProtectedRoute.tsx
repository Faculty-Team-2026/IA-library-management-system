import React from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: string | string[];
}

/**
 * ProtectedRoute component to block direct URL navigation to protected pages
 * Verifies user is logged in and has required role before allowing access
 */
const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  requiredRole,
}) => {
  const location = useLocation();
  const { isAuthenticated, userRole, isLoading } = useAuth();

  // Show nothing or a spinner while checking auth status
  if (isLoading) {
    return null; // Or a loading spinner component
  }

  // Check if user is authenticated
  if (!isAuthenticated) {
    // Redirect to login with return URL
    return <Navigate to="/auth/login" state={{ from: location }} replace />;
  }

  // Check if user has required role
  if (requiredRole) {
    const allowedRoles = Array.isArray(requiredRole)
      ? requiredRole
      : [requiredRole];

    if (!userRole || !allowedRoles.includes(userRole)) {
      // User doesn't have required role - redirect to home
      return <Navigate to="/" replace />;
    }
  }

  // User is authenticated and has required role
  return <>{children}</>;
};

export default ProtectedRoute;
