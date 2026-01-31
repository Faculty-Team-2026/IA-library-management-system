import { useEffect, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthContext } from "../context/AuthContext";

interface UseAuthResult {
  isAuthenticated: boolean;
  userRole: string | null;
  userId: string | null;
  user: any;
  isLoading: boolean;
  logout: () => void;
}

/**
 * Hook to check user authentication and role
 * Can be used in components to verify access
 */
export const useAuth = (): UseAuthResult => {
  const { isAuthenticated, user, isLoading, logout } = useAuthContext();

  return {
    isAuthenticated,
    userRole: user?.role || null,
    userId: user?.id || null,
    user,
    isLoading,
    logout
  };
};

/**
 * Hook to require authentication
 * Redirects to login if user is not authenticated
 */
export const useRequireAuth = () => {
  const navigate = useNavigate();
  const { isAuthenticated, isLoading } = useAuth();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      navigate("/auth/login", { replace: true });
    }
  }, [isAuthenticated, isLoading, navigate]);

  return isAuthenticated;
};

/**
 * Hook to require specific role
 * Redirects to home if user doesn't have required role
 */
export const useRequireRole = (requiredRole: string | string[]) => {
  const navigate = useNavigate();
  const { userRole, isAuthenticated, isLoading } = useAuth();
  const allowedRoles = useMemo(
    () => (Array.isArray(requiredRole) ? requiredRole : [requiredRole]),
    [requiredRole]
  );

  useEffect(() => {
    if (isLoading) return;

    if (!isAuthenticated) {
      navigate("/auth/login", { replace: true });
    } else if (!userRole || !allowedRoles.includes(userRole)) {
      navigate("/", { replace: true });
    }
  }, [userRole, isAuthenticated, isLoading, navigate, allowedRoles]);

  return isAuthenticated && userRole && allowedRoles.includes(userRole);
};
