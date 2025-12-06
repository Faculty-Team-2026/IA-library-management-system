import { useEffect, useMemo } from "react";
import { useNavigate } from "react-router-dom";

interface UseAuthResult {
  isAuthenticated: boolean;
  userRole: string | null;
  userId: string | null;
}

/**
 * Hook to check user authentication and role
 * Can be used in components to verify access
 */
export const useAuth = (): UseAuthResult => {
  const token = localStorage.getItem("token");
  const userRole = localStorage.getItem("userRole");
  const userId = localStorage.getItem("userId");

  return {
    isAuthenticated: !!token,
    userRole,
    userId,
  };
};

/**
 * Hook to require authentication
 * Redirects to login if user is not authenticated
 */
export const useRequireAuth = () => {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();

  useEffect(() => {
    if (!isAuthenticated) {
      navigate("/auth/login", { replace: true });
    }
  }, [isAuthenticated, navigate]);

  return isAuthenticated;
};

/**
 * Hook to require specific role
 * Redirects to home if user doesn't have required role
 */
export const useRequireRole = (requiredRole: string | string[]) => {
  const navigate = useNavigate();
  const { userRole, isAuthenticated } = useAuth();
  const allowedRoles = useMemo(
    () => (Array.isArray(requiredRole) ? requiredRole : [requiredRole]),
    [requiredRole]
  );

  useEffect(() => {
    if (!isAuthenticated) {
      navigate("/auth/login", { replace: true });
    } else if (!userRole || !allowedRoles.includes(userRole)) {
      navigate("/", { replace: true });
    }
  }, [userRole, isAuthenticated, navigate, allowedRoles]);

  return isAuthenticated && userRole && allowedRoles.includes(userRole);
};
