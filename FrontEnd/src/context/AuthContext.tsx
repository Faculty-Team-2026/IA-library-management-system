import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";

interface User {
  id: string;
  role: string;
  username: string;
  email?: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (authData: any) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const loadAuthData = () => {
    const storedToken = sessionStorage.getItem("token") || localStorage.getItem("token");
    const storedRole = sessionStorage.getItem("userRole") || localStorage.getItem("userRole");
    const storedId = sessionStorage.getItem("userId") || localStorage.getItem("userId");
    const storedUsername = sessionStorage.getItem("username") || localStorage.getItem("username");
    const storedEmail = sessionStorage.getItem("email") || localStorage.getItem("email");

    if (storedToken && storedRole && storedId && storedUsername) {
      setToken(storedToken);
      setUser({
        id: storedId,
        role: storedRole,
        username: storedUsername,
        email: storedEmail || undefined
      });
    } else {
      setToken(null);
      setUser(null);
    }
    setIsLoading(false);
  };

  useEffect(() => {
    loadAuthData();
    
    // Listen for storage changes (for multiple tabs)
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === "token" || e.key === "userRole") {
        loadAuthData();
      }
    };
    
    window.addEventListener("storage", handleStorageChange);
    return () => window.removeEventListener("storage", handleStorageChange);
  }, []);

  const login = (authData: any) => {
    // Determine where to store based on "remember me" (not implemented here but good to support)
    const storage = localStorage.getItem("rememberMe") === "true" ? localStorage : sessionStorage;
    
    storage.setItem("token", authData.token);
    storage.setItem("userRole", authData.role);
    storage.setItem("userId", authData.id?.toString() || "");
    storage.setItem("username", authData.username);
    if (authData.email) storage.setItem("email", authData.email);
    
    loadAuthData();
  };

  const logout = () => {
    sessionStorage.removeItem("token");
    sessionStorage.removeItem("userRole");
    sessionStorage.removeItem("userId");
    sessionStorage.removeItem("username");
    sessionStorage.removeItem("email");
    sessionStorage.removeItem("ssoProvider");
    
    localStorage.removeItem("token");
    localStorage.removeItem("userRole");
    localStorage.removeItem("userId");
    localStorage.removeItem("username");
    localStorage.removeItem("email");
    localStorage.removeItem("ssoProvider");
    
    setUser(null);
    setToken(null);
    
    window.location.href = "/auth/login";
  };

  const value = {
    user,
    token,
    isAuthenticated: !!token,
    isLoading,
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuthContext = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuthContext must be used within an AuthProvider");
  }
  return context;
};
