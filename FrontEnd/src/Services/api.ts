import axios from "axios";

// ============================================================================
// API CONFIGURATION
// ============================================================================

// Auto-detect environment
const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
const isLocalIP = /^192\.168\./.test(window.location.hostname) || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(window.location.hostname) || /^10\./.test(window.location.hostname);
const isNgrok = window.location.hostname.includes('ngrok');

// When on ngrok, use /api-proxy which Vite will proxy to localhost:5205
// When on localhost/local IP, use direct connection
const API_BASE_URL = isNgrok
  ? "/api"  // ngrok: Use Vite proxy to backend
  : "http://localhost:5205/api";  // PC/Local Network: Direct connection

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
    "ngrok-skip-browser-warning": "true",
  },
});

// Add request interceptor to include JWT token in headers
api.interceptors.request.use(
  (config) => {
    const token = sessionStorage.getItem("token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add response interceptor to handle errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Handle 401 Unauthorized - redirect to login
    if (error.response?.status === 401) {
      clearAllAuth();
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Clear all authentication data from sessionStorage
 */
const clearAllAuth = () => {
  sessionStorage.removeItem("token");
  sessionStorage.removeItem("userRole");
  sessionStorage.removeItem("userId");
  sessionStorage.removeItem("username");
  sessionStorage.removeItem("email");
  sessionStorage.removeItem("ssoProvider");
};

/**
 * Store regular authentication data in sessionStorage
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const storeAuth = (response: Record<string, any>) => {
  sessionStorage.setItem("token", response.token);
  sessionStorage.setItem("userRole", response.role);
  sessionStorage.setItem("userId", response.id?.toString() || "");
  sessionStorage.setItem("username", response.username);
};

/**
 * Store SSO authentication data in sessionStorage
 */
const storeSSOAuth = (ssoResponse: SSOResponse) => {
  sessionStorage.setItem("token", ssoResponse.token);
  sessionStorage.setItem("userRole", ssoResponse.role);
  sessionStorage.setItem("userId", ssoResponse.id.toString());
  sessionStorage.setItem("username", ssoResponse.username);
  sessionStorage.setItem("email", ssoResponse.email);
  sessionStorage.setItem("ssoProvider", ssoResponse.ssoProvider);
};

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

interface SSOResponse {
  token: string;
  username: string;
  role: string;
  id: number;
  email: string;
  ssoProvider: string;
}

interface LoginCredentials {
  username: string;
  password: string;
}

interface RegisterData {
  username: string;
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
}

// ============================================================================
// TRADITIONAL AUTHENTICATION ENDPOINTS
// ============================================================================

export const authService = {
  /**
   * Login with username and password
   */
  login: async (credentials: LoginCredentials) => {
    try {
      const response = await api.post("/Auth/login", credentials);
      storeAuth(response.data);
      return response.data;
    } catch (error) {
      throw new Error("Login failed");
    }
  },

  /**
   * Register a new user
   */
  register: async (userData: RegisterData) => {
    try {
      const response = await api.post("/Auth/register", userData);
      return response.data;
    } catch (error) {
      throw new Error("Registration failed");
    }
  },

  /**
   * Logout user
   */
  logout: () => {
    clearAllAuth();
    window.location.href = "/login";
  },
};

// ============================================================================
// SSO (SINGLE SIGN-ON) ENDPOINTS
// ============================================================================

export const ssoService = {
  /**
   * Handle Google SSO Login
   */
  googleLogin: async (
    googleToken: string,
    firstName: string = "Google",
    lastName: string = "User",
    email: string = "user@gmail.com"
  ): Promise<SSOResponse> => {
    try {
      const response = await api.post("/sso/google", {
        googleToken,
        firstName,
        lastName,
        email,
      });
      storeSSOAuth(response.data);
      return response.data;
    } catch (error) {
      throw new Error("Google login failed");
    }
  },

  /**
   * Handle GitHub SSO Login
   */
  githubLogin: async (
    githubToken: string,
    githubUsername: string,
    firstName: string = "GitHub",
    lastName: string = "User",
    email: string = "user@github.com"
  ): Promise<SSOResponse> => {
    try {
      const response = await api.post("/sso/github", {
        githubToken,
        githubUsername,
        firstName,
        lastName,
        email,
      });
      storeSSOAuth(response.data);
      return response.data;
    } catch (error) {
      throw new Error("GitHub login failed");
    }
  },

  /**
   * Handle Microsoft SSO Login
   */
  microsoftLogin: async (
    microsoftToken: string,
    firstName: string = "Microsoft",
    lastName: string = "User",
    email: string = "user@outlook.com"
  ): Promise<SSOResponse> => {
    try {
      const response = await api.post("/sso/microsoft", {
        microsoftToken,
        firstName,
        lastName,
        email,
      });
      storeSSOAuth(response.data);
      return response.data;
    } catch (error) {
      throw new Error("Microsoft login failed");
    }
  },

  /**
   * Check if user is logged in via SSO
   */
  isSSOLogin: (): boolean => {
    return !!sessionStorage.getItem("ssoProvider");
  },

  /**
   * Get SSO provider name
   */
  getSSOProvider: (): string | null => {
    return sessionStorage.getItem("ssoProvider");
  },

  /**
   * Clear SSO data on logout
   */
  clearSSOAuth: () => {
    clearAllAuth();
  },
};

// ============================================================================
// BOOKS ENDPOINTS
// ============================================================================

export const bookService = {
  /**
   * Get all books
   */
  getAllBooks: async () => {
    try {
      const response = await api.get("/Books");
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch books");
    }
  },

  /**
   * Get book by ID
   */
  getBook: async (id: number) => {
    try {
      const response = await api.get(`/Books/${id}`);
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch book");
    }
  },

  /**
   * Create a new book
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  createBook: async (bookData: Record<string, any>) => {
    try {
      const response = await api.post("/Books", bookData);
      return response.data;
    } catch (error) {
      throw new Error("Failed to create book");
    }
  },

  /**
   * Update a book
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  updateBook: async (id: number, bookData: Record<string, any>) => {
    try {
      const response = await api.put(`/Books/${id}`, bookData);
      return response.data;
    } catch (error) {
      throw new Error("Failed to update book");
    }
  },

  /**
   * Delete a book
   */
  deleteBook: async (id: number) => {
    try {
      await api.delete(`/Books/${id}`);
      return { success: true };
    } catch (error) {
      throw new Error("Failed to delete book");
    }
  },
};

// ============================================================================
// BORROW ENDPOINTS
// ============================================================================

export const borrowService = {
  /**
   * Get all borrow records
   */
  getAllRecords: async () => {
    try {
      const response = await api.get("/Borrow");
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch borrow records");
    }
  },

  /**
   * Get borrow record by ID
   */
  getRecord: async (id: number) => {
    try {
      const response = await api.get(`/Borrow/${id}`);
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch borrow record");
    }
  },

  /**
   * Create a borrow request
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  requestBorrow: async (borrowData: Record<string, any>) => {
    try {
      const response = await api.post("/Borrow/request", borrowData);
      return response.data;
    } catch (error) {
      throw new Error("Failed to create borrow request");
    }
  },

  /**
   * Return a book
   */
  returnBook: async (borrowId: number) => {
    try {
      const response = await api.post(`/Borrow/return/${borrowId}`);
      return response.data;
    } catch (error) {
      throw new Error("Failed to return book");
    }
  },

  /**
   * Get borrow requests by status
   */
  getRequestsByStatus: async (status: string) => {
    try {
      const response = await api.get(`/Borrow/requests?status=${status}`);
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch borrow requests");
    }
  },
};

// ============================================================================
// USERS ENDPOINTS
// ============================================================================

export const userService = {
  /**
   * Get all users
   */
  getAllUsers: async () => {
    try {
      const response = await api.get("/Users");
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch users");
    }
  },

  /**
   * Get user by ID
   */
  getUser: async (id: number) => {
    try {
      const response = await api.get(`/Users/${id}`);
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch user");
    }
  },

  /**
   * Update user profile
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  updateUser: async (id: number, userData: Record<string, any>) => {
    try {
      const response = await api.put(`/Users/${id}`, userData);
      return response.data;
    } catch (error) {
      throw new Error("Failed to update user");
    }
  },

  /**
   * Delete a user
   */
  deleteUser: async (id: number) => {
    try {
      await api.delete(`/Users/${id}`);
      return { success: true };
    } catch (error) {
      throw new Error("Failed to delete user");
    }
  },
};

// ============================================================================
// MEMBERSHIP ENDPOINTS
// ============================================================================

export const membershipService = {
  /**
   * Get all memberships
   */
  getAllMemberships: async () => {
    try {
      const response = await api.get("/Membership");
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch memberships");
    }
  },

  /**
   * Get membership by ID
   */
  getMembership: async (id: number) => {
    try {
      const response = await api.get(`/Membership/${id}`);
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch membership");
    }
  },

  /**
   * Create a membership
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  createMembership: async (membershipData: Record<string, any>) => {
    try {
      const response = await api.post("/Membership", membershipData);
      return response.data;
    } catch (error) {
      throw new Error("Failed to create membership");
    }
  },

  /**
   * Update membership
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  updateMembership: async (id: number, membershipData: Record<string, any>) => {
    try {
      const response = await api.put(`/Membership/${id}`, membershipData);
      return response.data;
    } catch (error) {
      throw new Error("Failed to update membership");
    }
  },

  /**
   * Delete membership
   */
  deleteMembership: async (id: number) => {
    try {
      await api.delete(`/Membership/${id}`);
      return { success: true };
    } catch (error) {
      throw new Error("Failed to delete membership");
    }
  },
};

// ============================================================================
// LOCATION ENDPOINTS
// ============================================================================

export const locationService = {
  /**
   * Get all locations
   */
  getAllLocations: async () => {
    try {
      const response = await api.get("/Location");
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch locations");
    }
  },

  /**
   * Get location by ID
   */
  getLocation: async (id: number) => {
    try {
      const response = await api.get(`/Location/${id}`);
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch location");
    }
  },

  /**
   * Create a location
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  createLocation: async (locationData: Record<string, any>) => {
    try {
      const response = await api.post("/Location", locationData);
      return response.data;
    } catch (error) {
      throw new Error("Failed to create location");
    }
  },

  /**
   * Update location
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  updateLocation: async (id: number, locationData: Record<string, any>) => {
    try {
      const response = await api.put(`/Location/${id}`, locationData);
      return response.data;
    } catch (error) {
      throw new Error("Failed to update location");
    }
  },

  /**
   * Delete location
   */
  deleteLocation: async (id: number) => {
    try {
      await api.delete(`/Location/${id}`);
      return { success: true };
    } catch (error) {
      throw new Error("Failed to delete location");
    }
  },
};

// ============================================================================
// LIBRARIAN ENDPOINTS
// ============================================================================

export const librarianService = {
  /**
   * Get all librarians
   */
  getAllLibrarians: async () => {
    try {
      const response = await api.get("/Librarian");
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch librarians");
    }
  },

  /**
   * Get librarian by ID
   */
  getLibrarian: async (id: number) => {
    try {
      const response = await api.get(`/Librarian/${id}`);
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch librarian");
    }
  },

  /**
   * Approve librarian request
   */
  approveRequest: async (requestId: number) => {
    try {
      const response = await api.post(`/Librarian/approve/${requestId}`);
      return response.data;
    } catch (error) {
      throw new Error("Failed to approve librarian request");
    }
  },

  /**
   * Reject librarian request
   */
  rejectRequest: async (requestId: number) => {
    try {
      const response = await api.post(`/Librarian/reject/${requestId}`);
      return response.data;
    } catch (error) {
      throw new Error("Failed to reject librarian request");
    }
  },
};

// ============================================================================
// EXPORTS
// ============================================================================

export default api;
