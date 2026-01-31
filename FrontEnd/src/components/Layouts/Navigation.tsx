import { Link, useLocation } from "react-router-dom";
import { useState, useEffect } from "react";
import { useAuth } from "../../hooks/useAuth";

export const Navigation = () => {
  const location = useLocation();
  const { user, isAuthenticated, logout } = useAuth();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);

  // Handle scroll effect
  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Close menu when route changes
  useEffect(() => {
    setIsMenuOpen(false);
  }, [location]);

  const navLinks = [
    { to: "/", label: "Home" },
    { to: "/explore", label: "Explore Books" },
    { to: "/plans", label: "Our Plans" },
  ];

  // Add role-specific links
  if (user?.role === "Admin") {
    navLinks.push({ to: "/admin", label: "Admin Dashboard" });
  } else if (user?.role === "Librarian") {
    navLinks.push({ to: "/librarian", label: "Librarian Dashboard" });
  }

  // Optional: Adjust links based on requirements
  // The user wants to "see everything", so maybe we don't hide Explore Books for Admins anymore?
  // Let's keep them visible for everyone now as per request "make the user see everything"

  return (
    <nav
      className={`z-50 text-white sm:h-28 h-20 flex flex-col justify-center transition-all duration-300 ${isScrolled ? "bg-primary shadow-lg" : "bg-primary"
        }`}
    >
      <div className="h-full flex flex-col items-center justify-center w-full px-4 sm:px-6 lg:px-8">
        <div className="relative w-full h-full flex items-center justify-between md:justify-around text-xl">
          {/* Logo */}
          <Link
            to="/"
            className="flex h-full items-center gap-3 text-xl md:text-2xl transition-colors z-10 text-white hover:text-white font-poppins"
          >
            <div className="aspect-square h-24 relative flex items-center justify-center">
              <img
                src="/Image/aalm-alkutub-logo.png"
                alt="logo"
                className="h-full w-full object-contain"
              />
            </div>
          </Link>

          {/* Navigation Links */}
          <div
            className={`
              ${isMenuOpen ? "flex" : "hidden md:flex"} 
              absolute md:static top-28 md:top-20 left-0 right-0 bg-white md:bg-transparent shadow-lg md:shadow-none`}
          >
            <div className="flex flex-col md:flex-row items-center gap-4 md:gap-8 p-4 md:p-0 w-full md:w-auto">
              {navLinks.map((link) => (
                <Link
                  key={link.to}
                  to={link.to}
                  className={`text-gray-800 md:text-white hover:text-blue-600 md:hover:text-gray-300 font-poppins transition-colors py-2 md:py-0 ${location.pathname === link.to
                      ? "text-blue-600 md:text-white"
                      : ""
                    }`}
                >
                  {link.label}
                </Link>
              ))}
              {isAuthenticated && user ? (
                <div className="flex flex-col md:flex-row items-center gap-4 w-full md:w-auto">
                  <Link
                    to={`/auth/user/${user.id}`}
                    className="w-full md:w-auto px-6 py-2 bg-gradient-to-r from-emerald-600 to-teal-500 text-white rounded-full shadow-lg hover:shadow-xl hover:text-white hover:from-teal-500 hover:to-emerald-400 transition-all duration-300 text-center"
                  >
                    {user.username}
                  </Link>
                  <button
                    onClick={logout}
                    className="w-full md:w-auto px-6 py-2 bg-transparent border border-white text-white rounded-full shadow-lg hover:shadow-xl hover:bg-white hover:text-[#2c3e50] transition-all duration-300 text-center"
                  >
                    Logout
                  </button>
                </div>
              ) : (
                <Link
                  to="/auth/login"
                  className="w-full md:w-auto px-6 py-2 bg-gradient-to-r from-emerald-600 to-teal-500 text-white rounded-full shadow-lg hover:shadow-xl hover:from-teal-500 hover:text-white hover:to-emerald-400 transition-all duration-300 text-center"
                >
                  Login
                </Link>
              )}
            </div>
          </div>

          {/* Mobile menu button */}
          <button
            className="md:hidden p-2 rounded-lg bg-primary text-2xl text-white transition-colors z-10"
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            aria-label="Toggle menu"
          >
            {isMenuOpen ? "✖" : "☰"}
          </button>
        </div>
      </div>
    </nav>
  );
};
