import React, { useState } from "react";
import { Link, useNavigate, useLocation, useSearchParams } from "react-router-dom";
import { Eye, EyeOff } from "lucide-react";
import { GoogleLogin, GoogleOAuthProvider } from "@react-oauth/google";
import { jwtDecode } from "jwt-decode";
import Checkbox from "../../components/UI/Checkbox";
import InputField from "../../components/UI/InputField";
import Button from "../../components/UI/Button";
import api from "../../Services/api";
import { useAuthContext } from "../../context/AuthContext";
import {
  containsXssRisk,
  isValidUsername,
  sanitizeInput,
} from "../../utils/validation";

const LoginForm = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { login } = useAuthContext();
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    username: "",
    password: "",
    rememberMe: false,
  });

  const redirectParam = searchParams.get("redirect");
  const from = location.state?.from?.pathname || redirectParam || "/";

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    const sanitizedValue = sanitizeInput(value, {
      maxLength: name === "password" ? 128 : 64,
      trim: true,
    });
    setFormData({
      ...formData,
      [name]: sanitizedValue,
    });
  };

  const handleCheckboxChange = (checked: boolean) => {
    setFormData({
      ...formData,
      rememberMe: checked,
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    const cleanedUsername = sanitizeInput(formData.username, {
      maxLength: 64,
    });
    const cleanedPassword = sanitizeInput(formData.password, {
      maxLength: 128,
      trim: false,
    });

    if (!cleanedUsername || !isValidUsername(cleanedUsername)) {
      setError("Enter a valid username (3-32 letters/numbers/._-)");
      setLoading(false);
      return;
    }

    if (!cleanedPassword) {
      setError("Password is required");
      setLoading(false);
      return;
    }

    if (containsXssRisk(cleanedUsername) || containsXssRisk(cleanedPassword)) {
      setError("Input contains disallowed characters.");
      setLoading(false);
      return;
    }

    try {
      const response = await api.post("/Auth/login", {
        username: cleanedUsername,
        password: cleanedPassword,
      });

      const authData = response.data;

      if (formData.rememberMe) {
        localStorage.setItem("rememberMe", "true");
      } else {
        localStorage.removeItem("rememberMe");
      }

      login(authData);

      // Logical redirection
      const hasExplicitRedirect = searchParams.get("redirect") !== null || location.state?.from;

      if (!hasExplicitRedirect && authData.role === "Admin") {
        navigate("/admin", { replace: true });
      } else if (!hasExplicitRedirect && authData.role === "Librarian") {
        navigate("/librarian", { replace: true });
      } else {
        navigate(from, { replace: true });
      }
    } catch (err: unknown) {
      const error = err as Error;
      setError(error.message || "Login failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const handleGoogleLogin = async (credentialResponse: any) => {
    try {
      setError("");
      setLoading(true);

      const decoded: any = jwtDecode(credentialResponse.credential);
      const { email, name, family_name } = decoded;

      const firstName = name ? name.split(" ")[0] : "User";
      const lastName = family_name || "SSO";

      const response = await api.post("/sso/google", {
        googleToken: credentialResponse.credential,
        firstName,
        lastName,
        email,
      });

      login(response.data);

      const hasExplicitRedirect = searchParams.get("redirect") !== null || location.state?.from;

      if (!hasExplicitRedirect && response.data.role === "Admin") {
        navigate("/admin", { replace: true });
      } else if (!hasExplicitRedirect && response.data.role === "Librarian") {
        navigate("/librarian", { replace: true });
      } else {
        navigate(from, { replace: true });
      }
    } catch (err: unknown) {
      const error = err as Error;
      setError("Google login failed: " + error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen px-4 sm:px-6 lg:px-8 relative z-10">
      <div className="w-full max-w-md space-y-8 bg-white/95 backdrop-blur-sm p-8 rounded-xl shadow-xl">
        <h2 className="font-poppins text-3xl font-bold text-gray-700">
          Sign In
        </h2>

        {error && (
          <div
            className="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded relative"
            role="alert"
          >
            <span className="block sm:inline">{error}</span>
          </div>
        )}

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="space-y-5">
            <div>
              <label
                htmlFor="username"
                className="block text-sm font-medium text-gray-600 mb-2"
              >
                Username
              </label>
              <InputField
                name="username"
                type="text"
                required
                className="appearance-none relative block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                value={formData.username}
                onChange={handleInputChange}
              />
            </div>

            <div>
              <div className="flex justify-between items-center mb-2">
                <label
                  htmlFor="password"
                  className="block text-sm font-medium text-gray-600"
                >
                  Password
                </label>
                <div
                  className="text-sm cursor-pointer text-gray-500 flex items-center"
                  onClick={togglePasswordVisibility}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  <span className="ml-1">{showPassword ? "Hide" : "Show"}</span>
                </div>
              </div>
              <div className="relative">
                <InputField
                  name="password"
                  type={showPassword ? "text" : "password"}
                  required
                  className="appearance-none relative block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  value={formData.password}
                  onChange={handleInputChange}
                />
              </div>
              <div className="text-right mt-1">
                <a
                  href="#"
                  className="underline font-bold text-sm text-gray-600 hover:text-gray-800"
                >
                  Forgot your password?
                </a>
              </div>
            </div>
          </div>

          <Button
            name={loading ? "Signing in..." : "Sign In"}
            type="submit"
            disabled={loading}
            style="group relative w-full flex justify-center p-4 border border-transparent text-md font-medium rounded-full text-white bg-gradient-to-r from-emerald-600 to-teal-500 hover:from-teal-500 hover:to-emerald-400 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          />

          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <Checkbox
                name="rememberMe"
                value={formData.rememberMe ? "on" : "off"}
                onCheckedChange={handleCheckboxChange}
              />
              <label
                htmlFor="rememberMe"
                className="block text-sm text-gray-600 ml-2"
              >
                Remember Me
              </label>
            </div>
            <div>
              <a href="#" className="text-sm text-gray-600 hover:text-gray-800">
                Need Help?
              </a>
            </div>
          </div>

          <div>
            <p className="text-center text-sm text-gray-600">
              Don't have an account?
              <Link
                to="/auth/register"
                className="ml-1 text-primary font-bold underline hover:text-gray-600"
              >
                Sign Up
              </Link>
            </p>
          </div>

          <div className="relative flex items-center justify-center mt-6">
            <hr className="w-full border-t border-gray-300" />
            <span className="absolute bg-white px-2 text-gray-500 text-sm">Or continue with Google</span>
          </div>

          {/* Google SSO Button */}
          <div className="flex justify-center mt-8">
            <GoogleOAuthProvider clientId={import.meta.env.VITE_GOOGLE_CLIENT_ID || "788186209104-n8ivk6irvgc6ibpp29k7ov0q4s0h9drq.apps.googleusercontent.com"}>
              <GoogleLogin
                onSuccess={handleGoogleLogin}
                onError={() => setError("Google login failed")}
                text="signin_with"
              />
            </GoogleOAuthProvider>
          </div>
        </form>
      </div>
    </div>
  );
};

export default LoginForm;
