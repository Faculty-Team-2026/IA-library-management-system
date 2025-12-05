import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Eye, EyeOff } from "lucide-react";
import { GoogleLogin, GoogleOAuthProvider } from "@react-oauth/google";
import { jwtDecode } from "jwt-decode";
import Checkbox from "../../components/UI/Checkbox";
import InputField from "../../components/UI/InputField";
import Button from "../../components/UI/Button";
import * as apiServices from "../../Services/api";

// SSO Icons (simple SVG)
const GoogleIcon = () => (
  <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12.545,10.239v3.821h5.445c-0.712,2.315-2.647,3.972-5.445,3.972c-3.332,0-6.033-2.701-6.033-6.032 c0-3.331,2.701-6.032,6.033-6.032c1.498,0,2.866,0.549,3.921,1.453l2.814-2.814C17.461,2.268,15.365,1.25,12.545,1.25 c-6.343,0-11.5,5.157-11.5,11.5c0,6.343,5.157,11.5,11.5,11.5c6.343,0,11.5-5.157,11.5-11.5c0-0.828-0.084-1.628-0.241-2.388H12.545z" />
  </svg>
);

const GitHubIcon = () => (
  <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
  </svg>
);

const MicrosoftIcon = () => (
  <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
    <path d="M11.4 24H0V12.6h11.4V24zM24 24H12.6V12.6H24V24zM11.4 11.4H0V0h11.4v11.4zm12.6 0H12.6V0H24v11.4z" />
  </svg>
);

const LoginForm = () => {
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    username: "",
    password: "",
    rememberMe: false,
  });

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
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

    try {
      const isNgrok = window.location.hostname.includes('ngrok');
      const API_URL = isNgrok ? "/api" : "http://localhost:5205/api";
      
      const response = await fetch(`${API_URL}/Auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "ngrok-skip-browser-warning": "true",
        },
        body: JSON.stringify({
          username: formData.username,
          password: formData.password,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Login failed");
      }

      const { token, role, id, username } = await response.json();

      // Store authentication data
      localStorage.setItem("token", token);
      localStorage.setItem("userRole", role);
      localStorage.setItem("userId", id.toString());
      localStorage.setItem("username", username);

      // If remember me is checked, store the token in a more persistent way
      if (formData.rememberMe) {
        localStorage.setItem("rememberMe", "true");
      }

      // Redirect based on role
      if (role === "Admin") {
        navigate("/admin");
      } else if (role === "Librarian") {
        navigate("/Librarian");
      } else {
        navigate("/");
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

      // Decode the JWT token to get user info
      const decoded: any = jwtDecode(credentialResponse.credential);
      const { email, name, family_name } = decoded;

      // Extract first and last name
      const firstName = name ? name.split(" ")[0] : "User";
      const lastName = family_name || "SSO";

      // Send to backend
      // ssoService.googleLogin already stores all auth data in localStorage via storeSSOAuth
      const response = await apiServices.ssoService.googleLogin(
        credentialResponse.credential,
        firstName,
        lastName,
        email
      );

      // Redirect based on role
      if (response.role === "Admin") {
        navigate("/admin");
      } else if (response.role === "Librarian") {
        navigate("/Librarian");
      } else {
        navigate("/");
      }
    } catch (err: unknown) {
      const error = err as Error;
      setError("Google login failed: " + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleGitHubLogin = async () => {
    try {
      setError("");
      setLoading(true);
      
      // For demonstration, we'll use a mock GitHub token with an email
      // In production, use GitHub OAuth library
      const mockGitHubToken = `mock-github-user-${Date.now()}@github.com`;
      const email = `githubsso${Date.now()}@github.com`;
      
      const response = await apiServices.ssoService.githubLogin(
        mockGitHubToken,
        "githubuser",
        "GitHub",
        "User",
        email
      );
      
      // Redirect based on role
      if (response.role === "Admin") {
        navigate("/admin");
      } else if (response.role === "Librarian") {
        navigate("/Librarian");
      } else {
        navigate("/");
      }
    } catch (err: unknown) {
      const error = err as Error;
      setError("GitHub login failed: " + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleMicrosoftLogin = async () => {
    try {
      setError("");
      setLoading(true);
      
      // For demonstration, we'll use a mock Microsoft token with an email
      // In production, use @azure/msal-browser
      const mockMicrosoftToken = `mock-microsoft-user-${Date.now()}@outlook.com`;
      const email = `microsoftsso${Date.now()}@outlook.com`;
      
      const response = await apiServices.ssoService.microsoftLogin(
        mockMicrosoftToken,
        "Microsoft",
        "User",
        email
      );
      
      // Redirect based on role
      if (response.role === "Admin") {
        navigate("/admin");
      } else if (response.role === "Librarian") {
        navigate("/Librarian");
      } else {
        navigate("/");
      }
    } catch (err: unknown) {
      const error = err as Error;
      setError("Microsoft login failed: " + error.message);
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
            <GoogleOAuthProvider clientId="788186209104-n8ivk6irvgc6ibpp29k7ov0q4s0h9drq.apps.googleusercontent.com">
              <GoogleLogin
                onSuccess={handleGoogleLogin}
                onError={() => setError("Google login failed")}
                text="signin_with"
              />
            </GoogleOAuthProvider>
          </div>

          <div className="relative flex items-center justify-center mt-6">
            <hr className="w-full border-t border-gray-300" />
          </div>

          <Button
            type="button"
            name="Continue as a guest"
            onClick={() => navigate("/")}
            style="w-full py-6 bg-[#16a085] text-white rounded-md focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed"
          />
        </form>
      </div>
    </div>
  );
};

export default LoginForm;
