import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Eye, EyeOff } from "lucide-react";
import Checkbox from "../../components/UI/Checkbox";
import InputField from "../../components/UI/InputField";
import Button from "../../components/UI/Button";
import api from "../../Services/api";

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
      const response = await api.post("/api/Auth/login", {
        username: formData.username,
        password: formData.password,
      });

      const { token, role, id, username } = response.data;

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
      const error = err as { response?: { data?: { message?: string } } };
      setError(
        error.response?.data?.message || "Login failed. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
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
          </div>

          <Button
            type="button"
            name="Continue as a guest"
            onClick={() => navigate("/")}
            style="w-full py-6 border border-[#16a085] border-gray-300 rounded-md text-[#16a085] bg-gray-50 hover:text-white hover:bg-[#16a085] hover:border-transparent focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-[#16a085] disabled:opacity-50 disabled:cursor-not-allowed"
          />
        </form>
      </div>
    </div>
  );
};

export default LoginForm;
