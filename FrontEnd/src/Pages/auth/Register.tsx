import React, { useEffect, useState } from "react";
import { Link, useNavigate, useLocation, useSearchParams } from "react-router-dom";
import InputField from "../../components/UI/InputField";
import api from "../../Services/api";
import { AxiosError } from "axios";
import { startSessionHub } from "../../Services/sessionHub";
import {
    containsXssRisk,
    isStrongPassword,
    isValidEmail,
    isValidName,
    isValidUsername,
    sanitizeInput,
} from "../../utils/validation";
import { useAuth } from "../../hooks/useAuth";

interface RegisterFormData {
    username: string;
    password: string;
    firstName: string;
    lastName: string;
    ssn: string;
    phoneNumber: string;
    email: string;
    role: string;
}

interface ValidationErrors {
    Username?: string[];
    Password?: string[];
    FirstName?: string[];
    LastName?: string[];
    SSN?: string[];
    PhoneNumber?: string[];
    Email?: string[];
}

const Register = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const [searchParams] = useSearchParams();
    const { isAuthenticated, userRole, isLoading } = useAuth();
    const [formData, setFormData] = useState<RegisterFormData>({
        username: "",
        password: "",
        firstName: "",
        lastName: "",
        ssn: "",
        phoneNumber: "",
        email: "",
        role: "User",
    });
    const [errors, setErrors] = useState<ValidationErrors>({});
    const [loading, setLoading] = useState(false);
    const [generalError, setGeneralError] = useState<string>("");
    const [successMessage, setSuccessMessage] = useState<string>("");

    const redirectParam = searchParams.get("redirect");
    const from = location.state?.from?.pathname || redirectParam || "/";

    useEffect(() => {
        if (!isLoading && isAuthenticated) {
            const hasExplicitRedirect = searchParams.get("redirect") !== null || location.state?.from;

            if (!hasExplicitRedirect && userRole === "Admin") {
                navigate("/admin", { replace: true });
            } else if (!hasExplicitRedirect && userRole === "Librarian") {
                navigate("/librarian", { replace: true });
            } else {
                navigate(from, { replace: true });
            }
        }
    }, [isAuthenticated, userRole, isLoading, navigate, from, searchParams, location.state]);

    if (isLoading) return null;

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        const maxLengthMap: Record<string, number> = {
            username: 64,
            password: 128,
            firstName: 60,
            lastName: 60,
            email: 80,
            role: 20,
        };

        const lengthLimit = maxLengthMap[name as keyof typeof maxLengthMap] ?? 120;

        const sanitizedValue = sanitizeInput(value, {
            maxLength: lengthLimit,
            trim: true,
        });

        setFormData((prev) => ({
            ...prev,
            [name]: sanitizedValue,
        }));
    };

    const runClientValidation = (data: RegisterFormData): ValidationErrors => {
        const validationErrors: ValidationErrors = {};

        const firstName = sanitizeInput(data.firstName, { maxLength: 60 });
        const lastName = sanitizeInput(data.lastName, { maxLength: 60 });
        const username = sanitizeInput(data.username, { maxLength: 64 });
        const email = sanitizeInput(data.email, { maxLength: 80 });
        const password = sanitizeInput(data.password, { maxLength: 128, trim: false });
        const ssn = data.ssn.replace(/\D/g, "").slice(0, 14);
        const phone = data.phoneNumber.replace(/\D/g, "").slice(0, 11);

        if (!isValidName(firstName) || containsXssRisk(firstName)) {
            validationErrors.FirstName = ["First name must be letters/spaces (2-60 chars) with no HTML tags."];
        }

        if (!isValidName(lastName) || containsXssRisk(lastName)) {
            validationErrors.LastName = ["Last name must be letters/spaces (2-60 chars) with no HTML tags."];
        }

        if (!isValidUsername(username) || containsXssRisk(username)) {
            validationErrors.Username = ["Username must be 3-32 chars using letters, numbers, . _ or - only."];
        }

        if (!isValidEmail(email) || containsXssRisk(email)) {
            validationErrors.Email = ["Enter a valid email address."];
        }

        if (!isStrongPassword(password) || containsXssRisk(password)) {
            validationErrors.Password = ["Password must be 8+ chars and include letters and numbers."];
        }

        if (ssn.length !== 14) {
            validationErrors.SSN = ["National ID must be exactly 14 digits."];
        }

        if (phone.length !== 11) {
            validationErrors.PhoneNumber = ["Phone number must be 11 digits."];
        }

        return validationErrors;
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setErrors({});
        setGeneralError("");
        setSuccessMessage("");
        setLoading(true);

        const clientErrors = runClientValidation(formData);
        if (Object.keys(clientErrors).length > 0) {
            setErrors(clientErrors);
            setGeneralError("Please fix the errors below before submitting.");
            setLoading(false);
            return;
        }

        const payload = {
            username: sanitizeInput(formData.username, { maxLength: 64 }),
            password: sanitizeInput(formData.password, { maxLength: 128, trim: false }),
            firstName: sanitizeInput(formData.firstName, { maxLength: 60 }),
            lastName: sanitizeInput(formData.lastName, { maxLength: 60 }),
            ssn: formData.ssn,
            phoneNumber: formData.phoneNumber && formData.phoneNumber.length === 11 ? formData.phoneNumber : "",
            email: sanitizeInput(formData.email, { maxLength: 80 }),
            role: formData.role,
        };

        try {
            const response = await api.post("/Auth/register", payload);

            if (response.data) {
                startSessionHub(() => {
                    localStorage.removeItem("token");
                    localStorage.removeItem("userRole");
                    localStorage.removeItem("userId");
                    localStorage.removeItem("username");
                    localStorage.removeItem("email");
                    localStorage.removeItem("ssoProvider");
                    window.location.href = "/login";
                }).catch((err) => {
                    console.warn("SessionHub connection error after registration:", err);
                });

                setSuccessMessage("✓ Registration successful! Redirecting to login page...");
                setTimeout(() => {
                    navigate("/auth/login", {
                        state: {
                            message: "Registration successful! Please log in with your credentials.",
                        },
                    });
                }, 2000);
            }
        } catch (err: unknown) {
            const error = err as AxiosError<any>;
            if (error.response?.data?.errors) {
                setErrors(error.response.data.errors);
                const errorMessages = Object.values(error.response.data.errors)
                    .flat()
                    .join(", ");
                setGeneralError(`Validation error: ${errorMessages}`);
            } else if (error.response?.data) {
                const errorData = error.response.data;
                const errorMsg = errorData.title || errorData.message || JSON.stringify(errorData);
                setGeneralError(`Registration failed: ${errorMsg}`);
            } else {
                setGeneralError("An error occurred during registration. Please try again.");
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex justify-center flex-1 gap-32">
            <div className="p-8 self-center">
                <div className="space-y-2 mb-5">
                    <h1 className="text-5xl font-poppins italic font-bold text-primary">
                        Welcome To Aalam Al-Kutub
                    </h1>
                    <p className="text-gray-600">
                        Already have an account?{" "}
                        <Link
                            to="/auth/login"
                            className="text-emerald-600 hover:underline"
                        >
                            Log in
                        </Link>
                    </p>
                </div>

                {generalError && (
                    <div className="mb-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded-md">
                        <p className="font-medium">❌ {generalError}</p>
                    </div>
                )}

                {successMessage && (
                    <div className="mb-4 p-4 bg-green-100 border border-green-400 text-green-700 rounded-md">
                        <p className="font-medium">{successMessage}</p>
                    </div>
                )}

                <form
                    onSubmit={handleSubmit}
                    className="space-y-6 flex flex-col"
                >
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <InputField
                            label="First Name"
                            name="firstName"
                            type="text"
                            value={formData.firstName}
                            onChange={handleChange}
                            required
                            error={errors.FirstName?.[0]}
                        />
                        <InputField
                            label="Last Name"
                            name="lastName"
                            type="text"
                            value={formData.lastName}
                            onChange={handleChange}
                            required
                            error={errors.LastName?.[0]}
                        />
                    </div>

                    <InputField
                        label="Username"
                        name="username"
                        type="text"
                        value={formData.username}
                        onChange={handleChange}
                        required
                        error={errors.Username?.[0]}
                    />

                    <InputField
                        label="Email Address"
                        name="email"
                        type="email"
                        value={formData.email}
                        onChange={handleChange}
                        required
                        error={errors.Email?.[0]}
                    />

                    <InputField
                        label="Phone Number"
                        name="phoneNumber"
                        type="tel"
                        placeholder="01001234567"
                        value={formData.phoneNumber}
                        onChange={(e) => {
                            let value = e.target.value.replace(/\D/g, "");
                            value = value.slice(0, 11);
                            setFormData((prev) => ({
                                ...prev,
                                phoneNumber: value,
                            }));
                        }}
                        required
                        error={
                            formData.phoneNumber.length > 0 &&
                                formData.phoneNumber.length !== 11
                                ? "Phone number must be 11 digits (e.g., 01001234567)"
                                : errors.PhoneNumber?.[0]
                        }
                    />

                    <InputField
                        label="National ID"
                        name="ssn"
                        type="text"
                        placeholder="12345678901234"
                        value={formData.ssn}
                        onChange={(e) => {
                            let newValue = e.target.value
                                .replace(/\D/g, "")
                                .slice(0, 14);

                            setFormData((prev) => ({
                                ...prev,
                                ssn: newValue,
                            }));
                        }}
                        required
                        error={
                            formData.ssn.length > 0 &&
                                formData.ssn.length !== 14
                                ? "National ID must be exactly 14 digits"
                                : errors.SSN?.[0]
                        }
                    />

                    <InputField
                        label="Password"
                        name="password"
                        type="password"
                        value={formData.password}
                        onChange={handleChange}
                        required
                        error={errors.Password?.[0]}
                    />

                    <div className="text-sm text-gray-600">
                        By creating an account, you agree to our{" "}
                        <Link
                            to="/terms"
                            className="text-emerald-600 hover:underline"
                        >
                            Terms of use
                        </Link>{" "}
                        and{" "}
                        <Link
                            to="/privacy"
                            className="text-emerald-600 hover:underline"
                        >
                            Privacy Policy
                        </Link>
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="w-fit px-8 bg-emerald-500 text-white rounded-full py-2.5 font-medium hover:bg-emerald-600 transition-colors disabled:bg-emerald-300"
                    >
                        {loading ? "Signing Up..." : "Sign Up"}
                    </button>
                </form>
            </div>
            <div className="w-3/12 h-screen">
                <img
                    src="/Image/books_background.jpg"
                    alt="books"
                    className="h-full object-cover object-right"
                />
            </div>
        </div>
    );
};

export default Register;
