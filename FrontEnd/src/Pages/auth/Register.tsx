import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import InputField from "../../components/UI/InputField";
import api from "../../Services/api";
import { AxiosError } from "axios";

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

interface ApiError {
    errors: ValidationErrors;
    status: number;
    title: string;
}

const Register = () => {
    const navigate = useNavigate();
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

    useEffect(() => {
        const role = localStorage.getItem("userRole");
        if (role === "Admin") {
            navigate("/admin"); // Redirect admin to their dashboard
        } else if (role === "Librarian") {
            navigate("/librarian"); // Redirect librarian to their dashboard
        } else if (role === "User") {
            navigate("/"); // Redirect user to the landing page
        }
    }, [navigate]);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        setFormData((prev) => ({
            ...prev,
            [name]: value,
        }));
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setErrors({});
        setLoading(true);

        try {
            const response = await api.post("/api/Auth/register", {
                username: formData.username,
                password: formData.password,
                firstName: formData.firstName,
                lastName: formData.lastName,
                ssn: formData.ssn,
                phoneNumber: formData.phoneNumber,
                email: formData.email,
                role: formData.role,
            });

            if (response.data) {
                navigate("/auth/login", {
                    state: {
                        message: "Registration successful! Please sign in.",
                    },
                });
            }
        } catch (err: unknown) {
            const error = err as AxiosError<ApiError>;
            if (error.response?.data?.errors) {
                setErrors(error.response.data.errors);
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
                        placeholder="+20xxxxxxxxxx"
                        value={
                            formData.phoneNumber
                                ? `+20${formData.phoneNumber.replace(/^0/, "")}`
                                : ""
                        }
                        onChange={(e) => {
                            let value = e.target.value
                                .replace(/^\+20/, "")
                                .replace(/\D/g, "");
                            value = value.slice(0, 10);
                            setFormData((prev) => ({
                                ...prev,
                                phoneNumber: value.startsWith("0")
                                    ? value
                                    : `0${value}`,
                            }));
                        }}
                        required
                        error={errors.PhoneNumber?.[0]}
                    />

                    <InputField
                        label="National ID"
                        name="ssn"
                        type="text"
                        value={formData.ssn}
                        onChange={(e) => {
                            const newValue = e.target.value
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
