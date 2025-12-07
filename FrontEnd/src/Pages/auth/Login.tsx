import LoginForm from "./LoginForm";
import VideoBackground from "../../components/Layouts/VideoBackground";
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";

const Login = () => {
    const navigate = useNavigate();

    useEffect(() => {
        // Check localStorage for remember me feature
        const rememberMe = localStorage.getItem("rememberMe");
        if (rememberMe === "true") {
            const role = localStorage.getItem("userRole");
            if (role === "Admin") {
                navigate("/admin"); // Redirect admin to their dashboard
            } else if (role === "Librarian") {
                navigate("/librarian"); // Redirect librarian to their dashboard
            } else if (role === "User") {
                navigate("/"); // Redirect user to the landing page
            }
        }
    }, [navigate]);

    return (
        <div className="relative min-h-screen w-full overflow-hidden">
            <VideoBackground />
            <LoginForm />
        </div>
    );
};

export default Login;