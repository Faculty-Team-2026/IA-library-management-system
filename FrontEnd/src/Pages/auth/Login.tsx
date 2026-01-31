import LoginForm from "./LoginForm";
import VideoBackground from "../../components/Layouts/VideoBackground";
import { useEffect } from "react";
import { useNavigate, useLocation, useSearchParams } from "react-router-dom";
import { useAuth } from "../../hooks/useAuth";

const Login = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const [searchParams] = useSearchParams();
    const { isAuthenticated, userRole, isLoading } = useAuth();

    const redirectParam = searchParams.get("redirect");
    const from = location.state?.from?.pathname || redirectParam || "/";

    useEffect(() => {
        if (!isLoading && isAuthenticated) {
            // Priority: Explicit redirect > Role default dashboard > "/"
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

    return (
        <div className="relative min-h-screen w-full overflow-hidden">
            <VideoBackground />
            <LoginForm />
        </div>
    );
};

export default Login;