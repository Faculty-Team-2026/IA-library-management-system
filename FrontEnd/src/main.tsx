import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router-dom";
import "./index.css";
import { router } from "./routes";
import loggerService from "./Services/LoggerService";
import { startSessionHub } from "./Services/sessionHub";
import { AuthProvider } from "./context/AuthContext";

// Send API logs to backend every 30 seconds (only if logged in)
setInterval(() => {
  const token = sessionStorage.getItem("token");
  if (token) {
    loggerService.sendLogsToBackend().catch(() => {
      // Silently fail - don't spam console
    });
  }
}, 30000);

// Only start session hub if user is already logged in
const token = sessionStorage.getItem("token") || localStorage.getItem("token");
if (token) {
  startSessionHub(() => {
    // Clear both sessionStorage and localStorage on logout
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
    window.location.href = "/auth/login";
  });
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AuthProvider>
      <RouterProvider router={router} future={{ v7_startTransition: true }} />
    </AuthProvider>
  </StrictMode>
);
