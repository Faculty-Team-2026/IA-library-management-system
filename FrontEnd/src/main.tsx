import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router-dom";
import "./index.css";
import { router } from "./routes";
import "./Services/LoggerService"; // Initialize logger service to capture all console logs
import loggerService from "./Services/LoggerService";
import { startSessionHub } from "./Services/sessionHub";

// Send logs to backend every 30 seconds
setInterval(() => {
  loggerService.sendLogsToBackend().catch((error) => {
    console.warn("Failed to sync logs to backend:", error);
  });
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
    window.location.href = "/login";
  });
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>
);
