import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router-dom";
import "./index.css";
import { router } from "./routes";
import "./Services/LoggerService"; // Initialize logger service to capture all console logs
import loggerService from "./Services/LoggerService";

// Send logs to backend every 30 seconds
setInterval(() => {
  loggerService.sendLogsToBackend().catch((error) => {
    console.warn("Failed to sync logs to backend:", error);
  });
}, 30000);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>
);
