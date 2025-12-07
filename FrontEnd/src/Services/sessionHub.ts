import {
  HubConnection,
  HubConnectionBuilder,
  HubConnectionState,
  HttpTransportType,
  LogLevel,
} from "@microsoft/signalr";

let sessionConnection: HubConnection | null = null;

const isNgrok = typeof window !== "undefined" && window.location.hostname.includes("ngrok");
// For ngrok, Vite proxy forwards `/sessionhub` to backend, so use relative path
const HUB_BASE = isNgrok ? "" : "http://localhost:5205";

export function startSessionHub(onForceLogout: () => void) {
  if (sessionConnection?.state === HubConnectionState.Connected) {
    return Promise.resolve();
  }

  sessionConnection = new HubConnectionBuilder()
    .withUrl(`${HUB_BASE}/sessionhub`, {
      accessTokenFactory: () => sessionStorage.getItem("token") || "",
      transport: HttpTransportType.WebSockets | HttpTransportType.LongPolling,
      withCredentials: false,
      headers: {
        "ngrok-skip-browser-warning": "true",
      },
    })
    .withAutomaticReconnect([0, 2000, 5000, 10000, 20000])
    .configureLogging(LogLevel.Information)
    .build();

  sessionConnection.onclose((error) => {
    if (error) {
      console.warn("SessionHub connection closed", error);
    }
  });

  sessionConnection.on("ForceLogout", () => {
    const username = sessionStorage.getItem("username") || "unknown";
    console.log(`[2025-12-07] Force logout: ${username}`);
    onForceLogout();
  });

  return sessionConnection.start().catch((err) => {
    console.error("SessionHub connection error", err);
    throw err;
  });
}

export function stopSessionHub() {
  if (sessionConnection) {
    sessionConnection.stop();
    sessionConnection = null;
  }
}
