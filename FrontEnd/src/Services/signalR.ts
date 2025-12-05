import * as signalR from "@microsoft/signalr";

export interface ChatHistoryMessage {
  user: string;
  message: string;
  timestamp: string;
}

export let connection: signalR.HubConnection | null = null;

export function startConnection(
  onReceiveMessage: (msg: ChatHistoryMessage) => void,
  onReceiveHistory: (msgs: ChatHistoryMessage[]) => void
) {
  if (connection?.state === signalR.HubConnectionState.Connected) {
    console.log("Connection already exists and is connected");
    return Promise.resolve();
  }

  // Detect if running through ngrok
  const isNgrok = typeof window !== 'undefined' && window.location.hostname.includes('ngrok');
  const API_BASE = isNgrok ? "" : "http://localhost:5205";
  
  connection = new signalR.HubConnectionBuilder()
    .withUrl(`${API_BASE}/chathub`, {
      skipNegotiation: false,
      transport: signalR.HttpTransportType.WebSockets | signalR.HttpTransportType.LongPolling,
      withCredentials: false,
      headers: {
        "ngrok-skip-browser-warning": "true"
      }
    })
    .withAutomaticReconnect([0, 2000, 5000, 10000, 20000])
    .configureLogging(signalR.LogLevel.Debug)
    .build();

  connection.onclose((error) => {
    console.error("SignalR Connection Closed:", error);
  });

  connection.onreconnecting((error) => {
    console.warn("SignalR Reconnecting:", error);
  });

  connection.onreconnected((connectionId) => {
    console.log("SignalR Reconnected:", connectionId);
    if (connection) {
      connection.invoke("GetChatHistory");
    }
  });

  connection.on(
    "ReceiveMessage",
    (user: string, message: string, timestamp: string) => {
      onReceiveMessage({ 
        user: user,
        message: message,
        timestamp: timestamp
      });
    }
  );

  connection.on("ReceiveChatHistory", (messages: ChatHistoryMessage[]) => {
    onReceiveHistory(messages);
  });

  connection.on("Error", (error: string) => {
    console.error("SignalR Error:", error);
  });

  return connection.start()
    .then(() => {
      console.log("SignalR Connected Successfully");
      if (connection) {
        return connection.invoke("GetChatHistory");
      }
    })
    .catch((err) => {
      console.error("SignalR Connection Error:", err);
      throw err;
    });
}

export function sendMessage(userId: number, message: string) {
  if (connection?.state === signalR.HubConnectionState.Connected) {
    return connection.invoke("SendMessageToAll", userId, message);
  } else {
    console.error("Cannot send message: Connection is not in Connected state");
    return Promise.reject("Connection is not in Connected state");
  }
}

export function stopConnection() {
  if (connection) {
    connection.stop();
    connection = null;
  }
}
