import React, { useState, useRef, useEffect } from "react";
import {
  startConnection,
  sendMessage,
  stopConnection,
  ChatHistoryMessage
} from "../Services/signalR";
import { containsXssRisk, sanitizeInput } from "../utils/validation";

const ChatePage: React.FC = () => {
  const [messages, setMessages] = useState<ChatHistoryMessage[]>([]);
  const [input, setInput] = useState("");
  const [isConnected, setIsConnected] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Get user info from localStorage
  const username = sanitizeInput(localStorage.getItem("username") || "", {
    maxLength: 50,
  });
  const userId = Number(localStorage.getItem("userId"));

  useEffect(() => {
    if (!username || !userId) {
      console.error("User not authenticated");
      return;
    }

    let isMounted = true;

    const setupConnection = async () => {
      try {
        await startConnection(
          // On single message
          (msg) => {
            if (isMounted) {
              setMessages((prev) => [...prev, msg]);
            }
          },
          // On history
          (msgs) => {
            if (isMounted) {
              setMessages([...msgs].reverse());
            }
          }
        );
        setIsConnected(true);
      } catch (error) {
        console.error("Failed to start connection:", error);
        setIsConnected(false);
      }
    };

    setupConnection();

    return () => {
      isMounted = false;
      stopConnection();
    };
  }, [username, userId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({
      behavior: "smooth",
      block: "nearest",
    });
  }, [messages]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    const sanitizedMessage = sanitizeInput(input, { maxLength: 500 });

    if (!sanitizedMessage || !userId || containsXssRisk(sanitizedMessage)) {
      setInput("");
      return;
    }

    try {
      await sendMessage(userId, sanitizedMessage);
      setInput("");
    } catch (error) {
      console.error("Failed to send message:", error);
    }
  };

  if (!username || !userId) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-gray-800 mb-4">Please log in to access the chat</h2>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gradient-to-br from-blue-100 to-blue-300 pt-10">
      <main className="w-full max-w-2xl flex flex-col flex-1 bg-white rounded-3xl shadow-2xl border border-blue-100 mt-12 mb-12 overflow-hidden">
        <header className="px-8 py-7 bg-gradient-to-r from-blue-700 to-blue-500 text-white rounded-t-3xl shadow flex items-center justify-between relative">
          <div className="flex items-center gap-3">
            <svg
              className="w-8 h-8 text-white drop-shadow"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M8 10h.01M12 10h.01M16 10h.01M21 12c0 4.418-4.03 8-9 8s-9-3.582-9-8 4.03-8 9-8 9 3.582 9 8z"
              />
            </svg>
            <h2 className="text-2xl font-extrabold tracking-tight drop-shadow">
              Library Chat
            </h2>
          </div>
          <span className="text-sm opacity-90 font-medium bg-blue-600/70 px-4 py-1 rounded-full shadow">
            Welcome, {username}
          </span>
          {!isConnected && (
            <div className="absolute top-0 left-0 w-full h-full bg-red-500/20 flex items-center justify-center">
              <span className="text-white font-medium">Connecting...</span>
            </div>
          )}
        </header>
        <div className="flex-1 overflow-y-auto px-8 py-8 space-y-4 bg-blue-50 max-h-[60vh] min-h-[300px]">
          {messages.length === 0 ? (
            <div className="text-center text-gray-400 italic py-12">
              No messages yet. Start the conversation!
            </div>
          ) : (
            messages.map((msg, idx) => {
              const safeUser = sanitizeInput(msg.user, { maxLength: 50 });
              const safeMessage = sanitizeInput(msg.message, {
                maxLength: 500,
                allowNewLines: true,
                trim: false,
              });

              return (
                <div
                  key={idx}
                  className={`flex flex-col max-w-xl ${
                    safeUser === username ? "ml-auto items-end" : "items-start"
                  }`}
                >
                  <span className="text-xs text-gray-500 mb-1">
                    {safeUser || "Unknown"} •{" "}
                    {new Date(msg.timestamp).toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </span>
                  <div
                    className={`px-5 py-3 rounded-2xl shadow-md text-base font-medium break-words ${
                      safeUser === username
                        ? "bg-blue-600 text-white"
                        : "bg-white text-gray-800 border border-blue-100"
                    }`}
                  >
                    <span className="whitespace-pre-wrap">{safeMessage}</span>
                  </div>
                </div>
              );
            })
          )}
          <div ref={messagesEndRef} />
        </div>
        <form
          onSubmit={handleSend}
          className="bg-white flex items-center gap-2 px-6 py-4 border-t rounded-b-3xl"
        >
          <input
            type="text"
            className="flex-1 rounded-full border border-blue-200 text-black bg-white px-5 py-3 focus:outline-none focus:ring-2 focus:ring-blue-400 caret-blue-600 text-base shadow-sm"
            placeholder="Type your message…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={!isConnected}
            autoFocus
            maxLength={500}
          />
          <button
            type="submit"
            className="bg-blue-600 hover:bg-blue-700 text-white px-7 py-3 rounded-full font-semibold transition text-base shadow-md disabled:opacity-60"
            disabled={!isConnected || !input.trim()}
          >
            Send
          </button>
        </form>
      </main>
    </div>
  );
};

export default ChatePage;
