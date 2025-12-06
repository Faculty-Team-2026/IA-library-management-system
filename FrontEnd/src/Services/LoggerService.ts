// Service to capture and store system logs

interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  source: string;
}

class LoggerService {
  private logs: LogEntry[] = [];
  private maxLogs = 1000;

  constructor() {
    this.initializeConsoleLogging();
  }

  /**
   * Initialize console logging interception
   */
  private initializeConsoleLogging() {
    // Store original console methods
    const originalLog = console.log;
    const originalError = console.error;
    const originalWarn = console.warn;
    const originalInfo = console.info;

    // Intercept console.log
    console.log = (...args: any[]) => {
      originalLog(...args);
      this.addLog("info", args.join(" "), "Console");
    };

    // Intercept console.error
    console.error = (...args: any[]) => {
      originalError(...args);
      this.addLog("error", args.join(" "), "Console");
    };

    // Intercept console.warn
    console.warn = (...args: any[]) => {
      originalWarn(...args);
      this.addLog("warning", args.join(" "), "Console");
    };

    // Intercept console.info
    console.info = (...args: any[]) => {
      originalInfo(...args);
      this.addLog("info", args.join(" "), "Console");
    };

    // Capture unhandled errors
    window.addEventListener("error", (event: ErrorEvent) => {
      this.addLog(
        "error",
        `${event.message} at ${event.filename}:${event.lineno}`,
        "ErrorHandler"
      );
    });

    // Capture unhandled promise rejections
    window.addEventListener("unhandledrejection", (event: PromiseRejectionEvent) => {
      this.addLog(
        "error",
        `Unhandled Promise Rejection: ${event.reason}`,
        "UnhandledRejection"
      );
    });
  }

  /**
   * Add a log entry
   */
  addLog(level: string, message: string, source: string) {
    const logEntry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      source,
    };

    this.logs.push(logEntry);

    // Keep only the last maxLogs entries
    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }

    // Store in localStorage for persistence
    this.persistLogs();
  }

  /**
   * Get all logs
   */
  getLogs(): LogEntry[] {
    return [...this.logs];
  }

  /**
   * Get logs filtered by level
   */
  getLogsByLevel(level: string): LogEntry[] {
    return this.logs.filter((log) => log.level === level);
  }

  /**
   * Get logs filtered by source
   */
  getLogsBySource(source: string): LogEntry[] {
    return this.logs.filter((log) => log.source === source);
  }

  /**
   * Search logs by message
   */
  searchLogs(query: string): LogEntry[] {
    const lowerQuery = query.toLowerCase();
    return this.logs.filter(
      (log) =>
        log.message.toLowerCase().includes(lowerQuery) ||
        log.source.toLowerCase().includes(lowerQuery)
    );
  }

  /**
   * Clear all logs
   */
  clearLogs() {
    this.logs = [];
    localStorage.removeItem("systemLogs");
  }

  /**
   * Persist logs to localStorage
   */
  private persistLogs() {
    try {
      localStorage.setItem("systemLogs", JSON.stringify(this.logs));
    } catch (error) {
      // Handle quota exceeded error
      if (
        error instanceof DOMException &&
        error.name === "QuotaExceededError"
      ) {
        // Clear half of the logs and retry
        this.logs.splice(0, Math.floor(this.logs.length / 2));
        this.persistLogs();
      }
    }
  }

  /**
   * Load logs from localStorage
   */
  loadLogsFromStorage() {
    try {
      const storedLogs = localStorage.getItem("systemLogs");
      if (storedLogs) {
        this.logs = JSON.parse(storedLogs);
      }
    } catch (error) {
      console.error("Failed to load logs from storage:", error);
    }
  }

  /**
   * Get statistics about logs
   */
  getStatistics() {
    return {
      totalLogs: this.logs.length,
      errors: this.logs.filter((log) => log.level === "error").length,
      warnings: this.logs.filter((log) => log.level === "warning").length,
      info: this.logs.filter((log) => log.level === "info").length,
      sources: [...new Set(this.logs.map((log) => log.source))],
    };
  }

  /**
   * Send logs to backend for persistent storage
   */
  async sendLogsToBackend(logEntries?: LogEntry[]): Promise<boolean> {
    try {
      const entriesToSend = logEntries || this.logs;
      if (entriesToSend.length === 0) return true;

      const token = localStorage.getItem("token");
      if (!token) {
        console.warn("No token found. Logs not sent to backend.");
        return false;
      }

      // Get API base URL (proxy via /api on ngrok)
      const isNgrok = window.location.hostname.includes("ngrok");
      const apiBase = isNgrok ? "/api" : "http://localhost:5205";

      // Send logs in batches to avoid overwhelming the backend
      const batchSize = 50;
      for (let i = 0; i < entriesToSend.length; i += batchSize) {
        const batch = entriesToSend.slice(i, i + batchSize);
        
        for (const log of batch) {
          try {
            const response = await fetch(`${apiBase}/logs`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
              },
              body: JSON.stringify({
                level: log.level,
                message: log.message,
                source: log.source,
              }),
            });

            if (!response.ok) {
              console.warn(`Failed to send log to backend: ${response.status}`);
            }
          } catch (error) {
            console.warn("Error sending log to backend:", error);
          }
        }
      }

      return true;
    } catch (error) {
      console.error("Failed to send logs to backend:", error);
      return false;
    }
  }
}

// Create singleton instance
const loggerService = new LoggerService();

// Load previous logs from storage on initialization
loggerService.loadLogsFromStorage();

export default loggerService;
