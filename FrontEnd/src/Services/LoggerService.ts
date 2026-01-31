// Service to capture and store API logs only (security logging)

interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  source: string;
}

class LoggerService {
  private logs: LogEntry[] = [];
  private maxLogs = 1000;
  private originalFetch: typeof fetch;

  constructor() {
    this.originalFetch = window.fetch.bind(window);
    this.initializeApiLogging();
  }

  /**
   * Initialize API logging by intercepting fetch requests
   */
  private initializeApiLogging() {
    window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const method = init?.method || "GET";
      const startTime = Date.now();

      // Skip logging for log sync requests to avoid infinite loop
      const isLogSyncRequest = url.toLowerCase().includes("/logs") || url.toLowerCase().includes("/api/logs");

      try {
        const response = await this.originalFetch(input, init);
        const duration = Date.now() - startTime;

        // Only log non-log-sync API calls
        if (!isLogSyncRequest) {
          this.addLog(
            response.ok ? "info" : "error",
            `${method} ${url} - ${response.status} (${duration}ms)`,
            "API"
          );
        }

        return response;
      } catch (error) {
        const duration = Date.now() - startTime;
        if (!isLogSyncRequest) {
          this.addLog(
            "error",
            `${method} ${url} - FAILED: ${error} (${duration}ms)`,
            "API"
          );
        }
        throw error;
      }
    };
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

    // Store in sessionStorage for persistence
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
    sessionStorage.removeItem("systemLogs");
  }

  /**
   * Persist logs to sessionStorage
   */
  private persistLogs() {
    try {
      sessionStorage.setItem("systemLogs", JSON.stringify(this.logs));
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

      const token = sessionStorage.getItem("token");
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
            // Use originalFetch to avoid logging the log sync requests
            const response = await this.originalFetch(`${apiBase}/logs`, {
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
