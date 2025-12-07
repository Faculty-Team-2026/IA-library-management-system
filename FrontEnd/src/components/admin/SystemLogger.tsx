import React, { useState, useEffect } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faRefresh, faDownload, faCopy, faTrash } from "@fortawesome/free-solid-svg-icons";
import api from "../../Services/api";

interface LogEntry {
  id?: number;
  timestamp: string;
  level: string;
  message: string;
  source: string;
  userId?: string;
  username?: string;
  createdAt?: string;
}

interface SystemLoggerProps {
  containerClassName?: string;
}

const SystemLogger: React.FC<SystemLoggerProps> = ({ containerClassName = "" }) => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [filteredLogs, setFilteredLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filterLevel, setFilterLevel] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [statistics, setStatistics] = useState<any>(null);

  // Fetch logs from backend API
  const fetchLogs = async () => {
    setLoading(true);
    try {
      const response = await api.get("/Logs?limit=100");
      const allLogs = response.data;
      setLogs(allLogs);
      
      // Calculate statistics
      const stats = {
        errors: allLogs.filter((l: LogEntry) => l.level === "error").length,
        warnings: allLogs.filter((l: LogEntry) => l.level === "warning").length,
        info: allLogs.filter((l: LogEntry) => l.level === "info").length,
        debug: allLogs.filter((l: LogEntry) => l.level === "debug").length,
      };
      setStatistics(stats);
      
      applyFilters(allLogs, filterLevel, searchTerm);
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.message || "Failed to fetch logs");
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = (logList: LogEntry[], level: string, search: string) => {
    let filtered = [...logList];

    if (level !== "all") {
      filtered = filtered.filter((log) => log.level === level);
    }

    if (search) {
      filtered = filtered.filter((log) =>
        log.message.toLowerCase().includes(search.toLowerCase()) ||
        log.source.toLowerCase().includes(search.toLowerCase()) ||
        log.username?.toLowerCase().includes(search.toLowerCase())
      );
    }

    setFilteredLogs(filtered.reverse());
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  useEffect(() => {
    applyFilters(logs, filterLevel, searchTerm);
  }, [filterLevel, searchTerm, logs]);

  // Auto-refresh logs every 10 seconds
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      fetchLogs();
    }, 10000);

    return () => clearInterval(interval);
  }, [autoRefresh]);

  const handleDownloadLogs = () => {
    const logsText = filteredLogs
      .map(
        (log) =>
          `[${log.timestamp}] [${log.level.toUpperCase()}] [${log.source}] ${log.message}`
      )
      .join("\n");

    const element = document.createElement("a") as HTMLAnchorElement;
    element.setAttribute(
      "href",
      "data:text/plain;charset=utf-8," + encodeURIComponent(logsText)
    );
    element.setAttribute(
      "download",
      `system-logs-${new Date().toISOString().slice(0, 10)}.txt`
    );
    element.style.display = "none";
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const handleCopyLogs = () => {
    const logsText = filteredLogs
      .map(
        (log) =>
          `[${log.timestamp}] [${log.level.toUpperCase()}] [${log.source}] ${log.message}`
      )
      .join("\n");

    navigator.clipboard.writeText(logsText);
    alert("Logs copied to clipboard!");
  };

  const handleClearLogs = async () => {
    if (window.confirm("Are you sure you want to clear all logs? This action cannot be undone.")) {
      try {
        await api.delete("/Logs");
        setLogs([]);
        setFilteredLogs([]);
        setError(null);
        setStatistics(null);
        alert("Logs cleared successfully");
      } catch (err: any) {
        setError(err.response?.data?.message || "Failed to clear logs");
      }
    }
  };

  const getLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case "error":
        return "bg-red-50 border-l-4 border-red-500 text-red-800";
      case "warning":
        return "bg-yellow-50 border-l-4 border-yellow-500 text-yellow-800";
      case "info":
        return "bg-blue-50 border-l-4 border-blue-500 text-blue-800";
      case "debug":
        return "bg-gray-50 border-l-4 border-gray-500 text-gray-800";
      default:
        return "bg-gray-50 border-l-4 border-gray-500 text-gray-800";
    }
  };

  const getLevelBadgeColor = (level: string) => {
    switch (level.toLowerCase()) {
      case "error":
        return "bg-red-100 text-red-800";
      case "warning":
        return "bg-yellow-100 text-yellow-800";
      case "info":
        return "bg-blue-100 text-blue-800";
      case "debug":
        return "bg-gray-100 text-gray-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  return (
    <div className={`w-full ${containerClassName}`}>
      <div className="bg-white rounded-xl shadow-md border p-4">
        {/* Header */}
        <div className="flex flex-col gap-3 mb-4">
          <h2 className="text-xl font-bold text-gray-800">System Logger</h2>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={fetchLogs}
              disabled={loading}
              className="flex items-center gap-2 px-3 py-1.5 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors disabled:opacity-50"
            >
              <FontAwesomeIcon icon={faRefresh} className={loading ? "animate-spin" : ""} />
              Refresh
            </button>
            <button
              onClick={handleDownloadLogs}
              className="flex items-center gap-2 px-3 py-1.5 text-sm bg-green-600 text-white rounded hover:bg-green-700 transition-colors"
            >
              <FontAwesomeIcon icon={faDownload} />
              Download
            </button>
            <button
              onClick={handleCopyLogs}
              className="flex items-center gap-2 px-3 py-1.5 text-sm bg-purple-600 text-white rounded hover:bg-purple-700 transition-colors"
            >
              <FontAwesomeIcon icon={faCopy} />
              Copy
            </button>
            <button
              onClick={handleClearLogs}
              className="flex items-center gap-2 px-3 py-1.5 text-sm bg-red-600 text-white rounded hover:bg-red-700 transition-colors"
            >
              <FontAwesomeIcon icon={faTrash} />
              Clear
            </button>
          </div>
        </div>

        {/* Controls */}
        <div className="flex flex-col gap-2 mb-3">
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="text"
              placeholder="Search..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="flex-1 min-w-[200px] px-3 py-1.5 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <select
              value={filterLevel}
              onChange={(e) => setFilterLevel(e.target.value)}
              className="px-3 py-1.5 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Levels</option>
              <option value="error">Errors</option>
              <option value="warning">Warnings</option>
              <option value="info">Info</option>
              <option value="debug">Debug</option>
            </select>
            <label className="flex items-center gap-1 px-2 py-1.5 text-sm text-gray-700 whitespace-nowrap">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="w-4 h-4 cursor-pointer"
              />
              <span>Auto Refresh</span>
            </label>
          </div>
        </div>

        {/* Error message */}
        {error && (
          <div className="mb-2 p-2 bg-red-50 border border-red-200 rounded text-red-800 text-xs">
            {error}
          </div>
        )}

        {/* Logs count */}
        <div className="mb-2 flex flex-wrap gap-3 text-xs">
          <div className="text-gray-600">
            Showing {filteredLogs.length} log entries (Total: {logs.length})
          </div>
          {statistics && (
            <>
              <div className="text-red-600 font-semibold">
                Errors: {statistics.errors}
              </div>
              <div className="text-yellow-600 font-semibold">
                Warnings: {statistics.warnings}
              </div>
              <div className="text-blue-600 font-semibold">
                Info: {statistics.info}
              </div>
            </>
          )}
        </div>

        {/* Logs container */}
        <div className="space-y-1 max-h-[400px] overflow-y-auto border border-gray-200 rounded-lg p-3 bg-gray-50">
          {loading && filteredLogs.length === 0 ? (
            <div className="flex justify-center items-center py-8">
              <span className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mr-2"></span>
              <span className="text-gray-600">Loading logs...</span>
            </div>
          ) : filteredLogs.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              No logs found matching your filters
            </div>
          ) : (
            filteredLogs.map((log, index) => (
              <div
                key={log.id || index}
                className={`p-2 rounded mb-1 ${getLevelColor(log.level)}`}
              >
                <div className="flex flex-col gap-1">
                  <div className="flex flex-wrap items-center gap-1">
                    <span
                      className={`inline-block px-1 py-0.5 rounded text-xs font-semibold ${getLevelBadgeColor(
                        log.level
                      )}`}
                    >
                      {log.level.toUpperCase()}
                    </span>
                    <span className="text-xs text-gray-500 font-mono">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                    <span className="text-xs font-semibold text-gray-700">
                      [{log.source}]
                    </span>
                    {log.username && (
                      <span className="text-xs bg-purple-100 text-purple-800 px-1 py-0.5 rounded">
                        👤 {log.username}
                      </span>
                    )}
                  </div>
                  <span className="text-xs">{log.message}</span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer info */}
        <div className="mt-2 text-xs text-gray-500 flex gap-3">
          <span>Last refreshed: {new Date().toLocaleTimeString()}</span>
          <span>Auto-refresh: {autoRefresh ? "enabled" : "disabled"}</span>
        </div>
      </div>
    </div>
  );
};

export default SystemLogger;
