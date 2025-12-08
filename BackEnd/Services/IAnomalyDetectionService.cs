namespace BackEnd.Services
{
    public interface IAnomalyDetectionService
    {
        Task<bool> DetectSuspiciousActivityAsync(string username, string ipAddress, string? userAgent = null);
        Task RecordLoginActivityAsync(string username, string ipAddress, DateTime loginTime);
        Task<List<string>> GetAnomalyReportAsync(string username);
    }
}
