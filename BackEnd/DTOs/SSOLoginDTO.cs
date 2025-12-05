namespace BackEnd.DTOs
{
    /// <summary>
    /// DTO for Google SSO login
    /// </summary>
    public class GoogleLoginDTO
    {
        public string? GoogleToken { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
    }

    /// <summary>
    /// DTO for GitHub SSO login
    /// </summary>
    public class GitHubLoginDTO
    {
        public string? GitHubToken { get; set; }
        public string? GitHubUsername { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
    }

    /// <summary>
    /// DTO for Microsoft SSO login
    /// </summary>
    public class MicrosoftLoginDTO
    {
        public string? MicrosoftToken { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
    }
}
