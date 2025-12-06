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

}
