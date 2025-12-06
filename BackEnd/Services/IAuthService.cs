using BackEnd.DTOs;

namespace BackEnd.Services
{
    public interface IAuthService
    {
        Task<AuthResponseDTO> Login(LoginDTO loginDTO, string ipAddress = "unknown");
        Task<AuthResponseDTO> Register(RegisterDTO registerDTO);
        Task<(bool success, string message)> RequestLibrarianRole(long userId, string requestMessage);
    }
}
