using Microsoft.AspNetCore.SignalR;
using System.Threading.Tasks;

namespace BackEnd.Hubs
{
    public interface ISessionHubClient
    {
        Task ForceLogout(string userId);
    }

    public class SessionHub : Hub<ISessionHubClient>
    {
        // This method can be called by the server to send force logout to a user
    }
}
