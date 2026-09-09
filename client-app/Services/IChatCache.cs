using Client_app.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Client_app.Services
{
    public interface IChatCache
    {
        Task SaveMessageAsync(ChatMessage message);
        Task<List<ChatMessage>> GetHistoryAsync(string user1, string user2);
        Task DeleteHistoryAsync(string user1, string user2);
        Task UpdateOnlineStatusAsync(string email, bool isOnline, string role = "", string fullName = "", string connectionId = "");
        Task<List<ChatUserStatus>> GetOnlineStatusesAsync();
    }
}
