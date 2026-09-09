using Microsoft.Extensions.Caching.Memory;
using Client_app.Models;
using Client_app.Services;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Client_app.Services
{
    public class ChatCache : IChatCache
    {
        private readonly IMemoryCache _cache;
        private readonly MemoryCacheEntryOptions _historyOptions;
        private const string HistoryKeyPrefix = "chat_history_";
        private const string OnlineStatusesKey = "online_statuses";
        private const string ConnectionCountsKey = "online_connection_counts";
        private const string ConnectionIdsKey = "online_connection_ids";
        private static readonly TimeSpan CacheDuration = TimeSpan.FromDays(30);

        public ChatCache(IMemoryCache cache)
        {
            _cache = cache;
            _historyOptions = new MemoryCacheEntryOptions()
            {
                AbsoluteExpirationRelativeToNow = CacheDuration,
                Priority = CacheItemPriority.Low
            };
        }

        public Task SaveMessageAsync(ChatMessage message)
        {
            var key = GetHistoryKey(message.SenderEmail, message.ReceiverEmail);
            var list = _cache.Get<List<ChatMessage>>(key) ?? new List<ChatMessage>();

            list.Add(message);
            var cutoff = DateTime.UtcNow.Subtract(CacheDuration);
            list = list.Where(m => GetMessageTime(m) >= cutoff).ToList();

            _cache.Set(key, list, _historyOptions);
            return Task.CompletedTask;
        }

        public Task<List<ChatMessage>> GetHistoryAsync(string user1, string user2)
        {
            var key = GetHistoryKey(user1, user2);
            var cutoff = DateTime.UtcNow.Subtract(CacheDuration);
            var history = (_cache.Get<List<ChatMessage>>(key) ?? new List<ChatMessage>())
                .Where(m => GetMessageTime(m) >= cutoff)
                .OrderBy(m => GetMessageTime(m))
                .ToList();
            return Task.FromResult(history);
        }

        public Task DeleteHistoryAsync(string user1, string user2)
        {
            _cache.Remove(GetHistoryKey(user1, user2));
            return Task.CompletedTask;
        }

        public Task UpdateOnlineStatusAsync(string email, bool isOnline, string role = "", string fullName = "", string connectionId = "")
        {
            var statuses = _cache.Get<ConcurrentDictionary<string, ChatUserStatus>>(OnlineStatusesKey)
                          ?? new ConcurrentDictionary<string, ChatUserStatus>();
            var connectionCounts = _cache.Get<ConcurrentDictionary<string, int>>(ConnectionCountsKey)
                                  ?? new ConcurrentDictionary<string, int>();
            var connectionIds = _cache.Get<ConcurrentDictionary<string, string>>(ConnectionIdsKey)
                                ?? new ConcurrentDictionary<string, string>();

            var status = new ChatUserStatus
            {
                Email = email,
                IsOnline = isOnline,
                LastSeen = DateTime.UtcNow,
                Role = role,
                FullName = fullName
            };

            if (isOnline)
            {
                if (!string.IsNullOrWhiteSpace(connectionId) && connectionIds.TryAdd(connectionId, email))
                {
                    connectionCounts.AddOrUpdate(email, 1, (_, count) => count + 1);
                }
                else if (string.IsNullOrWhiteSpace(connectionId))
                {
                    connectionCounts.AddOrUpdate(email, 1, (_, count) => count + 1);
                }

                statuses[email] = status;
            }
            else
            {
                var shouldRemove = true;
                if (!string.IsNullOrWhiteSpace(connectionId) && connectionIds.TryRemove(connectionId, out var connectedEmail))
                {
                    var emailToUpdate = connectedEmail;
                    var remaining = connectionCounts.AddOrUpdate(emailToUpdate, 0, (_, count) => Math.Max(0, count - 1));
                    shouldRemove = remaining <= 0;
                    email = emailToUpdate;
                }
                else if (connectionCounts.TryGetValue(email, out var currentCount))
                {
                    var remaining = Math.Max(0, currentCount - 1);
                    if (remaining <= 0) connectionCounts.TryRemove(email, out _);
                    else connectionCounts[email] = remaining;
                    shouldRemove = remaining <= 0;
                }

                if (shouldRemove)
                {
                    statuses.TryRemove(email, out _);
                    connectionCounts.TryRemove(email, out _);
                }
            }

            _cache.Set(OnlineStatusesKey, statuses, _historyOptions);
            _cache.Set(ConnectionCountsKey, connectionCounts, _historyOptions);
            _cache.Set(ConnectionIdsKey, connectionIds, _historyOptions);
            return Task.CompletedTask;
        }

        public Task<List<ChatUserStatus>> GetOnlineStatusesAsync()
        {
            var statuses = _cache.Get<ConcurrentDictionary<string, ChatUserStatus>>(OnlineStatusesKey);
            var onlineUsers = statuses?.Values.Where(s => s.IsOnline).ToList() ?? new List<ChatUserStatus>();
            return Task.FromResult(onlineUsers);
        }

        private static string GetHistoryKey(string u1, string u2)
        {
            var users = new[] { u1.ToLowerInvariant(), u2.ToLowerInvariant() }.OrderBy(u => u).ToArray();
            return $"{HistoryKeyPrefix}{users[0]}_{users[1]}";
        }

        private static DateTime GetMessageTime(ChatMessage message)
        {
            if (message.SentAt != default) return message.SentAt;
            if (message.Timestamp != default) return message.Timestamp;
            return DateTime.UtcNow;
        }
    }
}
