import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import * as signalR from '@microsoft/signalr';
import { getChatHubUrl } from '../../services/api';
import { getAuthToken } from '../../services/authSession';
import { pullSharedClientState } from '../../utils/sharedClientState';

const roleKeyFromRoleString = (role) => {
  const r = (role || '').toLowerCase();
  if (r.includes('system_admin') || r.includes('system admin') || r.includes('systemadmin')) return 'system_admin';
  if (r.includes('registrar')) return 'registrar';
  if (r.includes('faculty')) return 'faculty';
  if (
    r.includes('deptadmin') ||
    r.includes('dept_admin') ||
    r.includes('department_admin') ||
    r.includes('department admin') ||
    r.includes('admin')
  ) {
    return 'department_admin';
  }
  return 'student';
};

const displayNameForUser = (u) => {
  if (!u) return '';
  if (u.firstName && u.lastName) return `${u.firstName} ${u.lastName}`.trim();
  return u.fullName || u.email || '';
};

const valueOf = (obj, ...keys) => {
  for (const key of keys) {
    if (obj && obj[key] !== undefined && obj[key] !== null) return obj[key];
  }
  return undefined;
};

const isMimeTypeText = (text) =>
  /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+(?:\s*;.*)?$/i.test(String(text || '').trim());

const getVisibleMessageText = (msg) => {
  const text = String(msg?.message || '').trim();
  const mime = String(msg?.attachmentMime || '').trim();

  if (!text) return '';
  if (mime && text.toLowerCase() === mime.toLowerCase()) return '';
  if (isMimeTypeText(text)) return '';

  return msg.message;
};

const normalizeUser = (user) => ({
  email: valueOf(user, 'email', 'Email') || '',
  role: valueOf(user, 'role', 'Role') || '',
  fullName: valueOf(user, 'fullName', 'FullName') || '',
  firstName: valueOf(user, 'firstName', 'FirstName') || '',
  lastName: valueOf(user, 'lastName', 'LastName') || '',
  isOnline: Boolean(valueOf(user, 'isOnline', 'IsOnline')),
  hasConversation: Boolean(valueOf(user, 'hasConversation', 'HasConversation')),
});

const normalizeConversationState = (state) => ({
  otherUserEmail: valueOf(state, 'otherUserEmail', 'OtherUserEmail') || '',
  isArchived: Boolean(valueOf(state, 'isArchived', 'IsArchived')),
  deletedAt: valueOf(state, 'deletedAt', 'DeletedAt') || null,
  updatedAt: valueOf(state, 'updatedAt', 'UpdatedAt') || null,
});

const normalizeGroup = (group) => ({
  id: Number(valueOf(group, 'id', 'Id')),
  name: valueOf(group, 'name', 'Name') || 'Group chat',
  createdBy: valueOf(group, 'createdBy', 'CreatedBy') || '',
  createdAt: valueOf(group, 'createdAt', 'CreatedAt') || null,
  memberCount: Number(valueOf(group, 'memberCount', 'MemberCount') || 0),
  isOwner: Boolean(valueOf(group, 'isOwner', 'IsOwner')),
});

const normalizeGroupInvitation = (invitation) => ({
  groupId: Number(valueOf(invitation, 'groupId', 'GroupId')),
  groupName: valueOf(invitation, 'groupName', 'GroupName') || 'Group chat',
  invitedBy: valueOf(invitation, 'invitedBy', 'InvitedBy') || '',
  invitedAt: valueOf(invitation, 'invitedAt', 'InvitedAt') || null,
  memberCount: Number(valueOf(invitation, 'memberCount', 'MemberCount') || 0),
});

const normalizeGroupMessage = (message) => ({
  id: valueOf(message, 'id', 'Id'),
  groupId: Number(valueOf(message, 'groupId', 'GroupId')),
  sender: valueOf(message, 'senderEmail', 'SenderEmail') || '',
  senderName: valueOf(message, 'senderName', 'SenderName') || '',
  message: valueOf(message, 'message', 'Message') || '',
  sentAt: valueOf(message, 'sentAt', 'SentAt') || null,
});

const normalizeMessage = (payload) => {
  const normalized = {
    id: valueOf(payload, 'messageId', 'MessageId', 'id', 'Id'),
    sender: valueOf(payload, 'sender', 'Sender', 'senderEmail', 'SenderEmail'),
    receiver: valueOf(payload, 'receiver', 'Receiver', 'receiverEmail', 'ReceiverEmail'),
    message: valueOf(payload, 'message', 'Message', 'text', 'Text') || '',
    sentAt: valueOf(payload, 'sentAt', 'SentAt', 'timestamp', 'Timestamp'),
    deliveredAt: valueOf(payload, 'deliveredAt', 'DeliveredAt') || null,
    seenAt: valueOf(payload, 'seenAt', 'SeenAt') || null,
    timestamp: valueOf(payload, 'sentAt', 'SentAt', 'timestamp', 'Timestamp'),
    attachmentName: valueOf(payload, 'attachmentName', 'AttachmentName'),
    attachmentMime: valueOf(payload, 'attachmentMime', 'AttachmentMime'),
    attachmentSizeBytes: valueOf(payload, 'attachmentSizeBytes', 'AttachmentSizeBytes'),
    attachmentDataBase64: valueOf(payload, 'attachmentDataBase64', 'AttachmentDataBase64'),
    receivedAt: valueOf(payload, 'receivedAt', 'ReceivedAt') || Date.now(),
  };

  normalized.message = getVisibleMessageText(normalized);

  if (!normalized.id) {
    normalized.id = [
      normalized.sender,
      normalized.receiver,
      normalized.sentAt || normalized.timestamp,
      normalized.message,
      normalized.attachmentName || '',
    ].join('|');
  }

  return normalized;
};

const isSameMessage = (a, b) => {
  if (!a?.id || !b?.id) return false;
  return String(a.id) === String(b.id);
};

const getMessageTimeMs = (message) => {
  const raw = message?.sentAt || message?.timestamp || message?.receivedAt;
  if (!raw) return null;
  const time = raw instanceof Date ? raw.getTime() : new Date(raw).getTime();
  if (Number.isFinite(time)) return time;
  const fallbackTime = Number(raw);
  return Number.isFinite(fallbackTime) ? fallbackTime : null;
};

const sortMessagesOldestFirst = (list) =>
  [...list]
    .map((message, index) => ({ message, index }))
    .sort((a, b) => {
      const timeA = getMessageTimeMs(a.message);
      const timeB = getMessageTimeMs(b.message);

      if (timeA !== null && timeB !== null && timeA !== timeB) return timeA - timeB;

      const idA = Number(a.message?.id);
      const idB = Number(b.message?.id);
      if (Number.isFinite(idA) && Number.isFinite(idB) && idA !== idB) return idA - idB;

      return a.index - b.index;
    })
    .map(({ message }) => message);

const messageRenderKey = (msg, fallback) =>
  String(msg?.id || `${msg?.sender || 'unknown'}-${msg?.receiver || 'unknown'}-${msg?.sentAt || msg?.timestamp || fallback}`);

const mergeMessages = (existing, incoming) => {
  const merged = [...existing];
  for (const message of incoming) {
    const index = merged.findIndex((item) => isSameMessage(item, message));
    if (index >= 0) {
      merged[index] = { ...merged[index], ...message };
    } else {
      merged.push(message);
    }
  }
  return sortMessagesOldestFirst(merged);
};

const isConversationMessage = (msg, userEmail, otherEmail) =>
  (msg.sender === userEmail && msg.receiver === otherEmail) ||
  (msg.sender === otherEmail && msg.receiver === userEmail);

const isImageAttachment = (msg) => {
  const mime = (msg?.attachmentMime || '').toLowerCase();
  const name = (msg?.attachmentName || '').toLowerCase();
  return (
    mime.startsWith('image/') ||
    /\.(png|jpe?g|gif|webp|bmp|svg|avif|ico|tiff?|heic|heif)$/i.test(name)
  );
};

const inferImageMime = (fileName = '') => {
  const name = fileName.toLowerCase();
  if (name.endsWith('.jpg') || name.endsWith('.jpeg')) return 'image/jpeg';
  if (name.endsWith('.png')) return 'image/png';
  if (name.endsWith('.gif')) return 'image/gif';
  if (name.endsWith('.webp')) return 'image/webp';
  if (name.endsWith('.bmp')) return 'image/bmp';
  if (name.endsWith('.svg')) return 'image/svg+xml';
  if (name.endsWith('.avif')) return 'image/avif';
  if (name.endsWith('.ico')) return 'image/x-icon';
  if (name.endsWith('.tif') || name.endsWith('.tiff')) return 'image/tiff';
  if (name.endsWith('.heic')) return 'image/heic';
  if (name.endsWith('.heif')) return 'image/heif';
  return 'image/png';
};

const imageSrcForMessage = (msg) => {
  if (!msg?.attachmentDataBase64) return '';
  return `data:${msg.attachmentMime || inferImageMime(msg.attachmentName)};base64,${msg.attachmentDataBase64}`;
};

const TypingIndicator = ({ dark = false }) => (
  <div className="mb-3 flex w-full items-start">
    <div className={`relative rounded-2xl rounded-bl-none px-4 py-3 shadow-sm ${dark ? 'bg-slate-700' : 'bg-slate-100'}`}>
      <div className={`absolute -left-2 bottom-2 h-0 w-0 border-y-[8px] border-r-[10px] border-y-transparent ${dark ? 'border-r-slate-700' : 'border-r-slate-100'}`} />
      <div className="flex h-5 items-center gap-1" aria-label="Typing">
        <span className="h-2 w-2 animate-bounce rounded-full bg-slate-500" style={{ animationDelay: '0ms' }} />
        <span className="h-2 w-2 animate-bounce rounded-full bg-slate-500" style={{ animationDelay: '120ms' }} />
        <span className="h-2 w-2 animate-bounce rounded-full bg-slate-500" style={{ animationDelay: '240ms' }} />
      </div>
    </div>
  </div>
);

const Chat = ({
  userEmail,
  userRole,
  onClose,
  isOpen = true,
  onUnreadChange,
  onIncomingMessage,
  onRegistrationRequest,
  onSupportNotice,
  autoOpenTarget,
}) => {
  const [connection, setConnection] = useState(null);
  const [messages, setMessages] = useState([]);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState('');
  const [openChatUsers, setOpenChatUsers] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [conversationDrafts, setConversationDrafts] = useState({});

  const [onlineSearch, setOnlineSearch] = useState('');
  const [isUserDropdownOpen, setIsUserDropdownOpen] = useState(false);
  const [messageSearch, setMessageSearch] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [conversationStates, setConversationStates] = useState({});
  const [chatGroups, setChatGroups] = useState([]);
  const [groupInvitations, setGroupInvitations] = useState([]);
  const [groupEligibleUsers, setGroupEligibleUsers] = useState([]);
  const [groupMessages, setGroupMessages] = useState([]);
  const [selectedGroupId, setSelectedGroupId] = useState(null);
  const [isCreatingGroup, setIsCreatingGroup] = useState(false);
  const [groupName, setGroupName] = useState('');
  const [groupMemberSearch, setGroupMemberSearch] = useState('');
  const [selectedGroupInvitees, setSelectedGroupInvitees] = useState([]);
  const [groupActionBusy, setGroupActionBusy] = useState(false);
  const [isChatDarkMode, setIsChatDarkMode] = useState(() => {
    try {
      return localStorage.getItem(`blockgo-chat-dark-mode:${userEmail || 'anonymous'}`) === 'true';
    } catch {
      return false;
    }
  });

  const [chatBoxWidth, setChatBoxWidth] = useState(400);
  const [chatBoxHeight, setChatBoxHeight] = useState(500);
  const [dragState, setDragState] = useState(null);

  const [latestActivity, setLatestActivity] = useState({});
  const [unreadCounts, setUnreadCounts] = useState({});
  const [imagePreview, setImagePreview] = useState(null);
  const [typingUsers, setTypingUsers] = useState({});

  const messagesEndRef = useRef(null);
  const secondaryMessagesRef = useRef(null);
  const connectionRef = useRef(null);
  const selectedUserRef = useRef(selectedUser);
  const selectedGroupIdRef = useRef(selectedGroupId);
  const chatGroupsRef = useRef(chatGroups);
  const openChatUsersRef = useRef(openChatUsers);
  const historyTargetRef = useRef('');
  const isOpenRef = useRef(isOpen);
  const seenRequestRef = useRef({});
  const typingHideTimersRef = useRef({});
  const typingStopTimersRef = useRef({});
  const typingLastSentRef = useRef({});

  useEffect(() => {
    isOpenRef.current = isOpen;
  }, [isOpen]);

  useEffect(() => {
    try {
      localStorage.setItem(`blockgo-chat-dark-mode:${userEmail || 'anonymous'}`, String(isChatDarkMode));
    } catch {
      // Chat remains usable when browser storage is unavailable.
    }
  }, [isChatDarkMode, userEmail]);

  const applyConversationState = useCallback((rawState) => {
    const state = normalizeConversationState(rawState);
    if (!state.otherUserEmail) return;
    setConversationStates((prev) => {
      const next = { ...prev };
      if (!state.isArchived && !state.deletedAt) delete next[state.otherUserEmail];
      else next[state.otherUserEmail] = state;
      return next;
    });
  }, []);

  const loadConversationStates = useCallback(async (activeConnection) => {
    if (!activeConnection) return;
    try {
      const states = await activeConnection.invoke('GetConversationStates');
      const next = {};
      (Array.isArray(states) ? states : []).map(normalizeConversationState).forEach((state) => {
        if (state.otherUserEmail && (state.isArchived || state.deletedAt)) next[state.otherUserEmail] = state;
      });
      setConversationStates(next);
    } catch (error) {
      console.error('[Chat] GetConversationStates failed:', error);
    }
  }, []);

  const loadGroupChatData = useCallback(async (activeConnection = connectionRef.current) => {
    if (!activeConnection) return;
    try {
      const payload = await activeConnection.invoke('GetGroupChatData');
      setChatGroups((valueOf(payload, 'groups', 'Groups') || []).map(normalizeGroup).filter((group) => group.id));
      setGroupInvitations((valueOf(payload, 'invitations', 'Invitations') || []).map(normalizeGroupInvitation).filter((invitation) => invitation.groupId));
      setGroupEligibleUsers((valueOf(payload, 'eligibleUsers', 'EligibleUsers') || []).map(normalizeUser).filter((user) => user.email));
    } catch (error) {
      console.error('[Chat] GetGroupChatData failed:', error);
    }
  }, []);

  useEffect(() => {
    connectionRef.current = connection;
  }, [connection]);

  useEffect(() => {
    const hideTimers = typingHideTimersRef.current;
    const stopTimers = typingStopTimersRef.current;

    return () => {
      Object.values(hideTimers).forEach(window.clearTimeout);
      Object.values(stopTimers).forEach(window.clearTimeout);
    };
  }, []);

  const isConversationReadable = useCallback((targetEmail) =>
    Boolean(
      targetEmail &&
        isOpenRef.current &&
        openChatUsersRef.current.includes(targetEmail) &&
        document.visibilityState !== 'hidden'
    ), []);

  const markConversationSeen = useCallback((targetEmail, activeConnection = connectionRef.current) => {
    if (!activeConnection || !isConversationReadable(targetEmail)) return;

    const now = Date.now();
    if (now - (seenRequestRef.current[targetEmail] || 0) < 1200) return;
    seenRequestRef.current[targetEmail] = now;

    activeConnection
      .invoke('MarkConversationSeen', targetEmail)
      .catch((e) => console.error('[Chat] MarkConversationSeen failed:', e));
  }, [isConversationReadable]);

  const sendTypingState = useCallback((recipientEmail, isTyping, activeConnection = connectionRef.current) => {
    if (!activeConnection || !recipientEmail) return;
    activeConnection
      .invoke('SetTyping', recipientEmail, Boolean(isTyping))
      .catch((e) => console.error('[Chat] SetTyping failed:', e));
  }, []);

  const stopTyping = useCallback((recipientEmail, activeConnection = connectionRef.current) => {
    if (!recipientEmail) return;
    window.clearTimeout(typingStopTimersRef.current[recipientEmail]);
    delete typingStopTimersRef.current[recipientEmail];
    typingLastSentRef.current[recipientEmail] = 0;
    sendTypingState(recipientEmail, false, activeConnection);
  }, [sendTypingState]);

  const updateTyping = useCallback((recipientEmail, value, activeConnection = connectionRef.current) => {
    if (!recipientEmail || !activeConnection) return;

    window.clearTimeout(typingStopTimersRef.current[recipientEmail]);

    if (!String(value || '').trim()) {
      stopTyping(recipientEmail, activeConnection);
      return;
    }

    const now = Date.now();
    if (now - (typingLastSentRef.current[recipientEmail] || 0) > 900) {
      typingLastSentRef.current[recipientEmail] = now;
      sendTypingState(recipientEmail, true, activeConnection);
    }

    typingStopTimersRef.current[recipientEmail] = window.setTimeout(() => {
      stopTyping(recipientEmail, activeConnection);
    }, 1500);
  }, [sendTypingState, stopTyping]);

  useEffect(() => {
    selectedUserRef.current = selectedUser;
    if (selectedUser && isOpenRef.current) setUnreadCounts((prev) => ({ ...prev, [selectedUser]: 0 }));
  }, [selectedUser]);

  useEffect(() => {
    selectedGroupIdRef.current = selectedGroupId;
  }, [selectedGroupId]);

  useEffect(() => {
    chatGroupsRef.current = chatGroups;
  }, [chatGroups]);

  useEffect(() => {
    openChatUsersRef.current = openChatUsers;
    if (isOpen && openChatUsers.length > 0) {
      setUnreadCounts((prev) => {
        const next = { ...prev };
        openChatUsers.forEach((email) => {
          next[email] = 0;
        });
        return next;
      });
    }
  }, [isOpen, openChatUsers]);

  useEffect(() => {
    const targetEmail = autoOpenTarget?.email;
    if (!targetEmail || targetEmail === userEmail) return;

    setSelectedGroupId(null);
    setSelectedUser(targetEmail);
    setNewMessage('');
    setMessageSearch('');
    setIsUserDropdownOpen(false);
    setOpenChatUsers((prev) => {
      const next = prev.filter((email) => email !== targetEmail);
      next.push(targetEmail);
      return next.slice(-2);
    });
  }, [autoOpenTarget, userEmail]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const scrollSecondaryToBottom = () => {
    if (!secondaryMessagesRef.current) return;
    secondaryMessagesRef.current.scrollTop = secondaryMessagesRef.current.scrollHeight;
  };

  // SignalR lifecycle
  useEffect(() => {
    const chatUrl = getChatHubUrl();
    const token = getAuthToken();

    const conn = new signalR.HubConnectionBuilder()
      .withUrl(chatUrl, { accessTokenFactory: () => token || '' })
      .withAutomaticReconnect()
      .build();

    conn.on('ReceiveMessage', (payload) => {
      console.log('[Chat] ReceiveMessage:', payload);
      const normalized = normalizeMessage(payload);
      const otherUser = normalized.sender === userEmail ? normalized.receiver : normalized.sender;

      setMessages((prev) => mergeMessages(prev, [normalized]));

      if (otherUser) {
        setConversationStates((prev) => {
          if (!prev[otherUser]) return prev;
          const next = { ...prev };
          delete next[otherUser];
          return next;
        });
        setLatestActivity((prev) => {
          const ts = normalized.sentAt || normalized.timestamp;
          return { ...prev, [otherUser]: new Date(ts).getTime() };
        });

        setOnlineUsers((prev) =>
          prev.map((u) => (u.email === otherUser ? { ...u, hasConversation: true } : u))
        );
      }

      if (normalized.sender !== userEmail) {
        onIncomingMessage?.({
          from: otherUser,
          message: normalized.message,
          attachmentName: normalized.attachmentName,
          sentAt: normalized.sentAt || normalized.timestamp,
        });
      }

      setUnreadCounts((prev) => {
        const shouldNotify = !isOpenRef.current || !openChatUsersRef.current.includes(otherUser);
        if (shouldNotify && normalized.sender !== userEmail) {
          return { ...prev, [otherUser]: (prev[otherUser] || 0) + 1 };
        }
        return prev;
      });

      if (normalized.sender !== userEmail && isConversationReadable(otherUser)) {
        window.setTimeout(() => markConversationSeen(otherUser, conn), 250);
      }
    });

    conn.on('ChatHistory', (history) => {
      console.log('[Chat] ChatHistory received:', history?.length, 'messages');
      if (!history || !Array.isArray(history)) {
        console.warn('[Chat] ChatHistory is not an array');
        return;
      }

      const activeUser = historyTargetRef.current || selectedUserRef.current;
      if (!activeUser) return;
      
      const mapped = (history || [])
        .map((m) => ({
          ...normalizeMessage(m),
        }))
        .filter((msg) => isConversationMessage(msg, userEmail, activeUser));
      
      setMessages((prev) => mergeMessages(prev, mapped));

      if (isConversationReadable(activeUser)) {
        window.setTimeout(() => markConversationSeen(activeUser, conn), 250);
      }
    });

    conn.on('NewRegistrationRequest', (payload) => {
      console.log('[Chat] NewRegistrationRequest:', payload);
      onRegistrationRequest?.(payload);
    });

    conn.on('SystemSettingChanged', (payload) => {
      console.log('[Chat] SystemSettingChanged:', payload);
      window.dispatchEvent(new CustomEvent('blockgo:system-setting-changed', { detail: payload }));
    });

    conn.on('SupportNotice', (payload) => {
      console.log('[Chat] SupportNotice:', payload);
      onSupportNotice?.(payload);
    });

    conn.on('AcademicDataChanged', (payload) => {
      console.log('[Chat] AcademicDataChanged:', payload);
      pullSharedClientState()
        .catch((error) => console.warn('[Chat] Shared state pull failed:', error))
        .finally(() => {
          window.dispatchEvent(new CustomEvent('blockgo:academic-data-changed', { detail: payload }));
        });
    });

    conn.on('ChatContacts', (contacts) => {
      if (!Array.isArray(contacts)) return;
      const normalizedContacts = contacts.map(normalizeUser).filter((u) => u.email);
      setOnlineUsers(normalizedContacts);
    });

    conn.on('ConversationStateChanged', applyConversationState);

    conn.on('ConversationDeleted', (payload) => {
      const otherUserEmail = valueOf(payload, 'otherUserEmail', 'OtherUserEmail');
      if (!otherUserEmail) return;

      setMessages((prev) => prev.filter((message) => !isConversationMessage(message, userEmail, otherUserEmail)));
      setOnlineUsers((prev) => prev.map((user) => (
        user.email === otherUserEmail ? { ...user, hasConversation: false } : user
      )));
      setUnreadCounts((prev) => ({ ...prev, [otherUserEmail]: 0 }));
      setOpenChatUsers((prev) => prev.filter((email) => email !== otherUserEmail));
      setSelectedUser((current) => (current === otherUserEmail ? '' : current));
      if (historyTargetRef.current === otherUserEmail) historyTargetRef.current = '';
    });

    conn.on('GroupInvitationReceived', (payload) => {
      const invitation = normalizeGroupInvitation(payload);
      if (!invitation.groupId) return;
      setGroupInvitations((prev) => [invitation, ...prev.filter((item) => item.groupId !== invitation.groupId)]);
      onIncomingMessage?.({
        from: invitation.invitedBy,
        message: `Invited you to the group chat “${invitation.groupName}”.`,
        sentAt: invitation.invitedAt,
        type: 'group_invitation',
      });
    });

    conn.on('GroupMembershipChanged', () => loadGroupChatData(conn));

    conn.on('GroupChatHistory', (payload) => {
      const groupId = Number(valueOf(payload, 'groupId', 'GroupId'));
      if (!groupId) return;
      const mapped = (valueOf(payload, 'messages', 'Messages') || []).map(normalizeGroupMessage);
      setGroupMessages((prev) => [
        ...prev.filter((message) => message.groupId !== groupId),
        ...mapped,
      ]);
    });

    conn.on('ReceiveGroupMessage', (payload) => {
      const message = normalizeGroupMessage(payload);
      if (!message.groupId || !message.id) return;
      setGroupMessages((prev) => {
        if (prev.some((item) => String(item.id) === String(message.id) && item.groupId === message.groupId)) return prev;
        return [...prev, message];
      });
      if (message.sender !== userEmail && selectedGroupIdRef.current !== message.groupId) {
        const group = chatGroupsRef.current.find((item) => item.id === message.groupId);
        onIncomingMessage?.({
          from: group?.name || 'Group chat',
          message: message.message,
          sentAt: message.sentAt,
          type: 'group_message',
        });
      }
    });

    conn.on('UserJoined', (user) => {
      const normalized = normalizeUser(user);
      if (!normalized.email) return;
      console.log('[Chat] UserJoined:', normalized.email);
      setOnlineUsers((prev) => {
        if (prev.some((u) => u.email === normalized.email)) {
          return prev.map((u) => (u.email === normalized.email ? { ...u, ...normalized, isOnline: true } : u));
        }
        return [...prev, { ...normalized, isOnline: true }];
      });
    });

    conn.on('RequestRollCall', (targetEmail) => {
      console.log('[Chat] RequestRollCall for:', targetEmail);
      if (userEmail) conn.invoke('AnnouncePresence', targetEmail).catch(e => console.error('[Chat] AnnouncePresence failed:', e));
    });

    conn.on('UserLeft', (user) => {
      const normalized = normalizeUser(user);
      console.log('[Chat] UserLeft:', normalized.email);
      setOnlineUsers((prev) =>
        prev.map((u) => (u.email === normalized.email ? { ...u, isOnline: false } : u))
      );
    });

    conn.on('OnlineStatusChanged', (payload) => {
      const email = valueOf(payload, 'email', 'Email');
      const isOnline = Boolean(valueOf(payload, 'isOnline', 'IsOnline'));
      if (!email) return;
      setOnlineUsers((prev) =>
        prev.map((u) => (u.email === email ? { ...u, isOnline } : u))
      );
    });

    conn.on('MessageDelivered', (payload) => {
      const messageId = valueOf(payload, 'messageId', 'MessageId');
      const deliveredAt = valueOf(payload, 'deliveredAt', 'DeliveredAt');
      console.log('[Chat] MessageDelivered:', messageId);
      setMessages((prev) =>
        prev.map((m) => {
          if (String(m.id) !== String(messageId)) return m;
          return { ...m, deliveredAt };
        })
      );
    });

    conn.on('MessageSeen', (payload) => {
      const messageId = valueOf(payload, 'messageId', 'MessageId');
      const seenAt = valueOf(payload, 'seenAt', 'SeenAt');
      const deliveredAt = valueOf(payload, 'deliveredAt', 'DeliveredAt');
      console.log('[Chat] MessageSeen:', messageId);
      setMessages((prev) =>
        prev.map((m) => {
          if (String(m.id) !== String(messageId)) return m;
          return { ...m, seenAt, deliveredAt: deliveredAt ?? m.deliveredAt };
        })
      );
    });

    conn.on('UserTyping', (payload) => {
      const sender = valueOf(payload, 'sender', 'Sender');
      const receiver = valueOf(payload, 'receiver', 'Receiver');
      const isTyping = Boolean(valueOf(payload, 'isTyping', 'IsTyping'));
      if (
        !sender ||
        String(receiver || '').toLowerCase() !== String(userEmail || '').toLowerCase() ||
        String(sender || '').toLowerCase() === String(userEmail || '').toLowerCase()
      ) {
        return;
      }

      window.clearTimeout(typingHideTimersRef.current[sender]);

      if (!isTyping) {
        setTypingUsers((prev) => ({ ...prev, [sender]: false }));
        return;
      }

      setTypingUsers((prev) => ({ ...prev, [sender]: true }));
      typingHideTimersRef.current[sender] = window.setTimeout(() => {
        setTypingUsers((prev) => ({ ...prev, [sender]: false }));
      }, 3500);
    });

    conn.start()
      .then(() => {
        console.log('[Chat] Connected to SignalR');
        setConnection(conn);
        conn.invoke('JoinChat', userRole || '').catch(e => console.error('[Chat] JoinChat failed:', e));
        conn.invoke('GetChatContacts').catch(e => console.error('[Chat] GetChatContacts failed:', e));
        loadConversationStates(conn);
        loadGroupChatData(conn);
        pullSharedClientState().catch((error) => console.warn('[Chat] Initial shared state pull failed:', error));
      })
      .catch((err) => console.error('SignalR connection failed:', err));

    conn.onreconnected(() => {
      conn.invoke('JoinChat', userRole || '').catch(e => console.error('[Chat] JoinChat after reconnect failed:', e));
      conn.invoke('GetChatContacts').catch(e => console.error('[Chat] GetChatContacts after reconnect failed:', e));
      loadConversationStates(conn);
      loadGroupChatData(conn);
      if (selectedUserRef.current) {
        conn.invoke('GetChatHistory', selectedUserRef.current).catch(e => console.error('[Chat] GetChatHistory after reconnect failed:', e));
      }
    });

    return () => {
      setConnection(null);
      conn.stop();
    };
  }, [userEmail, userRole, onIncomingMessage, onRegistrationRequest, onSupportNotice, isConversationReadable, markConversationSeen, applyConversationState, loadConversationStates, loadGroupChatData]);

  // Load history when selected user changes
  useEffect(() => {
    if (connection && selectedUser) {
      console.log('[Chat] Loading history with:', selectedUser);
      historyTargetRef.current = selectedUser;
      connection.invoke('GetChatHistory', selectedUser).catch(e => console.error('[Chat] GetChatHistory failed:', e));
    }
  }, [connection, selectedUser]);

  useEffect(() => {
    if (!connection || !selectedGroupId) return;
    connection.invoke('GetGroupChatHistory', selectedGroupId)
      .catch((error) => console.error('[Chat] GetGroupChatHistory failed:', error));
  }, [connection, selectedGroupId]);

  useEffect(() => {
    if (!connection || !isOpen || document.visibilityState === 'hidden') return;

    const visibleIncoming = openChatUsers.filter((email) =>
      messages.some(
        (msg) =>
          msg.sender === email &&
          msg.receiver === userEmail &&
          !msg.seenAt &&
          isConversationMessage(msg, userEmail, email)
      )
    );

    visibleIncoming.forEach((email) => markConversationSeen(email));
  }, [connection, isOpen, messages, openChatUsers, userEmail, markConversationSeen]);

  useEffect(() => {
    if (!connection) return undefined;

    const markOpenConversations = () => {
      if (document.visibilityState === 'hidden') return;
      openChatUsersRef.current.forEach((email) => markConversationSeen(email));
    };

    window.addEventListener('focus', markOpenConversations);
    document.addEventListener('visibilitychange', markOpenConversations);

    return () => {
      window.removeEventListener('focus', markOpenConversations);
      document.removeEventListener('visibilitychange', markOpenConversations);
    };
  }, [connection, markConversationSeen]);

  const selectedUserTyping = selectedUser ? typingUsers[selectedUser] : false;

  // Scroll
  useEffect(() => {
    const frame = window.requestAnimationFrame(scrollToBottom);
    return () => window.cancelAnimationFrame(frame);
  }, [messages.length, groupMessages.length, selectedUser, selectedGroupId, selectedUserTyping]);

  useEffect(() => {
    const frame = window.requestAnimationFrame(scrollSecondaryToBottom);
    return () => window.cancelAnimationFrame(frame);
  }, [messages.length, openChatUsers, typingUsers]);

  useEffect(() => {
    const totalUnread = Object.values(unreadCounts).reduce((total, count) => total + Number(count || 0), 0);
    onUnreadChange?.(totalUnread, unreadCounts);
  }, [unreadCounts, onUnreadChange]);

  const sortedOnlineUsers = useMemo(() => {
    return [...onlineUsers].sort((a, b) => {
      if (a.isOnline !== b.isOnline) return a.isOnline ? -1 : 1;
      const timeA = latestActivity[a.email] || 0;
      const timeB = latestActivity[b.email] || 0;
      if (timeA !== timeB) return timeB - timeA;
      return displayNameForUser(a).localeCompare(displayNameForUser(b));
    });
  }, [onlineUsers, latestActivity]);

  const allowedTargetsByViewer = (viewerKey) => {
    if (viewerKey === 'faculty') return new Set(['registrar', 'department_admin', 'faculty']);
    if (viewerKey === 'department_admin') return new Set(['registrar', 'faculty']);
    if (viewerKey === 'system_admin') return new Set(['registrar']);
    if (viewerKey === 'registrar') return new Set(['system_admin', 'department_admin', 'faculty', 'student']);
    return new Set(['registrar']);
  };

  const viewerKey = roleKeyFromRoleString(userRole);
  const allowedTargets = allowedTargetsByViewer(viewerKey);

  const onlineCandidates = useMemo(() => {
    const q = onlineSearch.trim().toLowerCase();
    return sortedOnlineUsers
      .filter((u) => u.email !== userEmail)
      .filter((u) => allowedTargets.has(roleKeyFromRoleString(u.role || '')))
      .filter((u) => {
        if (!q) return true;
        return displayNameForUser(u).toLowerCase().includes(q);
      });
  }, [sortedOnlineUsers, userEmail, onlineSearch, allowedTargets]);

  const grouped = useMemo(() => {
    const buckets = {
      department_admin: [],
      faculty: [],
      student: [],
      registrar: [],
      system_admin: [],
    };
    for (const u of onlineCandidates) {
      const rk = roleKeyFromRoleString(u.role || '');
      const key = rk;
      if (buckets[key]) buckets[key].push(u);
    }
    return buckets;
  }, [onlineCandidates]);

  const allowedGroupOrder = useMemo(() => {
    return ['system_admin', 'department_admin', 'faculty', 'student', 'registrar'].filter((k) => {
      const setHas = allowedTargets.has(k);
      return setHas;
    });
  }, [allowedTargets]);

  const filteredMessages = useMemo(() => {
    if (!selectedUser) return [];

    const inChat = sortMessagesOldestFirst(
      messages.filter((msg) => isConversationMessage(msg, userEmail, selectedUser))
    );

    if (!isSearching || !messageSearch.trim()) return inChat;

    const q = messageSearch.toLowerCase();
    return inChat.filter((m) => {
      const text = (m.message || '').toLowerCase();
      const fileName = (m.attachmentName || '').toLowerCase();
      return text.includes(q) || fileName.includes(q);
    });
  }, [messages, userEmail, selectedUser, isSearching, messageSearch]);

  const getConversationMessages = (email) => {
    if (!email) return [];
    return sortMessagesOldestFirst(
      messages.filter(
        (msg) =>
          (msg.sender === userEmail && msg.receiver === email) ||
          (msg.sender === email && msg.receiver === userEmail)
      )
    );
  };

  const sendMessageTo = async (recipientEmail, draftValue, clearDraft) => {
    if (draftValue.trim() && connection && recipientEmail) {
      const msgText = draftValue.trim();
      clearDraft();
      stopTyping(recipientEmail);
      connection.invoke('SendMessage', recipientEmail, msgText).catch(e => console.error('[Chat] SendMessage failed:', e));
    }
  };

  const sendMessage = async () => {
    if (selectedGroupId) {
      if (!connection || !newMessage.trim()) return;
      const text = newMessage.trim();
      setNewMessage('');
      connection.invoke('SendGroupMessage', Number(selectedGroupId), text)
        .catch((error) => {
          console.error('[Chat] SendGroupMessage failed:', error);
          alert(error?.message || 'The group message could not be sent.');
        });
      return;
    }
    return sendMessageTo(selectedUser, newMessage, () => setNewMessage(''));
  };

  const handlePickFile = () => fileInputRef.current?.click();
  const fileInputRef = useRef(null);

  const handleFileChange = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    if (!selectedUser || !connection) return;

    const maxBytes = 5 * 1024 * 1024;
    if (file.size > maxBytes) {
      alert('File too large (max 5MB)');
      return;
    }

    const base64 = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.onload = () => {
        const result = reader.result;
        const b64 = typeof result === 'string' ? result.split(',')[1] : '';
        resolve(b64);
      };
      reader.readAsDataURL(file);
    });

    try {
      await connection.invoke(
        'SendFile',
        selectedUser,
        file.name,
        file.type || 'application/octet-stream',
        file.size,
        base64,
        ''
      );
    } catch (err) {
      console.error('[Chat] SendFile failed:', err);
      alert(err?.message || 'File could not be sent.');
    }
  };

  const downloadAttachment = (msg) => {
    if (!msg.attachmentDataBase64) return;

    try {
      const byteCharacters = atob(msg.attachmentDataBase64);
      const byteNumbers = Array.from(byteCharacters, (char) => char.charCodeAt(0));
      const blob = new Blob([new Uint8Array(byteNumbers)], {
        type: msg.attachmentMime || 'application/octet-stream',
      });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = msg.attachmentName || 'attachment';
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('[Chat] Failed to download attachment:', err);
      alert('Attachment could not be downloaded.');
    }
  };

  const onResizeMouseDown = (e) => {
    e.preventDefault();
    setDragState({
      startX: e.clientX,
      startY: e.clientY,
      startW: chatBoxWidth,
      startH: chatBoxHeight,
    });
  };

  useEffect(() => {
    if (!dragState) return;

    const onMouseMove = (e) => {
      const dx = e.clientX - dragState.startX;
      const dy = e.clientY - dragState.startY;
      const newW = Math.min(720, Math.max(320, dragState.startW + dx));
      const newH = Math.min(900, Math.max(380, dragState.startH + dy));
      setChatBoxWidth(newW);
      setChatBoxHeight(newH);
    };

    const onMouseUp = () => setDragState(null);

    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);

    return () => {
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
    };
  }, [dragState]);

  const otherCount = useMemo(() => {
    return onlineCandidates.length;
  }, [onlineCandidates]);

  const [facultyTypeFilters, setFacultyTypeFilters] = useState({
    registrar: true,
    department_admin: true,
    faculty: true,
  });

  useEffect(() => {
    setFacultyTypeFilters({ registrar: true, department_admin: true, faculty: true });
  }, [viewerKey]);

  const filteredGroupsForUI = useMemo(() => {
    if (viewerKey !== 'faculty') return grouped;

    return {
      ...grouped,
      registrar: facultyTypeFilters.registrar ? grouped.registrar : [],
      department_admin: facultyTypeFilters.department_admin ? grouped.department_admin : [],
      faculty: facultyTypeFilters.faculty ? grouped.faculty : [],
    };
  }, [viewerKey, grouped, facultyTypeFilters]);

  const groupTitle = (key) => {
    if (key === 'department_admin') return 'Department Admins';
    if (key === 'faculty') return 'Faculties';
    if (key === 'student') return 'Students';
    if (key === 'registrar') return 'Registrar';
    if (key === 'system_admin') return 'System Administrator';
    return key;
  };

  const hasVisibleContacts = allowedGroupOrder.some((key) => (filteredGroupsForUI[key] || []).length > 0);

  const selectedUserDetails = useMemo(
    () => onlineUsers.find((u) => u.email === selectedUser),
    [onlineUsers, selectedUser]
  );

  const selectedUserName = selectedUserDetails ? displayNameForUser(selectedUserDetails) : selectedUser;
  const selectedGroup = useMemo(
    () => chatGroups.find((group) => group.id === Number(selectedGroupId)) || null,
    [chatGroups, selectedGroupId]
  );
  const isAnyConversationSelected = Boolean(selectedUser || selectedGroupId);
  const canCreateGroupChats = ['registrar', 'department_admin', 'faculty'].includes(viewerKey);
  const selectedGroupMessages = useMemo(() => {
    const inGroup = groupMessages
      .filter((message) => message.groupId === Number(selectedGroupId))
      .sort((a, b) => new Date(a.sentAt || 0).getTime() - new Date(b.sentAt || 0).getTime());
    if (!isSearching || !messageSearch.trim()) return inGroup;
    const query = messageSearch.trim().toLowerCase();
    return inGroup.filter((message) => message.message.toLowerCase().includes(query) || message.senderName.toLowerCase().includes(query));
  }, [groupMessages, selectedGroupId, isSearching, messageSearch]);
  const activeMessages = selectedGroupId ? selectedGroupMessages : filteredMessages;

  const filteredGroupEligibleUsers = useMemo(() => {
    const query = groupMemberSearch.trim().toLowerCase();
    return groupEligibleUsers.filter((user) => {
      if (!query) return true;
      return displayNameForUser(user).toLowerCase().includes(query) || user.email.toLowerCase().includes(query);
    });
  }, [groupEligibleUsers, groupMemberSearch]);
  const getNameForEmail = (email) => {
    const user = onlineUsers.find((u) => u.email === email);
    return user ? displayNameForUser(user) : email;
  };

  const secondaryChatUsers = openChatUsers.filter((email) => email && email !== selectedUser).slice(0, 1);

  const totalOnlineUsers = useMemo(() => {
    return onlineUsers.filter((u) => u.email !== userEmail && u.isOnline).length;
  }, [onlineUsers, userEmail]);

  const archivedUsers = useMemo(
    () => sortedOnlineUsers.filter((u) => conversationStates[u.email]?.isArchived && !conversationStates[u.email]?.deletedAt),
    [sortedOnlineUsers, conversationStates]
  );

  const recentlyDeletedUsers = useMemo(() => {
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    return sortedOnlineUsers.filter((u) => {
      const deletedAt = conversationStates[u.email]?.deletedAt;
      return deletedAt && new Date(deletedAt).getTime() >= cutoff;
    });
  }, [sortedOnlineUsers, conversationStates]);

  const activeConversationUsers = useMemo(
    () => sortedOnlineUsers.filter((u) => u.hasConversation && !conversationStates[u.email]?.isArchived && !conversationStates[u.email]?.deletedAt),
    [sortedOnlineUsers, conversationStates]
  );

  const closeConversationLocally = useCallback((email) => {
    stopTyping(email);
    setOpenChatUsers((prev) => prev.filter((item) => item !== email));
    setSelectedUser((current) => (current === email ? '' : current));
    setNewMessage('');
    setMessageSearch('');
    setIsSearching(false);
    setConversationDrafts((prev) => {
      const next = { ...prev };
      delete next[email];
      return next;
    });
    if (historyTargetRef.current === email) historyTargetRef.current = '';
  }, [stopTyping]);

  const updateConversationState = useCallback(async (method, email, ...args) => {
    if (!connection || !email) return false;
    try {
      const state = await connection.invoke(method, email, ...args);
      applyConversationState(state);
      return true;
    } catch (error) {
      console.error(`[Chat] ${method} failed:`, error);
      alert(error?.message || 'The conversation could not be updated.');
      return false;
    }
  }, [connection, applyConversationState]);

  const archiveConversation = async (email) => {
    if (await updateConversationState('SetConversationArchived', email, true)) closeConversationLocally(email);
  };

  const deleteConversation = async (email) => {
    if (!window.confirm('Permanently delete every message in this conversation? Messages cannot be recovered. The user will remain available to message.')) return;
    if (await updateConversationState('DeleteConversation', email)) closeConversationLocally(email);
  };

  const restoreConversation = async (email, openAfterRestore = false) => {
    if (!(await updateConversationState('RestoreConversation', email))) return;
    if (openAfterRestore) {
      setIsSettingsOpen(false);
      setSelectedUser(email);
      setOpenChatUsers((prev) => [...prev.filter((item) => item !== email), email].slice(-2));
    }
  };

  const selectRecipient = async (email) => {
    if (selectedUser && selectedUser !== email) stopTyping(selectedUser);
    if (conversationStates[email]?.isArchived || conversationStates[email]?.deletedAt) {
      const restored = await updateConversationState('RestoreConversation', email);
      if (!restored) return;
    }
    setIsSettingsOpen(false);
    setSelectedGroupId(null);
    setSelectedUser(email);
    setNewMessage('');
    setMessageSearch('');
    setIsUserDropdownOpen(false);
    setOpenChatUsers((prev) => {
      const next = prev.filter((item) => item !== email);
      next.push(email);
      return next.slice(-2);
    });
  };

  const selectGroupChat = (groupId) => {
    if (selectedUser) stopTyping(selectedUser);
    setSelectedUser('');
    setOpenChatUsers([]);
    setSelectedGroupId(Number(groupId));
    setIsSettingsOpen(false);
    setIsCreatingGroup(false);
    setNewMessage('');
    setMessageSearch('');
    setIsSearching(false);
    setIsUserDropdownOpen(false);
  };

  const respondToGroupInvitation = async (groupId, accept) => {
    if (!connection || groupActionBusy) return;
    setGroupActionBusy(true);
    try {
      await connection.invoke('RespondToGroupInvitation', Number(groupId), Boolean(accept));
      await loadGroupChatData(connection);
      if (accept) selectGroupChat(groupId);
    } catch (error) {
      console.error('[Chat] RespondToGroupInvitation failed:', error);
      alert(error?.message || 'The group invitation could not be updated.');
    } finally {
      setGroupActionBusy(false);
    }
  };

  const toggleGroupInvitee = (email) => {
    setSelectedGroupInvitees((prev) => {
      if (prev.includes(email)) return prev.filter((item) => item !== email);
      if (prev.length >= 49) {
        alert('A group can contain at most 50 people including you.');
        return prev;
      }
      return [...prev, email];
    });
  };

  const createGroupChat = async () => {
    if (!connection || groupActionBusy) return;
    if (chatGroups.length >= 10) {
      alert('You can create or accept no more than 10 active group chats.');
      return;
    }
    if (groupName.trim().length < 2) {
      alert('Enter a group name with at least 2 characters.');
      return;
    }
    setGroupActionBusy(true);
    try {
      const created = normalizeGroup(await connection.invoke('CreateGroupChat', groupName.trim(), selectedGroupInvitees));
      await loadGroupChatData(connection);
      setGroupName('');
      setGroupMemberSearch('');
      setSelectedGroupInvitees([]);
      setIsCreatingGroup(false);
      selectGroupChat(created.id);
    } catch (error) {
      console.error('[Chat] CreateGroupChat failed:', error);
      alert(error?.message || 'The group chat could not be created.');
    } finally {
      setGroupActionBusy(false);
    }
  };

  const closeConversation = (email) => {
    stopTyping(email);
    setOpenChatUsers((prev) => {
      const next = prev.filter((item) => item !== email);
      const fallback = next[next.length - 1] || '';
      setSelectedUser(fallback);
      return next;
    });
    setNewMessage('');
    setMessageSearch('');
    setConversationDrafts((prev) => {
      const next = { ...prev };
      delete next[email];
      return next;
    });
    if (historyTargetRef.current === email) historyTargetRef.current = '';
  };

  const backToConversationList = () => {
    openChatUsers.forEach((email) => stopTyping(email));
    setOpenChatUsers([]);
    setSelectedUser('');
    setSelectedGroupId(null);
    setIsCreatingGroup(false);
    setNewMessage('');
    setMessageSearch('');
    setIsSearching(false);
    setIsUserDropdownOpen(false);
    setConversationDrafts({});
    historyTargetRef.current = '';
  };

  const closeAllChatWindows = () => {
    openChatUsers.forEach((email) => stopTyping(email));
    setOpenChatUsers([]);
    setSelectedUser('');
    setSelectedGroupId(null);
    setIsCreatingGroup(false);
    setNewMessage('');
    setMessageSearch('');
    setConversationDrafts({});
    historyTargetRef.current = '';
    onClose?.();
  };

  if (!isOpen) return null;

  return (
    <>
    <div
      className={`fixed bottom-5 right-5 z-[1000] flex flex-col overflow-hidden rounded-2xl font-sans shadow-2xl transition-colors ${
        isChatDarkMode ? 'bg-slate-900 text-slate-100' : 'bg-white text-slate-900'
      }`}
      style={{ width: chatBoxWidth, height: chatBoxHeight }}
    >
      <div className={`relative flex items-center justify-between border-b p-5 ${isChatDarkMode ? 'border-slate-700' : 'border-slate-200'}`}>
        <div className="flex min-w-0 items-center gap-2">
          {(isAnyConversationSelected || isCreatingGroup) && !isSettingsOpen && (
            <button
              type="button"
              onClick={backToConversationList}
              className={`flex h-9 shrink-0 items-center rounded-full px-3 text-sm font-bold transition ${isChatDarkMode ? 'bg-slate-800 text-slate-200 hover:bg-slate-700' : 'bg-slate-100 text-[#0866ff] hover:bg-blue-50'}`}
              title="Back to conversations"
            >
              Back
            </button>
          )}
          <div className="min-w-0">
          <h3 className={`m-0 text-lg font-bold ${isChatDarkMode ? 'text-white' : 'text-[#003366]'}`}>
            {isSettingsOpen ? 'Chat settings' : isCreatingGroup ? 'New group chat' : selectedGroup ? selectedGroup.name : selectedUser ? selectedUserName : 'Chats'}
          </h3>
          <div className={`mt-1 truncate text-xs font-semibold ${isChatDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>
            {isSettingsOpen
              ? 'Manage your conversations'
              : isCreatingGroup
                ? `${selectedGroupInvitees.length + 1} of 50 people`
                : selectedGroup
                  ? `${selectedGroup.memberCount} accepted member${selectedGroup.memberCount === 1 ? '' : 's'}`
                  : selectedUser || `${totalOnlineUsers} users online`}
          </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isAnyConversationSelected && !isSettingsOpen && (
            <button
              type="button"
              onClick={() => setIsSearching((v) => !v)}
              className={`cursor-pointer rounded-full px-3 py-2 text-xs font-bold transition ${isChatDarkMode ? 'text-slate-300 hover:bg-slate-800' : 'text-slate-500 hover:bg-slate-100 hover:text-slate-700'}`}
              title="Search this conversation"
            >
              Search
            </button>
          )}
          <button
            type="button"
            onClick={() => {
              setIsSettingsOpen((value) => !value);
              setIsSearching(false);
              setMessageSearch('');
            }}
            className={`cursor-pointer rounded-full px-3 py-2 text-xs font-bold transition ${isSettingsOpen ? 'bg-[#0866ff] text-white' : isChatDarkMode ? 'text-slate-300 hover:bg-slate-800' : 'text-slate-500 hover:bg-slate-100'}`}
            title="Chat settings"
          >
            Settings
          </button>
          <button onClick={closeAllChatWindows} className="cursor-pointer text-2xl leading-none text-slate-400 transition hover:text-slate-600" title="Close chat">
            x
          </button>
        </div>
      </div>

      {isAnyConversationSelected && !isSettingsOpen && isSearching && (
        <div className={`border-b p-3 ${isChatDarkMode ? 'border-slate-700' : 'border-slate-200'}`}>
          <input
            type="text"
            value={messageSearch}
            onChange={(e) => setMessageSearch(e.target.value)}
            placeholder="Search in chat..."
            className={`w-full rounded-full border px-4 py-2 text-sm outline-none focus:border-[#0866ff] focus:ring-1 focus:ring-[#0866ff]/20 ${isChatDarkMode ? 'border-slate-600 bg-slate-800 text-white placeholder:text-slate-500' : 'border-slate-300 bg-slate-50'}`}
          />
        </div>
      )}

      {selectedUser && !isSettingsOpen && (
        <div className={`flex items-center justify-end gap-2 border-b px-4 py-2 ${isChatDarkMode ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-slate-50'}`}>
          <button type="button" onClick={() => archiveConversation(selectedUser)} className={`rounded-full px-3 py-1.5 text-xs font-bold transition ${isChatDarkMode ? 'bg-slate-800 text-slate-200 hover:bg-slate-700' : 'bg-white text-slate-600 shadow-sm hover:bg-blue-50 hover:text-[#0866ff]'}`}>Archive</button>
          <button type="button" onClick={() => deleteConversation(selectedUser)} className={`rounded-full px-3 py-1.5 text-xs font-bold transition ${isChatDarkMode ? 'bg-red-950 text-red-300 hover:bg-red-900' : 'bg-white text-red-600 shadow-sm hover:bg-red-50'}`}>Delete messages</button>
        </div>
      )}

      <div className="flex-1 overflow-y-auto p-4">
        {isSettingsOpen ? (
          <div className="space-y-5">
            <div className={`flex items-center justify-between rounded-2xl p-4 ${isChatDarkMode ? 'bg-slate-800' : 'bg-slate-100'}`}>
              <div>
                <div className="text-sm font-bold">Dark mode</div>
                <div className={`mt-1 text-xs ${isChatDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>Only changes this chat window</div>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={isChatDarkMode}
                onClick={() => setIsChatDarkMode((value) => !value)}
                className={`relative h-7 w-12 rounded-full transition ${isChatDarkMode ? 'bg-[#0866ff]' : 'bg-slate-300'}`}
              >
                <span className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow transition-all ${isChatDarkMode ? 'left-6' : 'left-1'}`} />
              </button>
            </div>

            <div>
              <h4 className="mb-2 text-sm font-bold">Archived chats</h4>
              {archivedUsers.length === 0 ? (
                <p className={`rounded-xl p-3 text-xs ${isChatDarkMode ? 'bg-slate-800 text-slate-400' : 'bg-slate-50 text-slate-500'}`}>No archived conversations.</p>
              ) : archivedUsers.map((user) => (
                <div key={user.email} className={`mb-2 flex items-center justify-between gap-2 rounded-xl p-3 ${isChatDarkMode ? 'bg-slate-800' : 'bg-slate-50'}`}>
                  <div className="min-w-0">
                    <div className="truncate text-sm font-bold">{displayNameForUser(user)}</div>
                    <div className={`truncate text-xs ${isChatDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>{user.email}</div>
                  </div>
                  <button type="button" onClick={() => restoreConversation(user.email, true)} className="rounded-full bg-[#0866ff] px-3 py-1.5 text-xs font-bold text-white hover:bg-[#0758db]">Unarchive</button>
                </div>
              ))}
            </div>

            <div>
              <h4 className="mb-2 text-sm font-bold">Recently deleted</h4>
              <p className={`mb-2 text-xs ${isChatDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>Deleted messages are permanent. These shortcuts only let you start a new conversation.</p>
              {recentlyDeletedUsers.length === 0 ? (
                <p className={`rounded-xl p-3 text-xs ${isChatDarkMode ? 'bg-slate-800 text-slate-400' : 'bg-slate-50 text-slate-500'}`}>No conversations deleted in the last 30 days.</p>
              ) : recentlyDeletedUsers.map((user) => (
                <div key={user.email} className={`mb-2 flex items-center justify-between gap-2 rounded-xl p-3 ${isChatDarkMode ? 'bg-slate-800' : 'bg-slate-50'}`}>
                  <div className="min-w-0">
                    <div className="truncate text-sm font-bold">{displayNameForUser(user)}</div>
                    <div className={`truncate text-xs ${isChatDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>Deleted {new Date(conversationStates[user.email].deletedAt).toLocaleDateString()}</div>
                  </div>
                  <button type="button" onClick={() => restoreConversation(user.email, true)} className="rounded-full bg-[#0866ff] px-3 py-1.5 text-xs font-bold text-white hover:bg-[#0758db]">Start new chat</button>
                </div>
              ))}
            </div>
          </div>
        ) : isCreatingGroup ? (
          <div className="space-y-4">
            <div>
              <label className={`mb-1 block text-xs font-bold uppercase tracking-wide ${isChatDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>Group name</label>
              <input
                type="text"
                maxLength={100}
                value={groupName}
                onChange={(event) => setGroupName(event.target.value)}
                placeholder="Enter a group name"
                className={`w-full rounded-xl border px-3 py-2 text-sm outline-none focus:border-[#0866ff] ${isChatDarkMode ? 'border-slate-600 bg-slate-800 text-white' : 'border-slate-300 bg-white'}`}
              />
            </div>
            <div>
              <div className="mb-2 flex items-center justify-between gap-2">
                <label className={`text-xs font-bold uppercase tracking-wide ${isChatDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>Invite people</label>
                <span className="text-xs font-bold text-[#0866ff]">{selectedGroupInvitees.length + 1}/50</span>
              </div>
              <input
                type="text"
                value={groupMemberSearch}
                onChange={(event) => setGroupMemberSearch(event.target.value)}
                placeholder="Search name or account..."
                className={`mb-2 w-full rounded-full border px-3 py-2 text-sm outline-none focus:border-[#0866ff] ${isChatDarkMode ? 'border-slate-600 bg-slate-800 text-white' : 'border-slate-300 bg-white'}`}
              />
              <div className={`max-h-64 overflow-y-auto rounded-xl border p-2 ${isChatDarkMode ? 'border-slate-700' : 'border-slate-200'}`}>
                {filteredGroupEligibleUsers.length === 0 ? (
                  <p className="p-3 text-center text-xs text-slate-400">No matching users.</p>
                ) : filteredGroupEligibleUsers.map((user) => {
                  const selected = selectedGroupInvitees.includes(user.email);
                  return (
                    <button
                      key={user.email}
                      type="button"
                      onClick={() => toggleGroupInvitee(user.email)}
                      className={`mb-1 flex w-full items-center gap-3 rounded-xl p-2 text-left transition ${selected ? 'bg-[#0866ff] text-white' : isChatDarkMode ? 'hover:bg-slate-800' : 'hover:bg-slate-100'}`}
                    >
                      <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-xs font-bold ${selected ? 'bg-white/20' : 'bg-blue-100 text-[#0866ff]'}`}>{displayNameForUser(user).charAt(0).toUpperCase()}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm font-bold">{displayNameForUser(user)}</span>
                        <span className={`block truncate text-[11px] ${selected ? 'text-blue-100' : 'text-slate-500'}`}>{user.role} · {user.email}</span>
                      </span>
                      <span className="text-xs font-bold">{selected ? 'Selected' : 'Add'}</span>
                    </button>
                  );
                })}
              </div>
            </div>
            <div className="flex gap-2">
              <button type="button" onClick={backToConversationList} className={`flex-1 rounded-full px-4 py-2 text-sm font-bold ${isChatDarkMode ? 'bg-slate-800 text-slate-200' : 'bg-slate-100 text-slate-700'}`}>Cancel</button>
              <button type="button" onClick={createGroupChat} disabled={groupActionBusy || groupName.trim().length < 2} className="flex-1 rounded-full bg-[#0866ff] px-4 py-2 text-sm font-bold text-white disabled:opacity-50">{groupActionBusy ? 'Creating...' : 'Create group'}</button>
            </div>
          </div>
        ) : !isAnyConversationSelected ? (
          <div className="space-y-2">
            {groupInvitations.length > 0 && (
              <div className="mb-5">
                <div className={`mb-2 text-xs font-bold uppercase tracking-wide ${isChatDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>Group invitations</div>
                {groupInvitations.map((invitation) => (
                  <div key={invitation.groupId} className={`mb-2 rounded-2xl border p-3 ${isChatDarkMode ? 'border-blue-900 bg-blue-950/40' : 'border-blue-200 bg-blue-50'}`}>
                    <div className="text-sm font-bold">{invitation.groupName}</div>
                    <div className={`mt-1 text-xs ${isChatDarkMode ? 'text-slate-400' : 'text-slate-600'}`}>{invitation.invitedBy} invited you</div>
                    <div className="mt-3 flex gap-2">
                      <button type="button" disabled={groupActionBusy} onClick={() => respondToGroupInvitation(invitation.groupId, true)} className="flex-1 rounded-full bg-[#0866ff] px-3 py-1.5 text-xs font-bold text-white disabled:opacity-50">Accept</button>
                      <button type="button" disabled={groupActionBusy} onClick={() => respondToGroupInvitation(invitation.groupId, false)} className={`flex-1 rounded-full px-3 py-1.5 text-xs font-bold disabled:opacity-50 ${isChatDarkMode ? 'bg-slate-800 text-slate-200' : 'bg-white text-slate-700'}`}>Decline</button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="mb-5">
              <div className="mb-2 flex items-center justify-between gap-2">
                <div className={`text-xs font-bold uppercase tracking-wide ${isChatDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>Group chats · {chatGroups.length}/10</div>
                {canCreateGroupChats && (
                  <button
                    type="button"
                    disabled={chatGroups.length >= 10}
                    onClick={() => {
                      setIsCreatingGroup(true);
                      setIsSettingsOpen(false);
                    }}
                    className="rounded-full bg-[#0866ff] px-3 py-1.5 text-xs font-bold text-white disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    New group
                  </button>
                )}
              </div>
              {chatGroups.length === 0 ? (
                <p className={`rounded-xl p-3 text-xs ${isChatDarkMode ? 'bg-slate-800 text-slate-400' : 'bg-slate-50 text-slate-500'}`}>No accepted group chats yet.</p>
              ) : chatGroups.map((group) => (
                <button key={group.id} type="button" onClick={() => selectGroupChat(group.id)} className={`mb-1 flex w-full items-center gap-3 rounded-2xl p-3 text-left transition ${isChatDarkMode ? 'hover:bg-slate-800' : 'hover:bg-slate-100'}`}>
                  <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-violet-500 to-[#0866ff] font-bold text-white">G</span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-bold">{group.name}</span>
                    <span className={`block text-xs ${isChatDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>{group.memberCount} member{group.memberCount === 1 ? '' : 's'}{group.isOwner ? ' · You created this' : ''}</span>
                  </span>
                </button>
              ))}
            </div>

            <div className={`mb-3 text-xs font-bold uppercase tracking-wide ${isChatDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>Recent conversations</div>
            {activeConversationUsers.length === 0 ? (
              <div className="flex h-40 items-center justify-center text-center">
                
              </div>
            ) : activeConversationUsers.map((user) => (
              <button
                key={user.email}
                type="button"
                onClick={() => selectRecipient(user.email)}
                className={`flex w-full items-center gap-3 rounded-2xl p-3 text-left transition ${isChatDarkMode ? 'hover:bg-slate-800' : 'hover:bg-slate-100'}`}
              >
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[#0866ff] to-[#6aa7ff] font-bold text-white">{displayNameForUser(user).charAt(0).toUpperCase()}</span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-bold">{displayNameForUser(user)}</span>
                  <span className={`block truncate text-xs ${isChatDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>{user.isOnline ? 'Active now' : user.email}</span>
                </span>
                {(unreadCounts[user.email] || 0) > 0 && <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-[#0866ff] px-1 text-[11px] font-bold text-white">{unreadCounts[user.email]}</span>}
              </button>
            ))}
          </div>
        ) : activeMessages.length === 0 && !typingUsers[selectedUser] ? (
          <div className="flex h-full items-center justify-center text-center">
            <p className="text-sm text-slate-400">No messages yet. Start the conversation!</p>
          </div>
        ) : (
          <>
          {activeMessages.map((msg, i) => {
            const isMine = msg.sender === userEmail;
            const isImage = msg.attachmentName && isImageAttachment(msg) && msg.attachmentDataBase64;
            const imageSrc = isImage ? imageSrcForMessage(msg) : '';

            const senderUser = onlineUsers.find((u) => u.email === msg.sender);
            const senderName = msg.senderName || (senderUser ? displayNameForUser(senderUser) : msg.sender ? msg.sender.split('@')[0] : 'Unknown');

            return (
              <div key={messageRenderKey(msg, i)} className={`mb-3 flex w-full flex-col ${isMine ? 'items-end' : 'items-start'}`}>
                <span className={`mb-1 text-[11px] font-semibold text-slate-500 ${isMine ? 'mr-3' : 'ml-3'}`}>
                  {isMine ? 'You' : senderName}
                </span>
                <div
                  className={`relative min-h-[40px] min-w-[56px] whitespace-pre-wrap px-4 py-3 leading-relaxed shadow-sm ${
                    isMine
                      ? 'rounded-2xl rounded-br-none bg-gradient-to-br from-[#0866ff] to-[#2782ff] text-white'
                      : isChatDarkMode
                        ? 'rounded-2xl rounded-bl-none bg-slate-700 text-slate-100'
                        : 'rounded-2xl rounded-bl-none bg-slate-100 text-slate-800'
                  }`}
                  style={{ width: 'fit-content', maxWidth: '85%', overflowWrap: 'anywhere', wordBreak: 'break-word', overflowX: 'hidden' }}
                >
                  {isMine && (
                    <div className="absolute -right-2 bottom-2 h-0 w-0 border-y-[8px] border-l-[10px] border-y-transparent border-l-[#0866ff]" />
                  )}
                  {!isMine && (
                    <div className={`absolute -left-2 bottom-2 h-0 w-0 border-y-[8px] border-r-[10px] border-y-transparent ${isChatDarkMode ? 'border-r-slate-700' : 'border-r-slate-100'}`} />
                  )}

                  {isImage ? (
                    <div className="mb-2">
                      <button
                        type="button"
                        onClick={() => setImagePreview({ src: imageSrc, name: msg.attachmentName })}
                        className="block overflow-hidden rounded-xl border border-white/20 bg-black/5 text-left transition hover:opacity-90"
                        title="Open image preview"
                      >
                        <img
                          src={imageSrc}
                          alt={msg.attachmentName || 'Shared image'}
                          className="max-h-64 max-w-full object-contain"
                        />
                      </button>
                      <button
                        type="button"
                        onClick={() => downloadAttachment(msg)}
                        className="mt-2 block max-w-full truncate text-left text-[11px] font-semibold opacity-80 underline-offset-2 hover:underline"
                        title="Download image"
                      >
                        {msg.attachmentName}
                      </button>
                    </div>
                  ) : msg.attachmentName ? (
                    <div className="mb-2 text-[13px] sm:text-sm">
                      <button
                        type="button"
                        onClick={() => downloadAttachment(msg)}
                        disabled={!msg.attachmentDataBase64}
                        className={`text-left font-semibold underline-offset-2 ${
                          msg.attachmentDataBase64 ? 'cursor-pointer hover:underline' : 'cursor-default'
                        }`}
                        title={msg.attachmentDataBase64 ? 'Download attachment' : 'Attachment data unavailable'}
                      >
                        Attachment: {msg.attachmentName}
                      </button>
                    </div>
                  ) : (
                    <div className="mb-1 text-[13px] sm:text-sm">{getVisibleMessageText(msg)}</div>
                  )}

                  <div className={`mt-auto text-[11px] opacity-70 ${isMine ? 'text-right' : 'text-left'}`}>
                    {msg.sentAt ? new Date(msg.sentAt).toLocaleTimeString() : 'Sending...'}
                    {isMine && msg.seenAt ? (
                      <span className="ml-2 font-semibold opacity-90">Seen</span>
                    ) : isMine && msg.deliveredAt ? (
                      <span className="ml-2 font-semibold opacity-90">Delivered</span>
                    ) : null}
                  </div>
                </div>
              </div>
            );
          })}
          {typingUsers[selectedUser] && <TypingIndicator dark={isChatDarkMode} />}
          </>
        )}
        <div ref={messagesEndRef} />
      </div>

      {!isSettingsOpen && !isAnyConversationSelected && !isCreatingGroup && <div className="flex flex-col gap-2 p-4 pt-0">
        <div className="relative">
          <details
            className="w-full"
            open={isUserDropdownOpen}
            onToggle={(e) => setIsUserDropdownOpen(e.currentTarget.open)}
          >
            <summary className={`cursor-pointer list-none rounded-full border px-4 py-2 text-sm font-semibold ${isChatDarkMode ? 'border-slate-600 bg-slate-800 text-slate-200' : 'border-slate-200 bg-slate-50 text-slate-700'}`}>
              Find people
            </summary>

            <div className={`mt-2 rounded-xl border p-3 shadow-sm ${isChatDarkMode ? 'border-slate-600 bg-slate-800' : 'border-slate-200 bg-white'}`}>
              <div className="flex gap-2 mb-2">
                <input
                  type="text"
                  value={onlineSearch}
                  onChange={(e) => setOnlineSearch(e.target.value)}
                  placeholder="Search users..."
                  className={`flex-1 rounded-full border px-3 py-2 text-sm outline-none focus:border-[#0866ff] focus:ring-1 focus:ring-[#0866ff]/20 ${isChatDarkMode ? 'border-slate-600 bg-slate-900 text-white placeholder:text-slate-500' : 'border-slate-300 bg-slate-50'}`}
                />
              </div>

              {viewerKey === 'faculty' && (
                <div className="flex flex-wrap gap-x-4 gap-y-1 mb-3 text-sm">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={facultyTypeFilters.registrar}
                      onChange={(e) =>
                        setFacultyTypeFilters((p) => ({ ...p, registrar: e.target.checked }))
                      }
                    />
                    <span>Registrar</span>
                  </label>

                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={facultyTypeFilters.department_admin}
                      onChange={(e) =>
                        setFacultyTypeFilters((p) => ({ ...p, department_admin: e.target.checked }))
                      }
                    />
                    <span>Department Admins</span>
                  </label>

                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={facultyTypeFilters.faculty}
                      onChange={(e) => setFacultyTypeFilters((p) => ({ ...p, faculty: e.target.checked }))}
                    />
                    <span>Faculties</span>
                  </label>
                </div>
              )}

              <div className="mt-1 mb-2 text-xs text-slate-500">{otherCount} users available</div>

              <div className="flex max-h-64 flex-col gap-3 overflow-y-auto pr-1">
                {!hasVisibleContacts ? (
                  <div className="text-xs italic text-slate-400">No available chat targets</div>
                ) : (
                  allowedGroupOrder.map((key) => {
                    const arr = filteredGroupsForUI[key] || [];
                    if (!arr.length) return null;

                    return (
                      <div key={key}>
                        <div className="mb-2 text-xs font-bold uppercase tracking-wide text-slate-500">{groupTitle(key)}</div>
                        <div className="flex flex-col gap-1">
                          {arr.map((u) => {
                            const displayName = displayNameForUser(u);
                            const isSelected = selectedUser === u.email;
                            const unreadCount = unreadCounts[u.email] || 0;
                            return (
                              <button
                                key={u.email}
                                onClick={() => selectRecipient(u.email)}
                                className={`flex items-center justify-between rounded-lg px-3 py-2 text-sm font-semibold transition ${
                                  isSelected
                                    ? 'bg-[#0866ff] text-white'
                                    : isChatDarkMode
                                      ? 'bg-slate-700 text-slate-200 hover:bg-slate-600'
                                      : 'bg-slate-100 text-slate-700 hover:bg-blue-50 hover:text-[#003366]'
                                }`}
                                title={displayName}
                              >
                                <span className="truncate">{displayName}</span>
                                {!u.isOnline && (
                                  <span className="ml-2 text-[10px] font-semibold opacity-70">Offline</span>
                                )}
                                {unreadCount > 0 && (
                                  <span className="ml-3 flex h-5 min-w-5 items-center justify-center rounded-full bg-red-500 px-1 text-[11px] font-bold text-white">
                                    {unreadCount > 9 ? '9+' : unreadCount}
                                  </span>
                                )}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </details>
        </div>

      </div>}

      {isAnyConversationSelected && !isSettingsOpen && <div className="flex gap-2 items-end p-4 pt-0">
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={handleFileChange}
          aria-hidden="true"
        />

        {selectedUser && <button
          type="button"
          onClick={handlePickFile}
          disabled={!selectedUser}
          title={selectedUser ? 'Send file' : 'Select a user to send a file'}
          className={`mb-[2px] shrink-0 rounded-full px-3 py-2 text-sm font-bold transition disabled:cursor-not-allowed disabled:opacity-50 ${isChatDarkMode ? 'bg-slate-700 text-slate-200 hover:bg-slate-600' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'}`}
        >
          Attach
        </button>}

        <input
          type="text"
          value={newMessage}
          onChange={(e) => {
            setNewMessage(e.target.value);
            if (selectedUser) updateTyping(selectedUser, e.target.value);
          }}
          onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
          placeholder={selectedGroupId ? `Message ${selectedGroup?.name || 'group'}...` : 'Type a message...'}
          className={`flex-1 rounded-full border px-4 py-2 text-sm outline-none focus:border-[#0866ff] focus:ring-1 focus:ring-[#0866ff]/20 ${isChatDarkMode ? 'border-slate-600 bg-slate-800 text-white placeholder:text-slate-500' : 'border-slate-300 bg-slate-50'}`}
        />

        <button
          onClick={sendMessage}
          disabled={!newMessage.trim() || !isAnyConversationSelected}
          className="shrink-0 rounded-full bg-[#0866ff] px-5 py-2 text-sm font-bold text-white transition hover:bg-[#0758db] disabled:cursor-not-allowed disabled:opacity-50"
        >
          Send
        </button>
      </div>}

      <div
        onMouseDown={onResizeMouseDown}
        className="absolute bottom-0 right-0 h-4 w-4 cursor-nwse-resize"
        title="Resize chat"
        style={{ background: 'transparent' }}
      />

      {imagePreview && (
        <div
          className="fixed inset-0 z-[2100] flex items-center justify-center bg-black/80 p-4"
          onClick={() => setImagePreview(null)}
        >
          <div className="relative max-h-full max-w-5xl" onClick={(e) => e.stopPropagation()}>
            <button
              type="button"
              onClick={() => setImagePreview(null)}
              className="absolute -right-3 -top-3 flex h-9 w-9 items-center justify-center rounded-full bg-white text-xl font-bold text-slate-700 shadow-lg transition hover:bg-slate-100"
              title="Close image preview"
            >
              x
            </button>
            <img
              src={imagePreview.src}
              alt={imagePreview.name || 'Image preview'}
              className="max-h-[86vh] max-w-[92vw] rounded-xl object-contain shadow-2xl"
            />
            {imagePreview.name && (
              <div className="mt-3 max-w-[92vw] truncate text-center text-sm font-semibold text-white">
                {imagePreview.name}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
    {secondaryChatUsers.map((email, index) => {
      const draft = conversationDrafts[email] || '';
      const secondaryMessages = getConversationMessages(email);
      const rightOffset = chatBoxWidth + 36 + index * (chatBoxWidth + 16);
      return (
        <div
          key={email}
          className={`fixed bottom-5 z-[999] flex flex-col overflow-hidden rounded-2xl font-sans shadow-2xl ${isChatDarkMode ? 'bg-slate-900 text-slate-100' : 'bg-white text-slate-900'}`}
          style={{ width: chatBoxWidth, height: chatBoxHeight, right: rightOffset }}
        >
          <div className={`flex items-center justify-between border-b p-4 ${isChatDarkMode ? 'border-slate-700' : 'border-slate-200'}`}>
            <div className="min-w-0">
              <h3 className={`truncate text-base font-bold ${isChatDarkMode ? 'text-white' : 'text-[#003366]'}`}>{getNameForEmail(email)}</h3>
              <p className="truncate text-xs text-slate-500">{email}</p>
            </div>
            <button
              type="button"
              onClick={() => closeConversation(email)}
              className="cursor-pointer text-2xl leading-none text-slate-400 transition hover:text-slate-600"
              title="Close conversation"
            >
              x
            </button>
          </div>

          <div ref={secondaryMessagesRef} className="flex-1 overflow-y-auto p-4">
            {secondaryMessages.length === 0 && !typingUsers[email] ? (
              <div className="flex h-full items-center justify-center text-center">
                <p className="text-sm text-slate-400">No messages yet.</p>
              </div>
            ) : (
              <>
              {secondaryMessages.map((msg, i) => {
                const isMine = msg.sender === userEmail;
                const isImage = msg.attachmentName && isImageAttachment(msg) && msg.attachmentDataBase64;
                const imageSrc = isImage ? imageSrcForMessage(msg) : '';
                const senderUser = onlineUsers.find((u) => u.email === msg.sender);
                const senderName = senderUser ? displayNameForUser(senderUser) : msg.sender ? msg.sender.split('@')[0] : 'Unknown';

                return (
                  <div key={`${messageRenderKey(msg, i)}-${email}`} className={`mb-3 flex w-full flex-col ${isMine ? 'items-end' : 'items-start'}`}>
                    <span className={`mb-1 text-[11px] font-semibold text-slate-500 ${isMine ? 'mr-3' : 'ml-3'}`}>
                      {isMine ? 'You' : senderName}
                    </span>
                    <div
                      className={`relative min-h-[40px] min-w-[56px] whitespace-pre-wrap px-4 py-3 leading-relaxed shadow-sm ${
                        isMine
                          ? 'rounded-2xl rounded-br-none bg-gradient-to-br from-[#0866ff] to-[#2782ff] text-white'
                          : isChatDarkMode
                            ? 'rounded-2xl rounded-bl-none bg-slate-700 text-slate-100'
                            : 'rounded-2xl rounded-bl-none bg-slate-100 text-slate-800'
                      }`}
                      style={{ width: 'fit-content', maxWidth: '85%', overflowWrap: 'anywhere', wordBreak: 'break-word', overflowX: 'hidden' }}
                    >
                      {isImage ? (
                        <button
                          type="button"
                          onClick={() => setImagePreview({ src: imageSrc, name: msg.attachmentName })}
                          className="block overflow-hidden rounded-xl border border-white/20 bg-black/5 text-left transition hover:opacity-90"
                          title="Open image preview"
                        >
                          <img src={imageSrc} alt={msg.attachmentName || 'Shared image'} className="max-h-64 max-w-full object-contain" />
                        </button>
                      ) : msg.attachmentName ? (
                        <button
                          type="button"
                          onClick={() => downloadAttachment(msg)}
                          disabled={!msg.attachmentDataBase64}
                          className={`text-left text-[13px] font-semibold underline-offset-2 ${
                            msg.attachmentDataBase64 ? 'cursor-pointer hover:underline' : 'cursor-default'
                          }`}
                          title={msg.attachmentDataBase64 ? 'Download attachment' : 'Attachment data unavailable'}
                        >
                          Attachment: {msg.attachmentName}
                        </button>
                      ) : (
                        <div className="mb-1 text-[13px] sm:text-sm">{getVisibleMessageText(msg)}</div>
                      )}
                      <div className={`mt-2 text-[11px] opacity-70 ${isMine ? 'text-right' : 'text-left'}`}>
                        {msg.sentAt ? new Date(msg.sentAt).toLocaleTimeString() : 'Sending...'}
                        {isMine && msg.seenAt ? (
                          <span className="ml-2 font-semibold opacity-90">Seen</span>
                        ) : isMine && msg.deliveredAt ? (
                          <span className="ml-2 font-semibold opacity-90">Delivered</span>
                        ) : null}
                      </div>
                    </div>
                  </div>
                );
              })}
              {typingUsers[email] && <TypingIndicator dark={isChatDarkMode} />}
              </>
            )}
          </div>

          <div className="flex gap-2 p-4 pt-0">
            <input
              type="text"
              value={draft}
              onChange={(e) => {
                setConversationDrafts((prev) => ({ ...prev, [email]: e.target.value }));
                updateTyping(email, e.target.value);
              }}
              onKeyDown={(e) =>
                e.key === 'Enter' &&
                sendMessageTo(email, draft, () => setConversationDrafts((prev) => ({ ...prev, [email]: '' })))
              }
              placeholder="Type a message..."
              className={`min-w-0 flex-1 rounded-full border px-4 py-2 text-sm outline-none focus:border-[#0866ff] focus:ring-1 focus:ring-[#0866ff]/20 ${isChatDarkMode ? 'border-slate-600 bg-slate-800 text-white placeholder:text-slate-500' : 'border-slate-300 bg-slate-50'}`}
            />
            <button
              onClick={() => sendMessageTo(email, draft, () => setConversationDrafts((prev) => ({ ...prev, [email]: '' })))}
              disabled={!draft.trim()}
              className="shrink-0 rounded-full bg-[#0866ff] px-5 py-2 text-sm font-bold text-white transition hover:bg-[#0758db] disabled:cursor-not-allowed disabled:opacity-50"
            >
              Send
            </button>
          </div>
        </div>
      );
    })}
    </>
  );
};

export default Chat;
