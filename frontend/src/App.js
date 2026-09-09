import React, { useState, useEffect, useCallback, useRef } from "react";
import "./assets/style.css"; 
import "./assets/App.css";   
import Login from "./components/shared/Login";
import { fetchUserProfile } from './services/api';
import StudentPortal from './components/student/StudentPortal';
import FacultyPortal from './components/faculty/FacultyPortal';
import DeptAdminGradesView from './components/chairperson/DeptAdminGradesView';
import RegistrarGradesView from './components/registrar/RegistrarGradesView';
import SystemAdminPortal from './components/system-admin/SystemAdminPortal';
import Chat from './components/shared/Chat';
import { startNginxFailoverMonitor } from './services/nginxFailover';
import { getLocalDevUser } from './utils/localDevAuth';
import {
  clearAuthSession,
  decodeAuthToken,
  migrateLegacyAuthSession,
  normalizeSessionRole,
  roleForRoute,
  routeForRole,
  setAuthSession,
} from './services/authSession';

import { BrowserRouter as Router, useLocation, useNavigate } from 'react-router-dom';
import { NotificationProvider, useNotification } from './services/NotificationContext';

const normalizeAppRole = normalizeSessionRole;

function AppContent() {
  const [user, setUser] = useState(null);
  const [isRestoringSession, setIsRestoringSession] = useState(true);
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatUnreadTotal, setChatUnreadTotal] = useState(0);
  const [latestChatNotice, setLatestChatNotice] = useState(null);
  const [chatAutoOpenTarget, setChatAutoOpenTarget] = useState(null);
  const { addNotification } = useNotification();
  const location = useLocation();
  const navigate = useNavigate();
  const restorationStarted = useRef(false);

  const handleLoginSuccess = useCallback(async (token) => {
    try {
      const payload = decodeAuthToken(token);
      const localDevUser = getLocalDevUser(payload);
      if (localDevUser) {
        setAuthSession(token, localDevUser.role);
        setUser(localDevUser);
        navigate(routeForRole(localDevUser.role), { replace: true });
        return;
      }

      const email = payload.username || payload.email || payload['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'];
      const dbRole = normalizeAppRole(payload.dbRole || payload.role || payload['http://schemas.microsoft.com/ws/2008/06/identity/claims/role']);
      setAuthSession(token, dbRole);

      const profileResponse = await fetchUserProfile(email, dbRole);

      if (profileResponse.status === 'Success' && profileResponse.data) {
        const fetchedUser = profileResponse.data;
        const appRole = normalizeAppRole(fetchedUser.role || dbRole);
        setAuthSession(token, appRole);

        let displayName = fetchedUser.fullName;
        if (appRole === 'faculty') {
          displayName = `Prof. ${fetchedUser.fullName}`;
        } else if (appRole === 'department_admin') {
          displayName = `Dept Admin ${fetchedUser.fullName}`;
        } else if (appRole === 'registrar') {
          displayName = `Registrar ${fetchedUser.fullName}`;
        } else if (appRole === 'system_admin') {
          displayName = fetchedUser.fullName || 'System Administrator';
        }

        setUser({
          id: fetchedUser.id,
          name: displayName,
          email: fetchedUser.email,
          role: appRole,
          rawRole: fetchedUser.role,
          studentNo: fetchedUser.studentNo,
          dateOfBirth: fetchedUser.dateOfBirth,
          middleName: fetchedUser.middleName,
          sex: fetchedUser.sex,
          phone: fetchedUser.phone,
          studentEmail: fetchedUser.studentEmail,
          address: fetchedUser.address,
          department: fetchedUser.department,
          section: fetchedUser.section,
          yearLevel: fetchedUser.yearLevel,
          curriculumId: fetchedUser.curriculumId,
          curriculumName: fetchedUser.curriculumName,
          curriculumVersion: fetchedUser.curriculumVersion,
          schoolYear: fetchedUser.schoolYear,
          semester: fetchedUser.semester,
          enrollmentStatus: fetchedUser.enrollmentStatus,
          enrolledSubjects: fetchedUser.enrolledSubjects,
          facultyType: fetchedUser.facultyType,
          Classification: fetchedUser.facultyType || fetchedUser.classification,
          status: fetchedUser.status
        });
        navigate(routeForRole(appRole), { replace: true });
      } else {
        throw new Error("Failed to load user profile.");
      }
    } catch (error) {
      console.error("Error during login process:", error);
      clearAuthSession();
      setUser(null);
      navigate('/login', { replace: true });
      throw error;
    } finally {
      setIsRestoringSession(false);
    }
  }, [navigate]);

  useEffect(() => {
    if (restorationStarted.current) return undefined;
    restorationStarted.current = true;
    let active = true;
    const token = migrateLegacyAuthSession();
    if (!token) {
      setIsRestoringSession(false);
      const isPublicAuthRoute = location.pathname === '/login' || location.pathname.startsWith('/reset-password');
      if (!isPublicAuthRoute) navigate('/login', { replace: true });
      return () => { active = false; };
    }

    handleLoginSuccess(token).catch(() => {
      if (active) setIsRestoringSession(false);
    });
    return () => { active = false; };
  }, [handleLoginSuccess, location.pathname, navigate]);

  useEffect(() => {
    if (isRestoringSession || !user) return;
    const currentRouteRole = roleForRoute(location.pathname);
    const userRole = normalizeAppRole(user.role);
    if (currentRouteRole !== userRole) navigate(routeForRole(userRole), { replace: true });
  }, [isRestoringSession, location.pathname, navigate, user]);

  const handleLogout = () => {
    clearAuthSession();
    setUser(null);
    setChatUnreadTotal(0);
    setLatestChatNotice(null);
    setChatAutoOpenTarget(null);
    navigate('/login', { replace: true });
  };

  const handleNginxFailover = useCallback((nextOrigin) => {
    clearAuthSession();
    setUser(null);
    setChatUnreadTotal(0);
    setLatestChatNotice(null);
    setChatAutoOpenTarget(null);

    const from = encodeURIComponent(window.location.origin);
    window.location.replace(`${nextOrigin}/login?failover=nginx&from=${from}`);
  }, []);

  useEffect(() => {
    return startNginxFailoverMonitor({
      onFailover: handleNginxFailover,
    });
  }, [handleNginxFailover]);

  const handleUnreadChange = useCallback((totalUnread) => {
    setChatUnreadTotal(totalUnread);
  }, []);

  const handleIncomingMessage = useCallback(({ from, message, attachmentName }) => {
    const senderName = from ? from.split('@')[0] : 'A user';
    const chatPreview = message || (attachmentName ? `Sent ${attachmentName}` : 'Sent an attachment');
    const isRegistrar = normalizeAppRole(user?.role).includes('registrar');

    setLatestChatNotice({
      from: senderName,
      message: chatPreview,
      receivedAt: new Date().toISOString(),
    });

    if (isRegistrar && from) {
      setIsChatOpen(true);
      setChatAutoOpenTarget({ email: from, nonce: Date.now() });
    }
  }, [user?.role]);

  const handleRegistrationRequest = useCallback((request) => {
    const isRegistrar = normalizeAppRole(user?.role).includes('registrar');
    if (!isRegistrar) return;

    const name = request?.fullName || request?.FullName || request?.email || request?.Email || 'A new user';
    const role = request?.role || request?.Role || 'user';
    addNotification(`New registration request from ${name} (${role})`, 'success');
  }, [addNotification, user?.role]);

  const handleSupportNotice = useCallback((notice) => {
    const message = notice?.displayMessage || notice?.DisplayMessage;
    if (message) addNotification(message, 'notice');
  }, [addNotification]);

  const currentUserRole = normalizeAppRole(user?.role);
  const canUseChat = ['student', 'faculty', 'department_admin', 'registrar', 'system_admin'].includes(currentUserRole);

  return (
    <div className="main-app-wrapper">
      {isRestoringSession ? (
        <div className="flex min-h-screen items-center justify-center bg-slate-100 text-sm font-semibold text-slate-600">Restoring this tab's session...</div>
      ) : !user ? (
        <Login onLogin={handleLoginSuccess} />
      ) : (
        <>
          {/* Floating Chat Button */}
          {canUseChat && !isChatOpen && (
            <button 
              onClick={() => setIsChatOpen(true)} 
              style={{ position: 'fixed', bottom: '20px', right: '20px', zIndex: 1000, padding: '15px 25px', backgroundColor: '#003366', color: 'white', border: 'none', borderRadius: '30px', cursor: 'pointer', boxShadow: '0 4px 12px rgba(0,0,0,0.15)', fontWeight: 'bold', fontSize: '16px' }}>
              💬 Open Chat
            </button>
          )}
          {canUseChat && !isChatOpen && chatUnreadTotal > 0 && (
            <span
              style={{
                position: 'fixed',
                bottom: '52px',
                right: '18px',
                zIndex: 1001,
                display: 'inline-flex',
                minWidth: 22,
                height: 22,
                alignItems: 'center',
                justifyContent: 'center',
                borderRadius: 999,
                background: '#ef4444',
                color: 'white',
                fontSize: 12,
                fontWeight: 700,
                boxShadow: '0 2px 6px rgba(0,0,0,0.2)',
              }}
            >
              {chatUnreadTotal > 9 ? '9+' : chatUnreadTotal}
            </span>
          )}
          {canUseChat && <Chat
            userEmail={user.email}
            userRole={currentUserRole}
            isOpen={isChatOpen}
            onClose={() => setIsChatOpen(false)}
            onUnreadChange={handleUnreadChange}
            onIncomingMessage={handleIncomingMessage}
            onRegistrationRequest={handleRegistrationRequest}
            onSupportNotice={handleSupportNotice}
            autoOpenTarget={chatAutoOpenTarget}
          />}

          {currentUserRole === "student" ? (
            <StudentPortal studentData={user} onLogout={handleLogout} />
          ) : currentUserRole === "faculty" ? (
            <FacultyPortal facultyData={user} onLogout={handleLogout} />
          ) : currentUserRole === "department_admin" ? (
            <div style={{ position: 'relative', width: '100%', minHeight: '100vh', backgroundColor: '#f0f2f5' }}>
              <DeptAdminGradesView loggedInEmail={user.email ?? ''} loggedInName={user.name ?? ''} userRole={currentUserRole} department={user.department ?? ''} onLogout={handleLogout} />
            </div>
          ) : currentUserRole === "registrar" ? (
            <div style={{ position: 'relative', width: '100%', minHeight: '100vh', backgroundColor: '#f0f2f5' }}>
              <RegistrarGradesView
                loggedInEmail={user.email ?? ''}
                loggedInName={user.name ?? ''}
                chatUnreadCount={chatUnreadTotal}
                latestChatNotice={latestChatNotice}
                onOpenChat={() => setIsChatOpen(true)}
                onLogout={handleLogout}
              />
            </div>
          ) : currentUserRole === "system_admin" ? (
            <SystemAdminPortal
              adminData={user}
              onLogout={handleLogout}
              chatUnreadCount={chatUnreadTotal}
              onOpenChat={() => setIsChatOpen(true)}
            />
          ) : (
            <div style={{ position: 'relative', width: '100%', minHeight: '100vh', backgroundColor: '#f0f2f5' }}>
              <div style={{ position: 'absolute', top: '15px', right: '20px', zIndex: 10 }}>
                <button className="logout-btn" onClick={handleLogout} style={{ backgroundColor: '#003366', color: 'white', borderColor: '#003366', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer' }}>Logout</button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function App() {
  return (
    <NotificationProvider>
      <Router>
        <AppContent />
      </Router>
    </NotificationProvider>
  );
}

export default App;
