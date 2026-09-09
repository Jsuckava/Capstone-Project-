import React from 'react';
import StudentPortal from './StudentPortal';
import { useLocation } from 'react-router-dom';

const StudentLanding = ({ user, onLogout }) => {
  const location = useLocation();

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', color: 'white', padding: '40px 20px' }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        <header style={{ textAlign: 'center', marginBottom: '60px' }}>
          <h1 style={{ fontSize: '3rem', margin: 0, fontWeight: 'bold' }}>Student Portal</h1>
          <p style={{ fontSize: '1.2rem', opacity: 0.9 }}>Welcome back, {user.name}!</p>
          <div style={{ position: 'absolute', top: '20px', right: '20px' }}>
            <button onClick={onLogout} style={{ background: 'rgba(255,255,255,0.2)', color: 'white', border: '1px solid rgba(255,255,255,0.3)', padding: '10px 20px', borderRadius: '25px', cursor: 'pointer' }}>
              Logout
            </button>
          </div>
        </header>
        <StudentPortal studentData={user} onLogout={onLogout} />
      </div>
    </div>
  );
};

export default StudentLanding;

