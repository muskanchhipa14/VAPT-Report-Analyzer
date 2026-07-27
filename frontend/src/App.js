import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import Dashboard from './components/Dashboard';
import VulnerabilityList from './components/VulnerabilityList';
import KnowledgeBase from './components/KnowledgeBase';
import AuditLogs from './components/AuditLogs';
import Login from './components/Login';

// Private Route Wrapper Component
const PrivateRoute = ({ children, user }) => {
  const token = localStorage.getItem('token');
  return token ? children : <Navigate to="/login" replace />;
};

function App() {
  const [user, setUser] = useState(null);
  const [checkingAuth, setCheckingAuth] = useState(true);

  useEffect(() => {
    // Check if user is logged in
    const storedUser = localStorage.getItem('user');
    const token = localStorage.getItem('token');
    
    if (storedUser && token) {
      try {
        setUser(JSON.parse(storedUser));
      } catch (e) {
        localStorage.removeItem('user');
        localStorage.removeItem('token');
      }
    }
    setCheckingAuth(false);
  }, []);

  const handleLoginSuccess = (userData) => {
    setUser(userData);
  };

  const handleLogout = () => {
    setUser(null);
  };

  if (checkingAuth) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-dark-950 text-slate-500">
        <span>Initializing VAPT Shield...</span>
      </div>
    );
  }

  return (
    <Router>
      <div className="min-h-screen bg-dark-950 flex flex-col font-sans">
        <Routes>
          {/* Public Login Route */}
          <Route 
            path="/login" 
            element={
              localStorage.getItem('token') ? (
                <Navigate to="/" replace />
              ) : (
                <Login onLoginSuccess={handleLoginSuccess} />
              )
            } 
          />

          {/* Private Routes */}
          <Route
            path="/*"
            element={
              <PrivateRoute user={user}>
                <div className="flex flex-col min-h-screen">
                  <Navbar user={user} onLogout={handleLogout} />
                  <main className="flex-1 bg-dark-950">
                    <Routes>
                      <Route path="/" element={<Dashboard />} />
                      <Route path="/vulnerabilities" element={<VulnerabilityList />} />
                      <Route path="/knowledge-base" element={<KnowledgeBase />} />
                      <Route path="/logs" element={<AuditLogs />} />
                      <Route path="*" element={<Navigate to="/" replace />} />
                    </Routes>
                  </main>
                </div>
              </PrivateRoute>
            }
          />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
