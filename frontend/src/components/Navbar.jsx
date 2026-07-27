import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import { Shield, LayoutDashboard, AlertTriangle, BookOpen, ClipboardList, LogOut, User } from 'lucide-react';

const Navbar = ({ user, onLogout }) => {
  const navigate = useNavigate();

  const handleLogout = async () => {
    await authAPI.logout();
    if (onLogout) onLogout();
    navigate('/login');
  };

  const navItems = [
    { name: 'Dashboard', path: '/', icon: <LayoutDashboard size={18} /> },
    { name: 'Vulnerabilities', path: '/vulnerabilities', icon: <AlertTriangle size={18} /> },
    { name: 'Knowledge Base', path: '/knowledge-base', icon: <BookOpen size={18} /> },
    { name: 'Audit Logs', path: '/logs', icon: <ClipboardList size={18} /> },
  ];

  return (
    <nav className="border-b border-slate-800 bg-dark-900/80 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-8">
            {/* Logo */}
            <div className="flex items-center gap-2 cursor-pointer" onClick={() => navigate('/')}>
              <div className="p-1.5 bg-primary-500/10 border border-primary-500/20 rounded-lg text-primary-500">
                <Shield size={20} />
              </div>
              <span className="font-outfit font-bold text-lg text-white tracking-wide">VAPT SHIELD</span>
            </div>

            {/* Nav items */}
            <div className="hidden md:flex items-center gap-1">
              {navItems.map((item) => (
                <NavLink
                  key={item.name}
                  to={item.path}
                  className={({ isActive }) =>
                    `flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all ${
                      isActive
                        ? 'bg-primary-500/10 text-primary-500 border border-primary-500/20'
                        : 'text-slate-400 hover:text-white hover:bg-slate-800/40 border border-transparent'
                    }`
                  }
                >
                  {item.icon}
                  <span>{item.name}</span>
                </NavLink>
              ))}
            </div>
          </div>

          {/* User Profile & Logout */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-800/40 border border-slate-800 rounded-xl">
              <div className="w-6 h-6 rounded-full bg-primary-500/20 text-primary-400 border border-primary-500/30 flex items-center justify-center">
                <User size={12} />
              </div>
              <span className="text-slate-300 text-xs font-semibold">{user?.name || 'Security User'}</span>
            </div>

            <button
              onClick={handleLogout}
              className="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/5 rounded-xl border border-transparent hover:border-red-500/10 transition-all active:scale-95"
              title="Logout"
            >
              <LogOut size={18} />
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
