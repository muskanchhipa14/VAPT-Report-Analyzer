import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import { Shield, LayoutDashboard, AlertTriangle, BookOpen, LogOut, User, Code2, Lock, History } from 'lucide-react';

const Navbar = ({ user, onLogout }) => {
  const navigate = useNavigate();

  const handleLogout = async () => {
    await authAPI.logout();
    if (onLogout) onLogout();
    navigate('/login');
  };

  const userRole = (user?.role || 'user').toLowerCase();
  const isOfficer = ['cdac_officer', 'admin', 'officer', 'security_officer'].includes(userRole);
  const isAnalyst = ['security_analyst', 'auditor'].includes(userRole);
  const isSourceCodeAuthorized = isOfficer || isAnalyst;

  const navItems = [
    { name: 'Dashboard', path: '/', icon: <LayoutDashboard size={18} /> },
    {
      name: 'Source Code Scanner',
      path: '/source-code',
      icon: <Code2 size={18} />,
      restricted: !isSourceCodeAuthorized,
    },
    { name: 'Vulnerabilities', path: '/vulnerabilities', icon: <AlertTriangle size={18} /> },
    { name: 'Knowledge Base', path: '/knowledge-base', icon: <BookOpen size={18} /> },
    { name: 'Audit Logs', path: '/logs', icon: <History size={18} /> },
  ];

  const getRoleBadge = () => {
    if (isOfficer) {
      return (
        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30 flex items-center gap-1">
          <Shield size={10} className="text-amber-400" />
          <span>C-DAC Officer</span>
        </span>
      );
    }
    if (isAnalyst) {
      return (
        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center gap-1">
          <span>Security Analyst</span>
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-slate-800 text-slate-400 border border-slate-700 flex items-center gap-1">
        <Lock size={10} className="text-slate-400" />
        <span>Restricted User</span>
      </span>
    );
  };

  return (
    <nav className="border-b border-slate-800 bg-dark-900/80 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-8">
            {/* Logo */}
            <div className="flex items-center gap-2.5 cursor-pointer" onClick={() => navigate('/')}>
              <div className="p-1.5 bg-primary-500/10 border border-primary-500/20 rounded-lg text-primary-500">
                <Shield size={20} />
              </div>
              <div className="flex flex-col">
                <span className="font-outfit font-bold text-base text-white tracking-wide leading-tight">VAPT SHIELD</span>
                <span className="text-[9px] text-primary-400 font-semibold tracking-wider uppercase">C-DAC Gov Portal</span>
              </div>
            </div>

            {/* Nav items */}
            <div className="hidden md:flex items-center gap-1">
              {navItems.map((item) => (
                <NavLink
                  key={item.name}
                  to={item.path}
                  className={({ isActive }) =>
                    `flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-medium transition-all ${
                      isActive
                        ? 'bg-primary-500/10 text-primary-500 border border-primary-500/20'
                        : 'text-slate-400 hover:text-white hover:bg-slate-800/40 border border-transparent'
                    }`
                  }
                >
                  {item.icon}
                  <span>{item.name}</span>
                  {item.restricted && (
                    <span className="flex items-center text-slate-500 ml-0.5" title="Source Code clearance required">
                      <Lock size={12} />
                    </span>
                  )}
                </NavLink>
              ))}
            </div>
          </div>

          {/* User Profile & Logout */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-800/50 border border-slate-800 rounded-xl">
              <div className="w-6 h-6 rounded-full bg-primary-500/20 text-primary-400 border border-primary-500/30 flex items-center justify-center">
                <User size={12} />
              </div>
              <span className="text-slate-200 text-xs font-semibold">{user?.name || 'Security User'}</span>
              {getRoleBadge()}
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
