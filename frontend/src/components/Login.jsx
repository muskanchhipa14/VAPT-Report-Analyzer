import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authAPI } from '../services/api';
import { Shield, Lock, Mail, User, AlertCircle, Loader, CheckCircle } from 'lucide-react';

const Login = ({ onLoginSuccess }) => {
  const [isSignup, setIsSignup] = useState(false);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    if (isSignup) {
      if (password !== confirmPassword) {
        setError("Passwords do not match.");
        setLoading(false);
        return;
      }

      try {
        // Register user via backend POST /users/
        await authAPI.register(name, email, password);
        setSuccess('Registration successful! Please sign in with your credentials.');
        
        // Clear inputs
        setName('');
        setEmail('');
        setPassword('');
        setConfirmPassword('');
        
        // Switch back to Sign In mode after 2 seconds
        setTimeout(() => {
          setIsSignup(false);
          setSuccess('');
        }, 2000);
      } catch (err) {
        console.error(err);
        setError(err.response?.data?.detail || 'Registration failed. Email might already be registered.');
      } finally {
        setLoading(false);
      }
    } else {
      try {
        // Login via backend POST /auth/login
        const data = await authAPI.login(email, password);
        if (onLoginSuccess) onLoginSuccess(data.user);
        navigate('/');
      } catch (err) {
        console.error(err);
        setError(err.response?.data?.detail || 'Invalid email or password. Please try again.');
      } finally {
        setLoading(false);
      }
    }
  };

  const toggleMode = () => {
    setIsSignup(!isSignup);
    setError('');
    setSuccess('');
    setName('');
    setEmail('');
    setPassword('');
    setConfirmPassword('');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-dark-950 px-4">
      {/* Background glow effects */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary-600/10 rounded-full blur-[100px] pointer-events-none"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-indigo-500/5 rounded-full blur-[120px] pointer-events-none"></div>

      <div className="w-full max-w-md glass-panel rounded-2xl p-8 shadow-2xl relative z-10 border border-slate-800">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center p-3 bg-primary-500/10 border border-primary-500/20 rounded-xl text-primary-500 mb-4 pulse-indicator">
            <Shield size={36} />
          </div>
          <h1 className="text-2xl font-bold font-outfit text-white tracking-wide uppercase">VAPT SHIELD</h1>
          <p className="text-slate-400 text-sm mt-1">
            {isSignup ? 'Create a secure analyst account' : 'Sign in to access security reports & analysis'}
          </p>
        </div>

        {error && (
          <div className="mb-6 flex items-start gap-3 p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm">
            <AlertCircle size={18} className="shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div className="mb-6 flex items-start gap-3 p-4 bg-green-500/10 border border-green-500/20 rounded-xl text-green-400 text-sm">
            <CheckCircle size={18} className="shrink-0 mt-0.5" />
            <span>{success}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          {isSignup && (
            <div>
              <label className="block text-slate-300 text-xs font-semibold uppercase tracking-wider mb-2">Full Name</label>
              <div className="relative">
                <User size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  required
                  className="w-full bg-slate-900/50 border border-slate-800 focus:border-primary-500 focus:ring-1 focus:ring-primary-500 rounded-xl py-3 pl-10 pr-4 text-white placeholder-slate-500 outline-none transition-all"
                  placeholder="Security Engineer"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  disabled={loading}
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-slate-300 text-xs font-semibold uppercase tracking-wider mb-2">Email Address</label>
            <div className="relative">
              <Mail size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="email"
                required
                className="w-full bg-slate-900/50 border border-slate-800 focus:border-primary-500 focus:ring-1 focus:ring-primary-500 rounded-xl py-3 pl-10 pr-4 text-white placeholder-slate-500 outline-none transition-all"
                placeholder="name@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={loading}
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-300 text-xs font-semibold uppercase tracking-wider mb-2">Password</label>
            <div className="relative">
              <Lock size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="password"
                required
                className="w-full bg-slate-900/50 border border-slate-800 focus:border-primary-500 focus:ring-1 focus:ring-primary-500 rounded-xl py-3 pl-10 pr-4 text-white placeholder-slate-500 outline-none transition-all"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
              />
            </div>
          </div>

          {isSignup && (
            <div>
              <label className="block text-slate-300 text-xs font-semibold uppercase tracking-wider mb-2">Confirm Password</label>
              <div className="relative">
                <Lock size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="password"
                  required
                  className="w-full bg-slate-900/50 border border-slate-800 focus:border-primary-500 focus:ring-1 focus:ring-primary-500 rounded-xl py-3 pl-10 pr-4 text-white placeholder-slate-500 outline-none transition-all"
                  placeholder="••••••••"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  disabled={loading}
                />
              </div>
            </div>
          )}

          <div className="pt-2">
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-primary-600 hover:bg-primary-700 text-white font-semibold py-3 rounded-xl transition-all shadow-lg hover:shadow-primary-600/20 active:scale-[0.98] flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader size={18} className="animate-spin" />
                  <span>Please wait...</span>
                </>
              ) : (
                <span>{isSignup ? 'Create Account' : 'Sign In'}</span>
              )}
            </button>
          </div>
        </form>

        <div className="mt-6 text-center">
          <button
            onClick={toggleMode}
            className="text-xs text-primary-400 hover:text-primary-300 font-semibold focus:outline-none transition-colors"
          >
            {isSignup ? 'Already have an account? Sign In' : "Don't have an account? Sign Up"}
          </button>
        </div>


      </div>
    </div>
  );
};

export default Login;
