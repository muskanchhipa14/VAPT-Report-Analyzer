import React, { useState, useEffect } from 'react';
import { auditAPI } from '../services/api';
import { Search, Calendar, ShieldCheck, ShieldAlert, Loader2 } from 'lucide-react';

const AuditLogs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const data = await auditAPI.getLogs();
      // Sort logs descending by timestamp
      const sortedLogs = data.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      setLogs(sortedLogs);
    } catch (e) {
      console.error("Failed to load audit logs", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const filteredLogs = logs.filter(log =>
    log.user_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.module.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.status.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const formatTimestamp = (timestampString) => {
    try {
      const date = new Date(timestampString);
      return date.toLocaleString();
    } catch (e) {
      return timestampString;
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold font-outfit text-white tracking-wide">Security Audit Logs</h1>
          <p className="text-slate-400 text-sm mt-1">Review chronological records of system actions and administration operations.</p>
        </div>
      </div>

      {/* Search Bar */}
      <div className="relative mb-6">
        <Search size={18} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
        <input
          type="text"
          className="w-full max-w-md bg-slate-900 border border-slate-800 focus:border-primary-500 rounded-xl py-3 pl-11 pr-4 text-white placeholder-slate-500 outline-none transition-colors"
          placeholder="Search by user, action, module, status..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </div>

      {loading ? (
        <div className="flex flex-col items-center justify-center py-32 text-slate-500">
          <Loader2 size={36} className="animate-spin text-primary-500 mb-4" />
          <span>Loading audit logs trail...</span>
        </div>
      ) : (
        <div className="glass-panel rounded-2xl overflow-hidden border border-slate-800/80">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-900/40 text-slate-400 text-xs font-semibold uppercase tracking-wider border-b border-slate-800/50">
                  <th className="px-6 py-4">User</th>
                  <th className="px-6 py-4">Action</th>
                  <th className="px-6 py-4">Module</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {filteredLogs.length > 0 ? (
                  filteredLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-800/5 transition-colors">
                      <td className="px-6 py-4">
                        <span className="text-slate-200 text-sm font-semibold">{log.user_name}</span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-slate-300 text-sm font-medium">{log.action}</span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-slate-400 text-sm">{log.module}</span>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                          log.status.toLowerCase() === 'success'
                            ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                            : 'bg-red-500/10 text-red-400 border border-red-500/20'
                        }`}>
                          {log.status.toLowerCase() === 'success'
                            ? <ShieldCheck size={12} className="shrink-0" />
                            : <ShieldAlert size={12} className="shrink-0" />
                          }
                          <span>{log.status}</span>
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-1.5 text-slate-400 text-xs">
                          <Calendar size={13} className="shrink-0 text-slate-500" />
                          <span>{formatTimestamp(log.timestamp)}</span>
                        </div>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="5" className="text-center py-16 text-slate-500 text-sm">
                      No audit logs matches found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default AuditLogs;
