import React, { useState, useEffect } from 'react';
import {
  getVulnerabilities,
  getVulnerability,
  createVulnerability,
  updateVulnerability,
  deleteVulnerability
} from '../services/api';

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Create Form State
  const [createForm, setCreateForm] = useState({
    report_name: '',
    vulnerability_name: '',
    severity: 'Medium',
    cwe_id: '',
    file_name: '',
    line_number: 1
  });

  // View Detail State
  const [viewingVuln, setViewingVuln] = useState(null);

  // Update State
  const [editingVuln, setEditingVuln] = useState(null);
  const [editForm, setEditForm] = useState({ severity: 'Medium', status: 'Open' });

  const loadVulns = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await getVulnerabilities();
      setVulns(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to fetch vulnerabilities.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadVulns();
  }, []);

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await createVulnerability({
        ...createForm,
        line_number: parseInt(createForm.line_number, 10) || 0
      });
      setCreateForm({
        report_name: '',
        vulnerability_name: '',
        severity: 'Medium',
        cwe_id: '',
        file_name: '',
        line_number: 1
      });
      loadVulns();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create vulnerability.');
    }
  };

  const handleViewVuln = async (id) => {
    try {
      const res = await getVulnerability(id);
      setViewingVuln(res.data);
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to fetch vulnerability details.');
    }
  };

  const handleStartEdit = (vuln) => {
    setEditingVuln(vuln);
    setEditForm({
      severity: vuln.severity || 'Medium',
      status: vuln.status || 'Open'
    });
  };

  const handleEditSubmit = async (e) => {
    e.preventDefault();
    if (!editingVuln) return;
    setError('');
    try {
      await updateVulnerability(editingVuln.id, editForm);
      setEditingVuln(null);
      loadVulns();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update vulnerability.');
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm(`Are you sure you want to delete vulnerability #${id}?`)) {
      try {
        await deleteVulnerability(id);
        loadVulns();
      } catch (err) {
        alert(err.response?.data?.detail || 'Failed to delete vulnerability.');
      }
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex justify-between items-center border-b border-slate-200/80 pb-4">
        <div>
          <h2 className="text-xl font-bold text-slate-800 tracking-tight flex items-center gap-2">
            <svg className="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Vulnerability Information
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">Track, review, and manage identified security flaws and CWE findings</p>
        </div>
        <button
          onClick={loadVulns}
          className="text-xs font-semibold bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 px-3.5 py-2 rounded-lg shadow-sm hover:shadow transition-all flex items-center gap-1.5"
        >
          <svg className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-indigo-600' : 'text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh
        </button>
      </div>

      {error && (
        <div className="bg-rose-50 border border-rose-200 text-rose-700 px-4 py-3 rounded-xl text-sm flex items-center gap-2 shadow-sm">
          <svg className="w-5 h-5 shrink-0 text-rose-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span>{error}</span>
        </div>
      )}

      {/* Create Form */}
      <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200/80">
        <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider mb-4 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-indigo-600"></span>
          Add Vulnerability Record
        </h3>
        <form onSubmit={handleCreateSubmit} className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">Report Name</label>
            <input
              type="text"
              required
              value={createForm.report_name}
              onChange={(e) => setCreateForm({ ...createForm, report_name: e.target.value })}
              className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all bg-slate-50/50"
              placeholder="e.g. Audit_2026.pdf"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">Vulnerability Name</label>
            <input
              type="text"
              required
              value={createForm.vulnerability_name}
              onChange={(e) => setCreateForm({ ...createForm, vulnerability_name: e.target.value })}
              className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all bg-slate-50/50"
              placeholder="e.g. SQL Injection"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">Severity</label>
            <select
              value={createForm.severity}
              onChange={(e) => setCreateForm({ ...createForm, severity: e.target.value })}
              className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all bg-slate-50/50 cursor-pointer"
            >
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Info">Info</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">CWE ID</label>
            <input
              type="text"
              required
              value={createForm.cwe_id}
              onChange={(e) => setCreateForm({ ...createForm, cwe_id: e.target.value })}
              className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all bg-slate-50/50 font-mono"
              placeholder="e.g. CWE-89"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">File Name</label>
            <input
              type="text"
              required
              value={createForm.file_name}
              onChange={(e) => setCreateForm({ ...createForm, file_name: e.target.value })}
              className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all bg-slate-50/50"
              placeholder="e.g. login.py"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">Line Number</label>
            <input
              type="number"
              required
              min="1"
              value={createForm.line_number}
              onChange={(e) => setCreateForm({ ...createForm, line_number: e.target.value })}
              className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all bg-slate-50/50"
            />
          </div>
          <div className="sm:col-span-3 flex justify-end pt-2">
            <button
              type="submit"
              className="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold px-5 py-2.5 rounded-lg text-sm shadow-sm hover:shadow-indigo-500/25 active:scale-[0.98] transition-all flex items-center gap-1.5"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
              </svg>
              Create Vulnerability
            </button>
          </div>
        </form>
      </div>

      {/* Table */}
      <div className="bg-white rounded-2xl shadow-sm border border-slate-200/80 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="bg-slate-50/90 border-b border-slate-200 text-slate-500 uppercase text-[11px] font-bold tracking-wider">
                <th className="py-3.5 px-4">ID</th>
                <th className="py-3.5 px-4">Vulnerability</th>
                <th className="py-3.5 px-4">Severity</th>
                <th className="py-3.5 px-4">CWE ID</th>
                <th className="py-3.5 px-4">File:Line</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan="7" className="py-8 text-center text-slate-400 font-medium">
                    <div className="flex items-center justify-center space-x-2">
                      <div className="w-4 h-4 border-2 border-indigo-600 border-t-transparent rounded-full animate-spin"></div>
                      <span>Loading vulnerabilities...</span>
                    </div>
                  </td>
                </tr>
              ) : vulns.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-8 text-center text-slate-400 font-medium">
                    No vulnerabilities recorded.
                  </td>
                </tr>
              ) : (
                vulns.map((v) => (
                  <tr key={v.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-3.5 px-4 font-mono text-xs text-slate-500 font-semibold">#{v.id}</td>
                    <td className="py-3.5 px-4 font-semibold text-slate-800">{v.vulnerability_name}</td>
                    <td className="py-3.5 px-4">
                      <span className={`text-xs px-2.5 py-1 rounded-md font-bold uppercase tracking-wider border ${
                        v.severity === 'Critical' ? 'bg-rose-100/90 text-rose-700 border-rose-200' :
                        v.severity === 'High' ? 'bg-orange-100/90 text-orange-700 border-orange-200' :
                        v.severity === 'Medium' ? 'bg-amber-100/90 text-amber-700 border-amber-200' :
                        v.severity === 'Low' ? 'bg-blue-100/90 text-blue-700 border-blue-200' :
                        'bg-slate-100 text-slate-700 border-slate-200'
                      }`}>
                        {v.severity}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="font-mono text-xs text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-100 font-medium">
                        {v.cwe_id}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-600 font-mono text-xs">
                      {v.file_name}:{v.line_number}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`text-xs px-2.5 py-0.5 rounded-md font-semibold border ${
                        v.status === 'Resolved' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' :
                        v.status === 'Ignored' ? 'bg-slate-100 text-slate-600 border-slate-200' :
                        'bg-rose-50 text-rose-700 border-rose-200'
                      }`}>
                        {v.status || 'Open'}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right space-x-1.5">
                      <button
                        onClick={() => handleViewVuln(v.id)}
                        className="text-indigo-600 hover:text-indigo-800 font-semibold text-xs px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 rounded-lg transition-colors"
                      >
                        Read
                      </button>
                      <button
                        onClick={() => handleStartEdit(v)}
                        className="text-amber-600 hover:text-amber-800 font-semibold text-xs px-3 py-1.5 bg-amber-50 hover:bg-amber-100 rounded-lg transition-colors"
                      >
                        Update
                      </button>
                      <button
                        onClick={() => handleDelete(v.id)}
                        className="text-rose-600 hover:text-rose-800 font-semibold text-xs px-3 py-1.5 bg-rose-50 hover:bg-rose-100 rounded-lg transition-colors"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Read Modal */}
      {viewingVuln && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-2xl border border-slate-100 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex justify-between items-center mb-4 pb-3 border-b border-slate-100">
              <h3 className="text-base font-bold text-slate-800 flex items-center gap-2">
                <svg className="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                Vulnerability Details
              </h3>
              <button onClick={() => setViewingVuln(null)} className="text-slate-400 hover:text-slate-600">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="space-y-3 text-sm text-slate-700 bg-slate-50 p-4 rounded-xl border border-slate-200/60">
              <p className="flex justify-between"><strong className="text-slate-500">ID:</strong> <span className="font-mono">#{viewingVuln.id}</span></p>
              <p className="flex justify-between"><strong className="text-slate-500">Report Name:</strong> <span className="font-medium text-slate-800">{viewingVuln.report_name}</span></p>
              <p className="flex justify-between"><strong className="text-slate-500">Vulnerability:</strong> <span className="font-semibold text-slate-800">{viewingVuln.vulnerability_name}</span></p>
              <p className="flex justify-between"><strong className="text-slate-500">Severity:</strong> <span className="font-bold text-rose-600">{viewingVuln.severity}</span></p>
              <p className="flex justify-between"><strong className="text-slate-500">CWE ID:</strong> <span className="font-mono text-xs text-indigo-600">{viewingVuln.cwe_id}</span></p>
              <p className="flex justify-between"><strong className="text-slate-500">Location:</strong> <span className="font-mono text-xs text-slate-700">{viewingVuln.file_name}:{viewingVuln.line_number}</span></p>
              <p className="flex justify-between"><strong className="text-slate-500">Status:</strong> <span className="font-semibold text-slate-800">{viewingVuln.status}</span></p>
            </div>
            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setViewingVuln(null)}
                className="bg-slate-800 hover:bg-slate-900 text-white font-semibold px-4 py-2 rounded-lg text-sm shadow-sm transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {editingVuln && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-2xl border border-slate-100 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex justify-between items-center mb-4 pb-3 border-b border-slate-100">
              <h3 className="text-base font-bold text-slate-800 flex items-center gap-2">
                <svg className="w-5 h-5 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>
                Update Vulnerability #{editingVuln.id}
              </h3>
              <button onClick={() => setEditingVuln(null)} className="text-slate-400 hover:text-slate-600">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1.5">Severity</label>
                <select
                  value={editForm.severity}
                  onChange={(e) => setEditForm({ ...editForm, severity: e.target.value })}
                  className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-amber-500/20 focus:border-amber-500 transition-all bg-slate-50/50 cursor-pointer"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                  <option value="Info">Info</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1.5">Status</label>
                <input
                  type="text"
                  required
                  value={editForm.status}
                  onChange={(e) => setEditForm({ ...editForm, status: e.target.value })}
                  className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-amber-500/20 focus:border-amber-500 transition-all bg-slate-50/50"
                  placeholder="e.g. Open, Resolved, Ignored"
                />
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setEditingVuln(null)}
                  className="bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold px-4 py-2 rounded-lg text-sm transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-amber-600 hover:bg-amber-700 text-white font-semibold px-4 py-2 rounded-lg text-sm shadow-sm transition-colors"
                >
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}