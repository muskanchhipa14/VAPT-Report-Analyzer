import React, { useState, useEffect } from 'react';
import {
  getKnowledgeBase,
  getKnowledgeBaseEntry,
  createKnowledgeBase,
  updateKnowledgeBase,
  deleteKnowledgeBase
} from '../services/api';

export default function KnowledgeBase() {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Create Form State
  const [createForm, setCreateForm] = useState({
    vulnerability_name: '',
    cwe_id: '',
    severity: 'Medium',
    description: '',
    remediation: ''
  });

  // View Detail State
  const [viewingEntry, setViewingEntry] = useState(null);

  // Update State
  const [editingEntry, setEditingEntry] = useState(null);
  const [editForm, setEditForm] = useState({
    vulnerability_name: '',
    cwe_id: '',
    severity: 'Medium',
    description: '',
    remediation: ''
  });

  const loadEntries = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await getKnowledgeBase();
      setEntries(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to fetch knowledge base entries.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEntries();
  }, []);

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await createKnowledgeBase(createForm);
      setCreateForm({
        vulnerability_name: '',
        cwe_id: '',
        severity: 'Medium',
        description: '',
        remediation: ''
      });
      loadEntries();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to add Knowledge Base entry.');
    }
  };

  const handleViewEntry = async (id) => {
    try {
      const res = await getKnowledgeBaseEntry(id);
      setViewingEntry(res.data);
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to fetch entry details.');
    }
  };

  const handleStartEdit = (entry) => {
    setEditingEntry(entry);
    setEditForm({
      vulnerability_name: entry.vulnerability_name || '',
      cwe_id: entry.cwe_id || '',
      severity: entry.severity || 'Medium',
      description: entry.description || '',
      remediation: entry.remediation || ''
    });
  };

  const handleEditSubmit = async (e) => {
    e.preventDefault();
    if (!editingEntry) return;
    setError('');
    try {
      await updateKnowledgeBase(editingEntry.id, editForm);
      setEditingEntry(null);
      loadEntries();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update Knowledge Base entry.');
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm(`Are you sure you want to delete entry #${id}?`)) {
      try {
        await deleteKnowledgeBase(id);
        loadEntries();
      } catch (err) {
        alert(err.response?.data?.detail || 'Failed to delete entry.');
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
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
            </svg>
            Knowledge Base
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">Central repository for security advisories, vulnerability descriptions, and remediations</p>
        </div>
        <button
          onClick={loadEntries}
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

      {/* Create Entry Form */}
      <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200/80">
        <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider mb-4 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-indigo-600"></span>
          Add Knowledge Base Entry
        </h3>
        <form onSubmit={handleCreateSubmit} className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">Vulnerability Name</label>
            <input
              type="text"
              required
              value={createForm.vulnerability_name}
              onChange={(e) => setCreateForm({ ...createForm, vulnerability_name: e.target.value })}
              className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all bg-slate-50/50"
              placeholder="e.g. Cross-Site Scripting"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">CWE ID</label>
            <input
              type="text"
              required
              value={createForm.cwe_id}
              onChange={(e) => setCreateForm({ ...createForm, cwe_id: e.target.value })}
              className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all bg-slate-50/50 font-mono"
              placeholder="e.g. CWE-79"
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
          <div className="sm:col-span-3">
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">Description</label>
            <textarea
              required
              rows="2"
              value={createForm.description}
              onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
              className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all bg-slate-50/50"
              placeholder="Description of the vulnerability"
            />
          </div>
          <div className="sm:col-span-3">
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">Remediation</label>
            <textarea
              required
              rows="2"
              value={createForm.remediation}
              onChange={(e) => setCreateForm({ ...createForm, remediation: e.target.value })}
              className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all bg-slate-50/50"
              placeholder="Recommended fix or mitigation steps"
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
              Add Entry
            </button>
          </div>
        </form>
      </div>

      {/* Entries Table */}
      <div className="bg-white rounded-2xl shadow-sm border border-slate-200/80 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="bg-slate-50/90 border-b border-slate-200 text-slate-500 uppercase text-[11px] font-bold tracking-wider">
                <th className="py-3.5 px-4">ID</th>
                <th className="py-3.5 px-4">Vulnerability Name</th>
                <th className="py-3.5 px-4">CWE ID</th>
                <th className="py-3.5 px-4">Severity</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan="5" className="py-8 text-center text-slate-400 font-medium">
                    <div className="flex items-center justify-center space-x-2">
                      <div className="w-4 h-4 border-2 border-indigo-600 border-t-transparent rounded-full animate-spin"></div>
                      <span>Loading entries...</span>
                    </div>
                  </td>
                </tr>
              ) : entries.length === 0 ? (
                <tr>
                  <td colSpan="5" className="py-8 text-center text-slate-400 font-medium">
                    No Knowledge Base entries found.
                  </td>
                </tr>
              ) : (
                entries.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-3.5 px-4 font-mono text-xs text-slate-500 font-semibold">#{item.id}</td>
                    <td className="py-3.5 px-4 font-semibold text-slate-800">{item.vulnerability_name}</td>
                    <td className="py-3.5 px-4">
                      <span className="font-mono text-xs text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-100 font-medium">
                        {item.cwe_id}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`text-xs px-2.5 py-1 rounded-md font-bold uppercase tracking-wider border ${
                        item.severity === 'Critical' ? 'bg-rose-100/90 text-rose-700 border-rose-200' :
                        item.severity === 'High' ? 'bg-orange-100/90 text-orange-700 border-orange-200' :
                        item.severity === 'Medium' ? 'bg-amber-100/90 text-amber-700 border-amber-200' :
                        item.severity === 'Low' ? 'bg-blue-100/90 text-blue-700 border-blue-200' :
                        'bg-slate-100 text-slate-700 border-slate-200'
                      }`}>
                        {item.severity}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right space-x-1.5">
                      <button
                        onClick={() => handleViewEntry(item.id)}
                        className="text-indigo-600 hover:text-indigo-800 font-semibold text-xs px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 rounded-lg transition-colors"
                      >
                        Read
                      </button>
                      <button
                        onClick={() => handleStartEdit(item)}
                        className="text-amber-600 hover:text-amber-800 font-semibold text-xs px-3 py-1.5 bg-amber-50 hover:bg-amber-100 rounded-lg transition-colors"
                      >
                        Update
                      </button>
                      <button
                        onClick={() => handleDelete(item.id)}
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

      {/* Read Detail Modal */}
      {viewingEntry && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-6 max-w-xl w-full shadow-2xl border border-slate-100 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex justify-between items-center mb-4 pb-3 border-b border-slate-100">
              <h3 className="text-base font-bold text-slate-800 flex items-center gap-2">
                <svg className="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                </svg>
                Knowledge Base Entry #{viewingEntry.id}
              </h3>
              <button onClick={() => setViewingEntry(null)} className="text-slate-400 hover:text-slate-600">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="space-y-3.5 text-sm text-slate-700">
              <div className="flex justify-between items-center bg-slate-50 p-3 rounded-xl border border-slate-200/60">
                <div>
                  <span className="text-xs text-slate-400 block font-semibold">Vulnerability</span>
                  <span className="font-bold text-slate-800">{viewingEntry.vulnerability_name}</span>
                </div>
                <div className="text-right">
                  <span className="text-xs text-slate-400 block font-semibold">CWE / Severity</span>
                  <span className="font-mono text-xs text-indigo-600 font-bold mr-2">{viewingEntry.cwe_id}</span>
                  <span className="font-bold text-xs text-rose-600">{viewingEntry.severity}</span>
                </div>
              </div>
              
              <div>
                <strong className="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1">Description</strong>
                <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200/60 text-slate-700 text-xs leading-relaxed">
                  {viewingEntry.description}
                </div>
              </div>
              <div>
                <strong className="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1">Remediation Guidance</strong>
                <div className="bg-slate-900 text-indigo-200 p-3.5 rounded-xl border border-slate-800 text-xs leading-relaxed font-mono">
                  {viewingEntry.remediation}
                </div>
              </div>
            </div>
            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setViewingEntry(null)}
                className="bg-slate-800 hover:bg-slate-900 text-white font-semibold px-4 py-2 rounded-lg text-sm shadow-sm transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Entry Modal */}
      {editingEntry && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-6 max-w-lg w-full shadow-2xl border border-slate-100 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex justify-between items-center mb-4 pb-3 border-b border-slate-100">
              <h3 className="text-base font-bold text-slate-800 flex items-center gap-2">
                <svg className="w-5 h-5 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>
                Update Knowledge Base Entry #{editingEntry.id}
              </h3>
              <button onClick={() => setEditingEntry(null)} className="text-slate-400 hover:text-slate-600">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1.5">Vulnerability Name</label>
                <input
                  type="text"
                  required
                  value={editForm.vulnerability_name}
                  onChange={(e) => setEditForm({ ...editForm, vulnerability_name: e.target.value })}
                  className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-amber-500/20 focus:border-amber-500 transition-all bg-slate-50/50"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1.5">CWE ID</label>
                <input
                  type="text"
                  required
                  value={editForm.cwe_id}
                  onChange={(e) => setEditForm({ ...editForm, cwe_id: e.target.value })}
                  className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-amber-500/20 focus:border-amber-500 transition-all bg-slate-50/50 font-mono"
                />
              </div>
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
                <label className="block text-xs font-semibold text-slate-600 mb-1.5">Description</label>
                <textarea
                  required
                  rows="2"
                  value={editForm.description}
                  onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                  className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-amber-500/20 focus:border-amber-500 transition-all bg-slate-50/50"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1.5">Remediation</label>
                <textarea
                  required
                  rows="2"
                  value={editForm.remediation}
                  onChange={(e) => setEditForm({ ...editForm, remediation: e.target.value })}
                  className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-amber-500/20 focus:border-amber-500 transition-all bg-slate-50/50"
                />
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setEditingEntry(null)}
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