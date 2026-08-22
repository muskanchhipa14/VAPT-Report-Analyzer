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

  // Filter States
  const [filterSeverity, setFilterSeverity] = useState('All');
  const [filterStatus, setFilterStatus] = useState('All');
  const [filterCwe, setFilterCwe] = useState('');
  const [filterName, setFilterName] = useState('');

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

  // Apply client-side filters
  const filteredVulns = vulns.filter(v => {
    const matchesSeverity = filterSeverity === 'All' || v.severity === filterSeverity;
    const matchesStatus = filterStatus === 'All' || 
      (v.status || 'Open').toLowerCase() === filterStatus.toLowerCase();
    const matchesCwe = !filterCwe || 
      v.cwe_id.toLowerCase().includes(filterCwe.toLowerCase());
    const matchesName = !filterName || 
      v.vulnerability_name.toLowerCase().includes(filterName.toLowerCase());
    
    return matchesSeverity && matchesStatus && matchesCwe && matchesName;
  });

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center border-b pb-3">
        <div>
          <h2 className="text-xl font-bold text-slate-800">Vulnerability Registry</h2>
          <p className="text-xs text-gray-500">Query and manage detected vulnerabilities across reports</p>
        </div>
        <button
          onClick={loadVulns}
          className="text-sm bg-gray-200 hover:bg-gray-300 text-gray-700 px-4 py-2 rounded-xl transition-all font-medium"
        >
          Refresh Registry
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl text-sm shadow-sm">
          {error}
        </div>
      )}

      {/* Filter panel */}
      <div className="bg-white p-5 rounded-2xl shadow-sm border border-gray-200 space-y-4">
        <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Search and Filters</h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Vulnerability Name</label>
            <input
              type="text"
              value={filterName}
              onChange={(e) => setFilterName(e.target.value)}
              className="w-full border border-gray-300 rounded-xl px-3.5 py-2 text-sm bg-gray-50 focus:outline-none"
              placeholder="Search name..."
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">CWE ID</label>
            <input
              type="text"
              value={filterCwe}
              onChange={(e) => setFilterCwe(e.target.value)}
              className="w-full border border-gray-300 rounded-xl px-3.5 py-2 text-sm bg-gray-50 focus:outline-none"
              placeholder="Search CWE..."
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Severity</label>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="w-full border border-gray-300 rounded-xl px-3.5 py-2 text-sm bg-gray-50 focus:outline-none"
            >
              <option value="All">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Status</label>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="w-full border border-gray-300 rounded-xl px-3.5 py-2 text-sm bg-gray-50 focus:outline-none"
            >
              <option value="All">All Statuses</option>
              <option value="Open">Open</option>
              <option value="Closed">Closed / Resolved</option>
            </select>
          </div>
        </div>
      </div>

      {/* Create Form */}
      <div className="bg-white p-5 rounded-2xl shadow-sm border border-gray-200">
        <h3 className="text-sm font-bold text-slate-800 mb-3">Add Vulnerability Record</h3>
        <form onSubmit={handleCreateSubmit} className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Report Name</label>
            <input
              type="text"
              required
              value={createForm.report_name}
              onChange={(e) => setCreateForm({ ...createForm, report_name: e.target.value })}
              className="w-full border border-gray-300 rounded-xl px-3.5 py-2.5 text-sm bg-gray-50 focus:outline-none"
              placeholder="e.g. Audit_2026.pdf"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Vulnerability Name</label>
            <input
              type="text"
              required
              value={createForm.vulnerability_name}
              onChange={(e) => setCreateForm({ ...createForm, vulnerability_name: e.target.value })}
              className="w-full border border-gray-300 rounded-xl px-3.5 py-2.5 text-sm bg-gray-50 focus:outline-none"
              placeholder="e.g. SQL Injection"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Severity</label>
            <select
              value={createForm.severity}
              onChange={(e) => setCreateForm({ ...createForm, severity: e.target.value })}
              className="w-full border border-gray-300 rounded-xl px-3.5 py-2.5 text-sm bg-gray-50 focus:outline-none bg-white"
            >
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">CWE ID</label>
            <input
              type="text"
              required
              value={createForm.cwe_id}
              onChange={(e) => setCreateForm({ ...createForm, cwe_id: e.target.value })}
              className="w-full border border-gray-300 rounded-xl px-3.5 py-2.5 text-sm bg-gray-50 focus:outline-none"
              placeholder="e.g. CWE-89"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">File Name</label>
            <input
              type="text"
              required
              value={createForm.file_name}
              onChange={(e) => setCreateForm({ ...createForm, file_name: e.target.value })}
              className="w-full border border-gray-300 rounded-xl px-3.5 py-2.5 text-sm bg-gray-50 focus:outline-none"
              placeholder="e.g. login.py"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Line Number</label>
            <input
              type="number"
              required
              min="1"
              value={createForm.line_number}
              onChange={(e) => setCreateForm({ ...createForm, line_number: e.target.value })}
              className="w-full border border-gray-300 rounded-xl px-3.5 py-2.5 text-sm bg-gray-50 focus:outline-none"
            />
          </div>
          <div className="sm:col-span-3 flex justify-end">
            <button
              type="submit"
              className="bg-blue-600 hover:bg-blue-700 text-white font-semibold px-5 py-2.5 rounded-xl text-sm transition-all"
            >
              Create Vulnerability
            </button>
          </div>
        </form>
      </div>

      {/* Table */}
      <div className="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden">
        <table className="w-full text-left border-collapse text-sm">
          <thead>
            <tr className="bg-gray-50/60 border-b border-gray-200 text-gray-500 uppercase text-[11px] font-bold tracking-wider">
              <th className="py-3 px-5">ID</th>
              <th className="py-3 px-5">Name</th>
              <th className="py-3 px-5">Severity</th>
              <th className="py-3 px-5">CWE ID</th>
              <th className="py-3 px-5">File : Line Reference</th>
              <th className="py-3 px-5">Status</th>
              <th className="py-3 px-5 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="7" className="py-8 text-center text-gray-500">Loading vulnerabilities...</td>
              </tr>
            ) : filteredVulns.length === 0 ? (
              <tr>
                <td colSpan="7" className="py-8 text-center text-gray-500">No vulnerabilities recorded matching the filters.</td>
              </tr>
            ) : (
              filteredVulns.map((v) => (
                <tr key={v.id} className="border-b border-gray-100 hover:bg-gray-50/50 transition-colors">
                  <td className="py-3.5 px-5 font-mono text-gray-500 text-xs">{v.id}</td>
                  <td className="py-3.5 px-5 font-medium text-slate-800">{v.vulnerability_name}</td>
                  <td className="py-3.5 px-5">
                    <span className={`text-[10px] px-2.5 py-0.5 rounded-full font-bold border ${
                      v.severity === 'Critical' ? 'bg-purple-50 text-purple-700 border-purple-200' :
                      v.severity === 'High' ? 'bg-red-50 text-red-700 border-red-200' :
                      v.severity === 'Medium' ? 'bg-amber-50 text-amber-700 border-amber-200' : 'bg-gray-50 text-gray-700 border-gray-200'
                    }`}>
                      {v.severity}
                    </span>
                  </td>
                  <td className="py-3.5 px-5 font-mono text-gray-500 text-xs">{v.cwe_id}</td>
                  <td className="py-3.5 px-5 text-slate-600 font-mono text-xs">
                    {v.file_name} : <span className="font-semibold text-slate-800">{v.line_number}</span>
                  </td>
                  <td className="py-3.5 px-5">
                    <span className={`text-[10px] px-2 py-0.5 rounded font-semibold ${
                      (v.status || 'Open').toLowerCase() === 'open' ? 'bg-amber-100 text-amber-800' : 'bg-emerald-100 text-emerald-800'
                    }`}>
                      {v.status || 'Open'}
                    </span>
                  </td>
                  <td className="py-3.5 px-5 text-right space-x-1">
                    <button
                      onClick={() => handleViewVuln(v.id)}
                      className="text-blue-600 hover:text-blue-800 font-semibold text-xs px-2.5 py-1 hover:bg-blue-50 rounded-lg transition-colors"
                    >
                      Read Details
                    </button>
                    <button
                      onClick={() => handleStartEdit(v)}
                      className="text-amber-600 hover:text-amber-800 font-semibold text-xs px-2.5 py-1 hover:bg-amber-50 rounded-lg transition-colors"
                    >
                      Update
                    </button>
                    <button
                      onClick={() => handleDelete(v.id)}
                      className="text-red-600 hover:text-red-800 font-semibold text-xs px-2.5 py-1 hover:bg-red-50 rounded-lg transition-colors"
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

      {/* Read Modal */}
      {viewingVuln && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50 backdrop-blur-sm">
          <div className="bg-white rounded-2xl p-6 max-w-xl w-full shadow-xl border border-gray-100">
            <div className="flex justify-between items-center border-b pb-3 mb-4">
              <h3 className="text-lg font-bold text-slate-800">Vulnerability Details</h3>
              <span className={`text-xs font-bold px-3 py-0.5 rounded-full border ${
                viewingVuln.severity === 'Critical' ? 'bg-purple-50 text-purple-700 border-purple-200' :
                viewingVuln.severity === 'High' ? 'bg-red-50 text-red-700 border-red-200' :
                viewingVuln.severity === 'Medium' ? 'bg-amber-50 text-amber-700 border-amber-200' : 'bg-gray-50 text-gray-700 border-gray-200'
              }`}>
                {viewingVuln.severity}
              </span>
            </div>
            
            <div className="space-y-4 text-sm text-slate-600">
              <div className="grid grid-cols-2 gap-4 bg-gray-50 p-4 rounded-xl border border-gray-100 text-xs">
                <p><strong>Vulnerability ID:</strong> #{viewingVuln.id}</p>
                <p><strong>Report:</strong> {viewingVuln.report_name}</p>
                <p><strong>CWE ID:</strong> <span className="font-mono">{viewingVuln.cwe_id}</span></p>
                <p><strong>File : Line:</strong> <span className="font-mono text-slate-800">{viewingVuln.file_name} : {viewingVuln.line_number}</span></p>
                <p className="col-span-2"><strong>Status:</strong> <span className="font-semibold text-slate-800">{viewingVuln.status}</span></p>
              </div>

              <div>
                <strong className="text-xs font-bold text-gray-400 uppercase tracking-wider">Description</strong>
                <p className="mt-1 bg-slate-50 p-3.5 rounded-xl text-slate-700 text-xs leading-relaxed border border-slate-100">{viewingVuln.description}</p>
              </div>

              <div>
                <strong className="text-xs font-bold text-gray-400 uppercase tracking-wider">Remediation Steps</strong>
                <p className="mt-1 bg-emerald-50/50 p-3.5 rounded-xl text-emerald-800 text-xs leading-relaxed border border-emerald-100">{viewingVuln.remediation}</p>
              </div>
            </div>

            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setViewingVuln(null)}
                className="bg-slate-800 hover:bg-slate-900 text-white font-semibold px-4 py-2 rounded-xl text-sm transition-all"
              >
                Close Details
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {editingVuln && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50 backdrop-blur-sm">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-xl border border-gray-100">
            <h3 className="text-lg font-bold text-slate-800 mb-4">Update Vulnerability Status</h3>
            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-600 mb-1.5">Severity</label>
                <select
                  value={editForm.severity}
                  onChange={(e) => setEditForm({ ...editForm, severity: e.target.value })}
                  className="w-full border border-gray-300 rounded-xl px-3 py-2 text-sm focus:outline-none bg-white"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-semibold text-gray-600 mb-1.5">Status</label>
                <select
                  value={editForm.status}
                  onChange={(e) => setEditForm({ ...editForm, status: e.target.value })}
                  className="w-full border border-gray-300 rounded-xl px-3 py-2 text-sm focus:outline-none bg-white"
                >
                  <option value="Open">Open</option>
                  <option value="Closed">Closed</option>
                  <option value="Resolved">Resolved</option>
                </select>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setEditingVuln(null)}
                  className="bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-xl text-sm font-medium transition-all"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-amber-600 hover:bg-amber-700 text-white px-4 py-2 rounded-xl text-sm font-semibold transition-all shadow-md shadow-amber-500/10"
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