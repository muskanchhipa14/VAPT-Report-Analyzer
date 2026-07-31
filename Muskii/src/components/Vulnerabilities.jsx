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
      <div className="flex justify-between items-center border-b pb-3">
        <h2 className="text-xl font-bold text-slate-800">Vulnerability Information</h2>
        <button
          onClick={loadVulns}
          className="text-sm bg-gray-200 hover:bg-gray-300 text-gray-700 px-3 py-1.5 rounded"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm">
          {error}
        </div>
      )}

      {/* Create Form */}
      <div className="bg-white p-5 rounded-lg shadow-sm border border-gray-200">
        <h3 className="text-md font-semibold text-gray-700 mb-3">Add Vulnerability Record</h3>
        <form onSubmit={handleCreateSubmit} className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Report Name</label>
            <input
              type="text"
              required
              value={createForm.report_name}
              onChange={(e) => setCreateForm({ ...createForm, report_name: e.target.value })}
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
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
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
              placeholder="e.g. SQL Injection"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Severity</label>
            <select
              value={createForm.severity}
              onChange={(e) => setCreateForm({ ...createForm, severity: e.target.value })}
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none bg-white"
            >
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Info">Info</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">CWE ID</label>
            <input
              type="text"
              required
              value={createForm.cwe_id}
              onChange={(e) => setCreateForm({ ...createForm, cwe_id: e.target.value })}
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
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
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
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
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
            />
          </div>
          <div className="sm:col-span-3 flex justify-end">
            <button
              type="submit"
              className="bg-blue-600 hover:bg-blue-700 text-white font-medium px-4 py-2 rounded text-sm"
            >
              Create Vulnerability
            </button>
          </div>
        </form>
      </div>

      {/* Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <table className="w-full text-left border-collapse text-sm">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase text-xs">
              <th className="py-3 px-4">ID</th>
              <th className="py-3 px-4">Name</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">CWE ID</th>
              <th className="py-3 px-4">File:Line</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="7" className="py-6 text-center text-gray-500">Loading vulnerabilities...</td>
              </tr>
            ) : vulns.length === 0 ? (
              <tr>
                <td colSpan="7" className="py-6 text-center text-gray-500">No vulnerabilities recorded.</td>
              </tr>
            ) : (
              vulns.map((v) => (
                <tr key={v.id} className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-3 px-4 font-mono">{v.id}</td>
                  <td className="py-3 px-4 font-medium text-gray-800">{v.vulnerability_name}</td>
                  <td className="py-3 px-4">
                    <span className={`text-xs px-2.5 py-0.5 rounded font-bold ${
                      v.severity === 'Critical' ? 'bg-purple-100 text-purple-700' :
                      v.severity === 'High' ? 'bg-red-100 text-red-700' :
                      v.severity === 'Medium' ? 'bg-amber-100 text-amber-700' : 'bg-gray-100 text-gray-700'
                    }`}>
                      {v.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-gray-600">{v.cwe_id}</td>
                  <td className="py-3 px-4 text-gray-600">{v.file_name}:{v.line_number}</td>
                  <td className="py-3 px-4">
                    <span className="bg-gray-100 text-gray-700 text-xs px-2 py-0.5 rounded">
                      {v.status || 'Open'}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right space-x-2">
                    <button
                      onClick={() => handleViewVuln(v.id)}
                      className="text-blue-600 hover:text-blue-800 font-medium text-xs px-2 py-1 bg-blue-50 rounded"
                    >
                      Read
                    </button>
                    <button
                      onClick={() => handleStartEdit(v)}
                      className="text-amber-600 hover:text-amber-800 font-medium text-xs px-2 py-1 bg-amber-50 rounded"
                    >
                      Update
                    </button>
                    <button
                      onClick={() => handleDelete(v.id)}
                      className="text-red-600 hover:text-red-800 font-medium text-xs px-2 py-1 bg-red-50 rounded"
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
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full shadow-lg">
            <h3 className="text-lg font-bold text-gray-800 mb-4">Vulnerability Details (Read)</h3>
            <div className="space-y-2 text-sm text-gray-700">
              <p><strong>ID:</strong> {viewingVuln.id}</p>
              <p><strong>Report Name:</strong> {viewingVuln.report_name}</p>
              <p><strong>Vulnerability Name:</strong> {viewingVuln.vulnerability_name}</p>
              <p><strong>Severity:</strong> {viewingVuln.severity}</p>
              <p><strong>CWE ID:</strong> {viewingVuln.cwe_id}</p>
              <p><strong>File Name:</strong> {viewingVuln.file_name}</p>
              <p><strong>Line Number:</strong> {viewingVuln.line_number}</p>
              <p><strong>Status:</strong> {viewingVuln.status}</p>
            </div>
            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setViewingVuln(null)}
                className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-1.5 rounded text-sm"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {editingVuln && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full shadow-lg">
            <h3 className="text-lg font-bold text-gray-800 mb-4">Update Vulnerability #{editingVuln.id}</h3>
            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-600 mb-1">Severity</label>
                <select
                  value={editForm.severity}
                  onChange={(e) => setEditForm({ ...editForm, severity: e.target.value })}
                  className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none bg-white"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                  <option value="Info">Info</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-semibold text-gray-600 mb-1">Status</label>
                <input
                  type="text"
                  required
                  value={editForm.status}
                  onChange={(e) => setEditForm({ ...editForm, status: e.target.value })}
                  className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
                  placeholder="e.g. Open, Resolved, Ignored"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setEditingVuln(null)}
                  className="bg-gray-200 hover:bg-gray-300 text-gray-700 px-4 py-2 rounded text-sm"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-amber-600 hover:bg-amber-700 text-white px-4 py-2 rounded text-sm"
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