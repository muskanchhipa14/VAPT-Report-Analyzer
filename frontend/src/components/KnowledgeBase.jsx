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
      <div className="flex justify-between items-center border-b pb-3">
        <h2 className="text-xl font-bold text-slate-800">Knowledge Base</h2>
        <button
          onClick={loadEntries}
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

      {/* Create Entry Form */}
      <div className="bg-white p-5 rounded-lg shadow-sm border border-gray-200">
        <h3 className="text-md font-semibold text-gray-700 mb-3">Add Knowledge Base Entry</h3>
        <form onSubmit={handleCreateSubmit} className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Vulnerability Name</label>
            <input
              type="text"
              required
              value={createForm.vulnerability_name}
              onChange={(e) => setCreateForm({ ...createForm, vulnerability_name: e.target.value })}
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
              placeholder="e.g. Cross-Site Scripting"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">CWE ID</label>
            <input
              type="text"
              required
              value={createForm.cwe_id}
              onChange={(e) => setCreateForm({ ...createForm, cwe_id: e.target.value })}
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
              placeholder="e.g. CWE-79"
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
          <div className="sm:col-span-3">
            <label className="block text-xs font-semibold text-gray-600 mb-1">Description</label>
            <textarea
              required
              rows="2"
              value={createForm.description}
              onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
              placeholder="Description of the vulnerability"
            />
          </div>
          <div className="sm:col-span-3">
            <label className="block text-xs font-semibold text-gray-600 mb-1">Remediation</label>
            <textarea
              required
              rows="2"
              value={createForm.remediation}
              onChange={(e) => setCreateForm({ ...createForm, remediation: e.target.value })}
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
              placeholder="Recommended fix or mitigation steps"
            />
          </div>
          <div className="sm:col-span-3 flex justify-end">
            <button
              type="submit"
              className="bg-blue-600 hover:bg-blue-700 text-white font-medium px-4 py-2 rounded text-sm"
            >
              Add Entry
            </button>
          </div>
        </form>
      </div>

      {/* Entries Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <table className="w-full text-left border-collapse text-sm">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase text-xs">
              <th className="py-3 px-4">ID</th>
              <th className="py-3 px-4">Vulnerability Name</th>
              <th className="py-3 px-4">CWE ID</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="5" className="py-6 text-center text-gray-500">Loading entries...</td>
              </tr>
            ) : entries.length === 0 ? (
              <tr>
                <td colSpan="5" className="py-6 text-center text-gray-500">No Knowledge Base entries found.</td>
              </tr>
            ) : (
              entries.map((item) => (
                <tr key={item.id} className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-3 px-4 font-mono">{item.id}</td>
                  <td className="py-3 px-4 font-medium text-gray-800">{item.vulnerability_name}</td>
                  <td className="py-3 px-4 font-mono text-gray-600">{item.cwe_id}</td>
                  <td className="py-3 px-4">
                    <span className="bg-amber-100 text-amber-700 text-xs px-2.5 py-0.5 rounded font-bold">
                      {item.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right space-x-2">
                    <button
                      onClick={() => handleViewEntry(item.id)}
                      className="text-blue-600 hover:text-blue-800 font-medium text-xs px-2 py-1 bg-blue-50 rounded"
                    >
                      Read
                    </button>
                    <button
                      onClick={() => handleStartEdit(item)}
                      className="text-amber-600 hover:text-amber-800 font-medium text-xs px-2 py-1 bg-amber-50 rounded"
                    >
                      Update
                    </button>
                    <button
                      onClick={() => handleDelete(item.id)}
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

      {/* Read Detail Modal */}
      {viewingEntry && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg p-6 max-w-lg w-full shadow-lg">
            <h3 className="text-lg font-bold text-gray-800 mb-4">Knowledge Base Entry #{viewingEntry.id} (Read)</h3>
            <div className="space-y-3 text-sm text-gray-700">
              <p><strong>Name:</strong> {viewingEntry.vulnerability_name}</p>
              <p><strong>CWE ID:</strong> {viewingEntry.cwe_id}</p>
              <p><strong>Severity:</strong> {viewingEntry.severity}</p>
              <div>
                <strong>Description:</strong>
                <p className="mt-1 bg-gray-50 p-2 rounded text-gray-600 text-xs">{viewingEntry.description}</p>
              </div>
              <div>
                <strong>Remediation:</strong>
                <p className="mt-1 bg-gray-50 p-2 rounded text-gray-600 text-xs">{viewingEntry.remediation}</p>
              </div>
            </div>
            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setViewingEntry(null)}
                className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-1.5 rounded text-sm"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Entry Modal */}
      {editingEntry && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg p-6 max-w-lg w-full shadow-lg">
            <h3 className="text-lg font-bold text-gray-800 mb-4">Update Knowledge Base Entry #{editingEntry.id}</h3>
            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-600 mb-1">Vulnerability Name</label>
                <input
                  type="text"
                  required
                  value={editForm.vulnerability_name}
                  onChange={(e) => setEditForm({ ...editForm, vulnerability_name: e.target.value })}
                  className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-gray-600 mb-1">CWE ID</label>
                <input
                  type="text"
                  required
                  value={editForm.cwe_id}
                  onChange={(e) => setEditForm({ ...editForm, cwe_id: e.target.value })}
                  className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
                />
              </div>
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
                <label className="block text-xs font-semibold text-gray-600 mb-1">Description</label>
                <textarea
                  required
                  rows="2"
                  value={editForm.description}
                  onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                  className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-gray-600 mb-1">Remediation</label>
                <textarea
                  required
                  rows="2"
                  value={editForm.remediation}
                  onChange={(e) => setEditForm({ ...editForm, remediation: e.target.value })}
                  className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setEditingEntry(null)}
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