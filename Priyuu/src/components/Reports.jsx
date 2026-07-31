import React, { useState, useEffect } from 'react';
import { getReports, getReport, uploadReport, updateReport, deleteReport } from '../services/api';

export default function Reports() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [file, setFile] = useState(null);

  // View Modal State
  const [viewingReport, setViewingReport] = useState(null);

  // Edit Modal State
  const [editingReport, setEditingReport] = useState(null);
  const [editStatus, setEditStatus] = useState('');

  const loadReports = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await getReports();
      setReports(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to fetch reports.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, []);

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file) return;

    if (!file.name.endsWith('.pdf')) {
      setError('Only PDF files are allowed.');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);
    setError('');

    try {
      await uploadReport(formData);
      setFile(null);
      e.target.reset();
      loadReports();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to upload report PDF.');
    }
  };

  const handleViewReport = async (id) => {
    try {
      const res = await getReport(id);
      setViewingReport(res.data);
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to fetch report details.');
    }
  };

  const handleStartEdit = (report) => {
    setEditingReport(report);
    setEditStatus(report.status || 'Uploaded');
  };

  const handleEditSubmit = async (e) => {
    e.preventDefault();
    if (!editingReport) return;
    setError('');
    try {
      await updateReport(editingReport.id, { status: editStatus });
      setEditingReport(null);
      loadReports();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update report status.');
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm(`Are you sure you want to delete report #${id}?`)) {
      try {
        await deleteReport(id);
        loadReports();
      } catch (err) {
        alert(err.response?.data?.detail || 'Failed to delete report.');
      }
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center border-b pb-3">
        <h2 className="text-xl font-bold text-slate-800">VAPT Report Management</h2>
        <button
          onClick={loadReports}
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

      {/* Grid container with inputs on left, outputs on right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Upload Form (Input) */}
        <div className="lg:col-span-4 bg-white p-5 rounded-lg shadow-sm border border-gray-200">
          <h3 className="text-md font-semibold text-gray-700 mb-3 border-b pb-2">Upload VAPT PDF Report</h3>
          <form onSubmit={handleUpload} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1">Select PDF File</label>
              <input
                type="file"
                accept=".pdf"
                required
                onChange={(e) => setFile(e.target.files[0])}
                className="w-full border border-gray-300 rounded px-3 py-2 text-sm bg-gray-50 focus:outline-none"
              />
            </div>
            <div className="pt-2">
              <button
                type="submit"
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium px-4 py-2 rounded text-sm transition-colors"
              >
                Upload Report
              </button>
            </div>
          </form>
        </div>

        {/* Right Column: Reports Table (Output) */}
        <div className="lg:col-span-8 bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
          <div className="p-4 border-b border-gray-200 bg-gray-50/50">
            <h3 className="text-md font-semibold text-gray-700">Uploaded Reports List</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase text-xs">
                  <th className="py-3 px-4">ID</th>
                  <th className="py-3 px-4">Filename</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Vulnerabilities</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="5" className="py-6 text-center text-gray-500">Loading reports...</td>
                  </tr>
                ) : reports.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="py-6 text-center text-gray-500">No reports uploaded yet.</td>
                  </tr>
                ) : (
                  reports.map((report) => (
                    <tr key={report.id} className="border-b border-gray-100 hover:bg-gray-50">
                      <td className="py-3 px-4 font-mono">{report.id}</td>
                      <td className="py-3 px-4 font-medium text-gray-800">{report.filename}</td>
                      <td className="py-3 px-4">
                        <span className="bg-blue-50 text-blue-700 text-xs px-2.5 py-1 rounded border border-blue-200 font-medium">
                          {report.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-gray-600">{report.vulnerabilities_count}</td>
                      <td className="py-3 px-4 text-right space-x-2">
                        <button
                          onClick={() => handleViewReport(report.id)}
                          className="text-blue-600 hover:text-blue-800 font-medium text-xs px-2 py-1 bg-blue-50 rounded"
                        >
                          Read
                        </button>
                        <button
                          onClick={() => handleStartEdit(report)}
                          className="text-amber-600 hover:text-amber-800 font-medium text-xs px-2 py-1 bg-amber-50 rounded"
                        >
                          Update
                        </button>
                        <button
                          onClick={() => handleDelete(report.id)}
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
        </div>
      </div>

      {/* View Details Modal */}
      {viewingReport && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full shadow-lg">
            <h3 className="text-lg font-bold text-gray-800 mb-4">Report Details (Read)</h3>
            <div className="space-y-2 text-sm text-gray-700">
              <p><strong>ID:</strong> {viewingReport.id}</p>
              <p><strong>Filename:</strong> {viewingReport.filename}</p>
              <p><strong>Status:</strong> {viewingReport.status}</p>
              <p><strong>Vulnerabilities Count:</strong> {viewingReport.vulnerabilities_count}</p>
            </div>
            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setViewingReport(null)}
                className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-1.5 rounded text-sm"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Status Modal */}
      {editingReport && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full shadow-lg">
            <h3 className="text-lg font-bold text-gray-800 mb-4">Update Report #{editingReport.id} Status</h3>
            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-600 mb-1">Status</label>
                <input
                  type="text"
                  required
                  value={editStatus}
                  onChange={(e) => setEditStatus(e.target.value)}
                  className="w-full border border-gray-300 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
                  placeholder="e.g. Uploaded, Processing, Completed"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setEditingReport(null)}
                  className="bg-gray-200 hover:bg-gray-300 text-gray-700 px-4 py-2 rounded text-sm"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-amber-600 hover:bg-amber-700 text-white px-4 py-2 rounded text-sm"
                >
                  Save Status
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}