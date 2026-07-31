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
      {/* Header Bar */}
      <div className="flex justify-between items-center border-b border-slate-200/80 pb-4">
        <div>
          <h2 className="text-xl font-bold text-slate-800 tracking-tight flex items-center gap-2">
            <svg className="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            VAPT Report Management
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">Upload, parse, and analyze security vulnerability assessment reports</p>
        </div>
        <button
          onClick={loadReports}
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

      {/* Upload Form */}
      <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200/80">
        <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider mb-4 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-indigo-600"></span>
          Upload VAPT PDF Report
        </h3>
        <form onSubmit={handleUpload} className="flex flex-col sm:flex-row items-start sm:items-end gap-4">
          <div className="flex-1 w-full">
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">Select PDF File</label>
            <input
              type="file"
              accept=".pdf"
              required
              onChange={(e) => setFile(e.target.files[0])}
              className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm bg-slate-50/50 file:mr-4 file:py-1 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-indigo-50 file:text-indigo-700 hover:file:bg-indigo-100 focus:outline-none transition-all cursor-pointer"
            />
          </div>
          <button
            type="submit"
            className="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold px-5 py-2.5 rounded-lg text-sm shadow-sm hover:shadow-indigo-500/25 active:scale-[0.98] transition-all shrink-0 flex items-center gap-1.5"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
            Upload Report
          </button>
        </form>
      </div>

      {/* Reports Table */}
      <div className="bg-white rounded-2xl shadow-sm border border-slate-200/80 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="bg-slate-50/90 border-b border-slate-200 text-slate-500 uppercase text-[11px] font-bold tracking-wider">
                <th className="py-3.5 px-4">ID</th>
                <th className="py-3.5 px-4">Filename</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4">Vulnerabilities</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan="5" className="py-8 text-center text-slate-400 font-medium">
                    <div className="flex items-center justify-center space-x-2">
                      <div className="w-4 h-4 border-2 border-indigo-600 border-t-transparent rounded-full animate-spin"></div>
                      <span>Loading reports...</span>
                    </div>
                  </td>
                </tr>
              ) : reports.length === 0 ? (
                <tr>
                  <td colSpan="5" className="py-8 text-center text-slate-400 font-medium">
                    No reports uploaded yet.
                  </td>
                </tr>
              ) : (
                reports.map((report) => (
                  <tr key={report.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-3.5 px-4 font-mono text-xs text-slate-500 font-semibold">#{report.id}</td>
                    <td className="py-3.5 px-4 font-semibold text-slate-800 flex items-center gap-2">
                      <svg className="w-4 h-4 text-rose-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                      </svg>
                      <span className="font-mono text-xs">{report.filename}</span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`text-xs px-2.5 py-1 rounded-md border font-semibold inline-flex items-center gap-1.5 ${
                        report.status === 'Completed' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' :
                        report.status === 'Processing' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                        'bg-indigo-50 text-indigo-700 border-indigo-200'
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          report.status === 'Completed' ? 'bg-emerald-500' :
                          report.status === 'Processing' ? 'bg-amber-500 animate-ping' :
                          'bg-indigo-500'
                        }`}></span>
                        {report.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="font-mono text-xs bg-slate-100 text-slate-700 px-2 py-1 rounded border border-slate-200/80 font-bold">
                        {report.vulnerabilities_count} items
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right space-x-1.5">
                      <button
                        onClick={() => handleViewReport(report.id)}
                        className="text-indigo-600 hover:text-indigo-800 font-semibold text-xs px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 rounded-lg transition-colors"
                      >
                        Read
                      </button>
                      <button
                        onClick={() => handleStartEdit(report)}
                        className="text-amber-600 hover:text-amber-800 font-semibold text-xs px-3 py-1.5 bg-amber-50 hover:bg-amber-100 rounded-lg transition-colors"
                      >
                        Update
                      </button>
                      <button
                        onClick={() => handleDelete(report.id)}
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

      {/* View Details Modal */}
      {viewingReport && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-2xl border border-slate-100 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex justify-between items-center mb-4 pb-3 border-b border-slate-100">
              <h3 className="text-base font-bold text-slate-800 flex items-center gap-2">
                <svg className="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Report Details
              </h3>
              <button onClick={() => setViewingReport(null)} className="text-slate-400 hover:text-slate-600">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="space-y-3 text-sm text-slate-700 bg-slate-50 p-4 rounded-xl border border-slate-200/60">
              <p className="flex justify-between"><strong className="text-slate-500">ID:</strong> <span className="font-mono">#{viewingReport.id}</span></p>
              <p className="flex justify-between"><strong className="text-slate-500">Filename:</strong> <span className="font-mono text-xs text-indigo-600 truncate max-w-[200px]">{viewingReport.filename}</span></p>
              <p className="flex justify-between"><strong className="text-slate-500">Status:</strong> <span className="font-semibold text-slate-800">{viewingReport.status}</span></p>
              <p className="flex justify-between"><strong className="text-slate-500">Vulnerabilities:</strong> <span className="font-mono font-bold text-slate-800">{viewingReport.vulnerabilities_count}</span></p>
            </div>
            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setViewingReport(null)}
                className="bg-slate-800 hover:bg-slate-900 text-white font-semibold px-4 py-2 rounded-lg text-sm shadow-sm transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Status Modal */}
      {editingReport && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-2xl border border-slate-100 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex justify-between items-center mb-4 pb-3 border-b border-slate-100">
              <h3 className="text-base font-bold text-slate-800 flex items-center gap-2">
                <svg className="w-5 h-5 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>
                Update Report #{editingReport.id} Status
              </h3>
              <button onClick={() => setEditingReport(null)} className="text-slate-400 hover:text-slate-600">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-600 mb-1.5">Status</label>
                <input
                  type="text"
                  required
                  value={editStatus}
                  onChange={(e) => setEditStatus(e.target.value)}
                  className="w-full border border-slate-200 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-amber-500/20 focus:border-amber-500 transition-all bg-slate-50/50"
                  placeholder="e.g. Uploaded, Processing, Completed"
                />
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setEditingReport(null)}
                  className="bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold px-4 py-2 rounded-lg text-sm transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-amber-600 hover:bg-amber-700 text-white font-semibold px-4 py-2 rounded-lg text-sm shadow-sm transition-colors"
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