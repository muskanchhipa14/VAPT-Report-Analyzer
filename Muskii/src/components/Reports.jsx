import React, { useState, useEffect } from 'react';
import { getReports, getReport, uploadReport, updateReport, deleteReport } from '../services/api';

export default function Reports() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [processingStep, setProcessingStep] = useState(0); // 0: Idle, 1: Uploading, 2: Analyzing, 3: Detecting
  const [analysisResult, setAnalysisResult] = useState(null);
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

  // Timer logic for simulated step transitions during PDF analysis
  useEffect(() => {
    let timer1, timer2;
    if (uploading) {
      setProcessingStep(1); // Uploading...
      
      timer1 = setTimeout(() => {
        setProcessingStep(2); // Analyzing report...
      }, 1200);

      timer2 = setTimeout(() => {
        setProcessingStep(3); // Detecting vulnerabilities...
      }, 2500);
    } else {
      setProcessingStep(0);
    }
    return () => {
      clearTimeout(timer1);
      clearTimeout(timer2);
    };
  }, [uploading]);

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
    setUploading(true);
    setAnalysisResult(null);

    try {
      const res = await uploadReport(formData);
      // Wait a moment if the server returns too fast, to ensure the user sees our nice progress flow
      await new Promise(resolve => setTimeout(resolve, 3800));
      setAnalysisResult(res.data);
      setFile(null);
      e.target.reset();
      loadReports();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to upload report PDF.');
    } finally {
      setUploading(false);
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
        <div>
          <h2 className="text-xl font-bold text-slate-800">VAPT Report Upload & Analysis</h2>
          <p className="text-xs text-gray-500">Extract issues and map fixes automatically from PDF audit reports</p>
        </div>
        <button
          onClick={loadReports}
          className="text-sm bg-gray-200 hover:bg-gray-300 text-gray-700 px-4 py-2 rounded-xl transition-all font-medium"
        >
          Refresh List
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl text-sm shadow-sm">
          {error}
        </div>
      )}

      {/* Processing Loader */}
      {uploading && (
        <div className="bg-white p-8 rounded-2xl border border-blue-100 shadow-sm flex flex-col items-center justify-center space-y-4">
          <div className="w-12 h-12 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
          <div className="text-center">
            <h4 className="font-semibold text-slate-800 text-base">Processing Report</h4>
            <div className="mt-2 space-y-1">
              <p className={`text-sm ${processingStep >= 1 ? 'text-blue-600 font-semibold' : 'text-gray-400'}`}>
                {processingStep >= 1 ? '✓' : '○'} Uploading...
              </p>
              <p className={`text-sm ${processingStep >= 2 ? 'text-blue-600 font-semibold' : 'text-gray-400'}`}>
                {processingStep >= 2 ? '✓' : '○'} Analyzing report...
              </p>
              <p className={`text-sm ${processingStep >= 3 ? 'text-blue-600 font-semibold' : 'text-gray-400'}`}>
                {processingStep >= 3 ? '✓' : '○'} Detecting vulnerabilities...
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Analysis Result panel */}
      {analysisResult && !uploading && (
        <div className="bg-slate-900 text-white rounded-2xl p-6 shadow-xl border border-slate-800 space-y-6">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-slate-800 pb-4 gap-4">
            <div>
              <span className="text-xs text-blue-400 font-bold uppercase tracking-wider">Analysis Completed</span>
              <h3 className="text-xl font-bold text-white mt-0.5">{analysisResult.filename}</h3>
            </div>
            <div className="flex items-center space-x-3">
              <span className="bg-red-500/20 text-red-400 border border-red-500/30 font-bold text-sm px-4 py-1.5 rounded-full">
                {analysisResult.vulnerabilities_count} Vulnerabilities Found
              </span>
              <button
                onClick={() => setAnalysisResult(null)}
                className="text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 px-3.5 py-1.5 rounded-lg border border-slate-700 font-semibold"
              >
                Clear Result
              </button>
            </div>
          </div>

          <div>
            <h4 className="text-sm font-semibold text-slate-400 mb-3">Detected Findings Detail</h4>
            
            {analysisResult.detected_vulnerabilities.length === 0 ? (
              <p className="text-sm text-slate-400 italic py-2">No security flaws were matched by the CWE engine.</p>
            ) : (
              <div className="space-y-4">
                {analysisResult.detected_vulnerabilities.map((vuln) => (
                  <div key={vuln.id} className="bg-slate-950/60 rounded-xl p-5 border border-slate-800 hover:border-slate-700 transition-colors">
                    <div className="flex flex-col sm:flex-row justify-between items-start gap-2 border-b border-slate-900 pb-3 mb-3">
                      <div>
                        <h5 className="font-bold text-base text-slate-100 flex items-center gap-2">
                          <span>{vuln.vulnerability_name}</span>
                          <span className="font-mono text-xs text-blue-400 bg-blue-900/30 px-2.5 py-0.5 rounded border border-blue-800/40">{vuln.cwe_id}</span>
                        </h5>
                        <p className="text-xs text-slate-500 mt-1">
                          File: <span className="text-slate-300 font-mono">{vuln.file_name}</span> at line <span className="text-slate-300 font-mono">{vuln.line_number}</span>
                        </p>
                      </div>
                      <span className={`text-xs font-bold px-3 py-1 rounded-full border ${
                        vuln.severity === 'Critical' ? 'bg-purple-950/60 text-purple-400 border-purple-800/40' :
                        vuln.severity === 'High' ? 'bg-red-950/60 text-red-400 border-red-800/40' :
                        vuln.severity === 'Medium' ? 'bg-amber-950/60 text-amber-400 border-amber-800/40' : 'bg-gray-950/60 text-gray-400 border-gray-800/40'
                      }`}>
                        {vuln.severity}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                      <div>
                        <span className="font-bold text-slate-400 uppercase tracking-wider text-[10px]">Description</span>
                        <p className="mt-1 text-slate-300 leading-relaxed bg-slate-900/40 p-3 rounded-lg border border-slate-900">{vuln.description}</p>
                      </div>
                      <div>
                        <span className="font-bold text-slate-400 uppercase tracking-wider text-[10px]">Remediation</span>
                        <p className="mt-1 text-emerald-400 leading-relaxed bg-slate-900/40 p-3 rounded-lg border border-slate-900">{vuln.remediation}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Upload Form */}
      {!uploading && (
        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-200">
          <h3 className="text-base font-bold text-slate-800 mb-3">Upload VAPT Report</h3>
          <form onSubmit={handleUpload} className="flex flex-col sm:flex-row items-start sm:items-end gap-4">
            <div className="flex-1 w-full">
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">Choose PDF</label>
              <input
                type="file"
                accept=".pdf"
                required
                onChange={(e) => setFile(e.target.files[0])}
                className="w-full border border-gray-300 rounded-xl px-4 py-2.5 text-sm bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
              />
            </div>
            <button
              type="submit"
              className="bg-blue-600 hover:bg-blue-700 text-white font-semibold px-6 py-3 rounded-xl text-sm shrink-0 shadow-md shadow-blue-500/10 hover:shadow-lg transition-all active:scale-95 duration-150"
            >
              Upload & Analyze
            </button>
          </form>
        </div>
      )}

      {/* Reports Table */}
      {!uploading && (
        <div className="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-100 bg-gray-50/50">
            <h3 className="font-bold text-sm text-slate-800">Historical Scans</h3>
          </div>
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="bg-gray-50/60 border-b border-gray-200 text-gray-500 uppercase text-[11px] font-bold tracking-wider">
                <th className="py-3 px-5">ID</th>
                <th className="py-3 px-5">Filename</th>
                <th className="py-3 px-5">Status</th>
                <th className="py-3 px-5">Vulnerabilities</th>
                <th className="py-3 px-5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="5" className="py-8 text-center text-gray-500">Loading reports...</td>
                </tr>
              ) : reports.length === 0 ? (
                <tr>
                  <td colSpan="5" className="py-8 text-center text-gray-500">No reports uploaded yet.</td>
                </tr>
              ) : (
                reports.map((report) => (
                  <tr key={report.id} className="border-b border-gray-100 hover:bg-gray-50/50 transition-colors">
                    <td className="py-3.5 px-5 font-mono text-gray-500 text-xs">{report.id}</td>
                    <td className="py-3.5 px-5 font-medium text-slate-700">{report.filename}</td>
                    <td className="py-3.5 px-5">
                      <span className={`text-[11px] px-2.5 py-0.5 rounded-full font-bold ${
                        report.status === 'Analyzed' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                        report.status === 'Processing' ? 'bg-blue-50 text-blue-700 border border-blue-200 animate-pulse' :
                        'bg-gray-50 text-gray-700 border border-gray-200'
                      }`}>
                        {report.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-5 font-mono text-gray-600 font-medium">{report.vulnerabilities_count}</td>
                    <td className="py-3.5 px-5 text-right space-x-1">
                      <button
                        onClick={() => handleViewReport(report.id)}
                        className="text-blue-600 hover:text-blue-800 font-semibold text-xs px-2.5 py-1 hover:bg-blue-50 rounded-lg transition-colors"
                      >
                        Read
                      </button>
                      <button
                        onClick={() => handleStartEdit(report)}
                        className="text-amber-600 hover:text-amber-800 font-semibold text-xs px-2.5 py-1 hover:bg-amber-50 rounded-lg transition-colors"
                      >
                        Update
                      </button>
                      <button
                        onClick={() => handleDelete(report.id)}
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
      )}

      {/* View Details Modal */}
      {viewingReport && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50 backdrop-blur-sm">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-xl border border-gray-100">
            <h3 className="text-lg font-bold text-slate-800 mb-4">Report Details</h3>
            <div className="space-y-3 text-sm text-slate-600 border-y py-4">
              <p className="flex justify-between">
                <span className="font-medium text-gray-400">Database ID:</span>
                <span className="font-mono text-slate-800">{viewingReport.id}</span>
              </p>
              <p className="flex justify-between">
                <span className="font-medium text-gray-400">Filename:</span>
                <span className="font-semibold text-slate-800">{viewingReport.filename}</span>
              </p>
              <p className="flex justify-between">
                <span className="font-medium text-gray-400">Status:</span>
                <span className="font-bold text-slate-800">{viewingReport.status}</span>
              </p>
              <p className="flex justify-between">
                <span className="font-medium text-gray-400">Vulnerabilities Detected:</span>
                <span className="font-mono font-semibold text-slate-800">{viewingReport.vulnerabilities_count}</span>
              </p>
            </div>
            <div className="mt-5 flex justify-end">
              <button
                onClick={() => setViewingReport(null)}
                className="bg-slate-800 hover:bg-slate-900 text-white font-semibold px-4 py-2 rounded-xl text-sm transition-all"
              >
                Close Details
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Status Modal */}
      {editingReport && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50 backdrop-blur-sm">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-xl border border-gray-100">
            <h3 className="text-lg font-bold text-slate-800 mb-4">Update Report Status</h3>
            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-600 mb-1.5">Status</label>
                <input
                  type="text"
                  required
                  value={editStatus}
                  onChange={(e) => setEditStatus(e.target.value)}
                  className="w-full border border-gray-300 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                  placeholder="e.g. Uploaded, Processing, Completed"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setEditingReport(null)}
                  className="bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-xl text-sm font-medium transition-all"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-amber-600 hover:bg-amber-700 text-white px-4 py-2 rounded-xl text-sm font-semibold transition-all shadow-md shadow-amber-500/10"
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