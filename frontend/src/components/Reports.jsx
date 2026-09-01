import React, { useState, useEffect } from 'react';
import {
  getReports,
  getReport,
  uploadReport,
  updateReport,
  deleteReport,
  evaluateReportFile,
  evaluateReportById,
  getEvaluationStatus
} from '../services/api';

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

  // Evaluation States
  const [evaluating, setEvaluating] = useState(false);
  const [evaluatingReportId, setEvaluatingReportId] = useState(null);
  const [evaluationResult, setEvaluationResult] = useState(null);
  const [evaluationStatusInfo, setEvaluationStatusInfo] = useState(null);

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

  const checkGeminiStatus = async () => {
    try {
      const res = await getEvaluationStatus();
      setEvaluationStatusInfo(res.data);
    } catch (err) {
      console.warn('Could not fetch Gemini status', err);
    }
  };

  useEffect(() => {
    loadReports();
    checkGeminiStatus();
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

  const handleUploadAndEvaluate = async () => {
    if (!file) {
      setError('Please select a PDF file to evaluate.');
      return;
    }
    if (!file.name.endsWith('.pdf')) {
      setError('Only PDF files are allowed.');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);
    setError('');
    setEvaluating(true);

    try {
      const res = await evaluateReportFile(formData);
      setEvaluationResult(res.data);
      setFile(null);
      loadReports();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to evaluate report with Gemini.');
    } finally {
      setEvaluating(false);
    }
  };

  const handleEvaluateExisting = async (id) => {
    setError('');
    setEvaluatingReportId(id);
    try {
      const res = await evaluateReportById(id);
      setEvaluationResult(res.data);
      loadReports();
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to evaluate report.');
    } finally {
      setEvaluatingReportId(null);
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

  const formatCoverage = (decimalVal) => {
    if (decimalVal === undefined || decimalVal === null || isNaN(decimalVal)) return '0%';
    return `${Math.round(decimalVal * 100)}%`;
  };

  const formatAccuracy = (decimalVal, evaluatedCount) => {
    if (evaluatedCount === 0 || decimalVal === undefined || decimalVal === null || isNaN(decimalVal)) {
      return 'N/A';
    }
    return `${Math.round(decimalVal * 100)}%`;
  };

  const formatPercentage = (decimalVal) => {
    if (decimalVal === undefined || decimalVal === null || isNaN(decimalVal)) return '0%';
    return `${Math.round(decimalVal * 100)}%`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center border-b pb-3">
        <div>
          <h2 className="text-xl font-bold text-slate-800">VAPT Report Management & AI Evaluation</h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Compare Knowledge Base detections and remediations against Gemini LLM independent evaluator
          </p>
        </div>
        <div className="flex gap-2">
          {evaluationStatusInfo && !evaluationStatusInfo.configured && (
            <span className="inline-flex items-center text-xs bg-amber-50 text-amber-800 border border-amber-300 px-2.5 py-1 rounded">
              ⚠️ GEMINI_API_KEY not configured
            </span>
          )}
          <button
            onClick={() => { loadReports(); checkGeminiStatus(); }}
            className="text-sm bg-gray-200 hover:bg-gray-300 text-gray-700 px-3 py-1.5 rounded transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm">
          {error}
        </div>
      )}

      {/* Upload Form */}
      <div className="bg-white p-5 rounded-lg shadow-sm border border-gray-200">
        <h3 className="text-md font-semibold text-gray-700 mb-3">Upload & Analyze VAPT PDF Report</h3>
        <form onSubmit={handleUpload} className="flex flex-col sm:flex-row items-start sm:items-end gap-3">
          <div className="flex-1 w-full">
            <label className="block text-xs font-semibold text-gray-600 mb-1">Select PDF File</label>
            <input
              type="file"
              accept=".pdf"
              onChange={(e) => setFile(e.target.files[0])}
              className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm bg-gray-50 focus:outline-none"
            />
          </div>
          <div className="flex gap-2 w-full sm:w-auto">
            <button
              type="submit"
              disabled={evaluating}
              className="flex-1 sm:flex-initial bg-blue-600 hover:bg-blue-700 text-white font-medium px-4 py-2 rounded text-sm shrink-0 disabled:opacity-50"
            >
              Upload Report
            </button>
            <button
              type="button"
              disabled={evaluating || !file}
              onClick={handleUploadAndEvaluate}
              className="flex-1 sm:flex-initial bg-purple-600 hover:bg-purple-700 text-white font-medium px-4 py-2 rounded text-sm shrink-0 flex items-center justify-center gap-1.5 disabled:opacity-50"
            >
              {evaluating ? (
                <>
                  <span className="inline-block animate-spin">⏳</span>
                  Evaluating...
                </>
              ) : (
                <>
                  <span>✨</span>
                  Upload & Evaluate with Gemini
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Evaluation Results Banner / Section */}
      {evaluationResult && (() => {
        const evaluatedCount = evaluationResult.metrics?.successfully_evaluated ?? evaluationResult.metrics?.evaluated_count ?? 0;
        const totalFindings = evaluationResult.metrics?.total_findings ?? evaluationResult.total_vulnerabilities;
        const failedCount = evaluationResult.metrics?.failed_evaluations ?? 0;

        return (
          <div className="bg-slate-900 text-white p-6 rounded-xl shadow-lg border border-slate-700 space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-700 pb-4">
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h3 className="text-lg font-bold text-white">Evaluation Summary</h3>
                  <span className="bg-purple-900/80 text-purple-200 border border-purple-500 text-xs px-2.5 py-0.5 rounded-full font-medium">
                    {evaluationResult.evaluation_type || 'LLM-based Evaluation (Gemini Reference Judge)'}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Report: <span className="text-slate-200 font-semibold">{evaluationResult.report_name}</span> |
                  Total Unique Findings: <span className="text-slate-200 font-semibold">{totalFindings}</span>
                </p>
                {evaluatedCount === 0 ? (
                  <p className="text-xs text-amber-300 mt-1.5 bg-amber-950/60 px-2.5 py-1 rounded border border-amber-800/80 inline-block font-medium">
                    ⚠️ No successful Gemini evaluations were available for this report. Accuracy metrics are N/A.
                  </p>
                ) : (
                  <p className="text-xs text-amber-300/90 mt-1.5 italic bg-slate-800/60 px-2.5 py-1 rounded border border-slate-700 inline-block">
                    ℹ️ {evaluationResult.disclaimer || "Accuracy is calculated only from successfully evaluated findings. API failures are excluded from accuracy calculations."}
                  </p>
                )}
              </div>
              <button
                onClick={() => setEvaluationResult(null)}
                className="text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded transition-colors"
              >
                Close Evaluation
              </button>
            </div>

            {/* Metrics Cards Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
              <div className="bg-slate-800/80 p-3 rounded-lg border border-slate-700">
                <span className="text-xs text-slate-400 block font-medium">Total Findings</span>
                <span className="text-xl font-bold text-white">
                  {totalFindings}
                </span>
              </div>

              <div className="bg-slate-800/80 p-3 rounded-lg border border-slate-700">
                <span className="text-xs text-slate-400 block font-medium">Evaluated</span>
                <span className={`text-xl font-bold ${evaluatedCount > 0 ? 'text-emerald-400' : 'text-slate-400'}`}>
                  {evaluatedCount}
                </span>
              </div>

              <div className="bg-slate-800/80 p-3 rounded-lg border border-slate-700">
                <span className="text-xs text-slate-400 block font-medium">Failed / Skipped</span>
                <span className={`text-xl font-bold ${failedCount > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
                  {failedCount}
                </span>
              </div>

              <div className="bg-slate-800/80 p-3 rounded-lg border border-slate-700">
                <span className="text-xs text-slate-400 block font-medium">Eval. Coverage</span>
                <span className="text-xl font-bold text-cyan-400">
                  {formatCoverage(evaluationResult.metrics?.evaluation_coverage)}
                </span>
              </div>

              <div className="bg-slate-800/80 p-3 rounded-lg border border-slate-700">
                <span className="text-xs text-slate-400 block font-medium">Vuln. Accuracy</span>
                <span className={`text-xl font-bold ${evaluatedCount > 0 ? 'text-emerald-400' : 'text-slate-400'}`}>
                  {formatAccuracy(evaluationResult.metrics?.vulnerability_accuracy, evaluatedCount)}
                </span>
              </div>

              <div className="bg-slate-800/80 p-3 rounded-lg border border-slate-700">
                <span className="text-xs text-slate-400 block font-medium">Remed. Accuracy</span>
                <span className={`text-xl font-bold ${evaluatedCount > 0 ? 'text-blue-400' : 'text-slate-400'}`}>
                  {formatAccuracy(evaluationResult.metrics?.remediation_accuracy, evaluatedCount)}
                </span>
              </div>

              <div className="bg-slate-800/80 p-3 rounded-lg border border-slate-700">
                <span className="text-xs text-slate-400 block font-medium">Avg Remed. Score</span>
                <span className={`text-xl font-bold ${evaluatedCount > 0 ? 'text-purple-400' : 'text-slate-400'}`}>
                  {formatAccuracy(evaluationResult.metrics?.average_remediation_score, evaluatedCount)}
                </span>
              </div>

              <div className="bg-slate-800/80 p-3 rounded-lg border border-slate-700">
                <span className="text-xs text-slate-400 block font-medium">Precision / F1</span>
                <span className={`text-base font-bold block ${evaluatedCount > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
                  {evaluatedCount > 0
                    ? `${formatAccuracy(evaluationResult.metrics?.precision, evaluatedCount)} / ${formatAccuracy(evaluationResult.metrics?.f1_score, evaluatedCount)}`
                    : 'N/A'
                  }
                </span>
              </div>
            </div>

          {/* Detailed Vulnerability Comparison List */}
          <div className="space-y-4">
            <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              Independent Comparison & Technical Breakdown
            </h4>

            {evaluationResult.evaluations.map((item, idx) => (
              <div
                key={idx}
                className="bg-slate-800 rounded-lg p-4 border border-slate-700 space-y-3"
              >
                {/* Vulnerability Title & Metadata */}
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-700/60 pb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono bg-slate-700 text-slate-300 px-2 py-0.5 rounded">
                      #{idx + 1}
                    </span>
                    <h5 className="font-bold text-white text-base">
                      {item.vulnerability}
                    </h5>
                    {item.cwe_id && (
                      <span className="text-xs bg-blue-900/60 text-blue-300 border border-blue-700 px-2 py-0.5 rounded">
                        {item.cwe_id}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    <span>File: <code className="text-slate-200">{item.file_name || 'N/A'}:{item.line_number || 1}</code></span>
                    {item.evaluation_status === 'failed' && (
                      <span className="bg-amber-950 text-amber-300 border border-amber-800 px-2 py-0.5 rounded font-medium">
                        ⚠️ Evaluation Skipped / Quota
                      </span>
                    )}
                  </div>
                </div>

                {/* Comparison Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  {/* Left Column: Knowledge Base */}
                  <div className="bg-slate-900/60 p-3 rounded border border-slate-700/50 space-y-2">
                    <span className="font-semibold text-slate-300 block text-xs">
                      📖 System Knowledge Base Remediation:
                    </span>
                    <p className="text-slate-300 leading-relaxed">
                      {item.knowledge_base_remediation || 'No remediation provided.'}
                    </p>
                  </div>

                  {/* Right Column: Gemini Evaluation */}
                  <div className="bg-slate-900/60 p-3 rounded border border-slate-700/50 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-purple-300 block text-xs">
                        🤖 Gemini Independent Evaluation:
                      </span>
                      {item.gemini_evaluation && (
                        <span className="text-xs font-bold text-purple-200">
                          Score: {formatPercentage(item.gemini_evaluation.remediation_score)}
                        </span>
                      )}
                    </div>

                    {item.gemini_evaluation ? (
                      <div className="space-y-2">
                        <div className="flex flex-wrap gap-2 text-xs">
                          <span className={`px-2 py-0.5 rounded font-medium ${
                            item.gemini_evaluation.is_vulnerability_correct
                              ? 'bg-emerald-900/80 text-emerald-200 border border-emerald-600'
                              : 'bg-red-900/80 text-red-200 border border-red-600'
                          }`}>
                            Correct Vuln: {item.gemini_evaluation.is_vulnerability_correct ? 'YES' : 'NO'} (Conf: {formatPercentage(item.gemini_evaluation.vulnerability_confidence)})
                          </span>

                          <span className={`px-2 py-0.5 rounded font-medium ${
                            item.gemini_evaluation.remediation_is_correct
                              ? 'bg-emerald-900/80 text-emerald-200 border border-emerald-600'
                              : 'bg-red-900/80 text-red-200 border border-red-600'
                          }`}>
                            Remediation Correct: {item.gemini_evaluation.remediation_is_correct ? 'YES' : 'NO'}
                          </span>
                        </div>

                        {item.gemini_evaluation.missing_points && item.gemini_evaluation.missing_points.length > 0 && (
                          <div className="bg-amber-950/40 border border-amber-800/60 p-2 rounded text-amber-200 text-xs">
                            <strong>Missing Remediation Points:</strong>
                            <ul className="list-disc list-inside mt-1 space-y-0.5">
                              {item.gemini_evaluation.missing_points.map((pt, pIdx) => (
                                <li key={pIdx}>{pt}</li>
                              ))}
                            </ul>
                          </div>
                        )}

                        <div>
                          <strong className="text-slate-300 block">Gemini Recommended Remediation:</strong>
                          <p className="text-slate-300 mt-0.5 leading-relaxed">
                            {item.gemini_evaluation.gemini_recommended_remediation}
                          </p>
                        </div>

                        {item.gemini_evaluation.reason && (
                          <div>
                            <strong className="text-slate-400 block">Reason / Technical Rationale:</strong>
                            <p className="text-slate-400 italic mt-0.5">
                              {item.gemini_evaluation.reason}
                            </p>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="bg-amber-950/40 border border-amber-800/60 p-3 rounded text-amber-200 text-xs space-y-1">
                        <span className="font-semibold block">⚠️ Finding Not Evaluated</span>
                        <p className="text-slate-300">
                          {item.error_message || 'Gemini quota exceeded; this finding was not evaluated.'}
                        </p>
                        <p className="text-slate-400 text-[11px] italic">
                          (This API failure is excluded from accuracy calculations and does not penalize system scores.)
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      );
    })()}

      {/* Reports Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
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
                    <span className={`text-xs px-2.5 py-1 rounded font-medium border ${
                      report.status === 'Evaluated'
                        ? 'bg-purple-50 text-purple-700 border-purple-200'
                        : report.status === 'Analyzed'
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : 'bg-blue-50 text-blue-700 border-blue-200'
                    }`}>
                      {report.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-gray-600">{report.vulnerabilities_count}</td>
                  <td className="py-3 px-4 text-right space-x-1 sm:space-x-2">
                    <button
                      onClick={() => handleEvaluateExisting(report.id)}
                      disabled={evaluatingReportId === report.id}
                      className="text-purple-700 hover:text-purple-900 font-medium text-xs px-2.5 py-1 bg-purple-50 hover:bg-purple-100 rounded border border-purple-200 transition-colors disabled:opacity-50"
                      title="Evaluate with Gemini"
                    >
                      {evaluatingReportId === report.id ? 'Evaluating...' : '✨ Evaluate'}
                    </button>
                    <button
                      onClick={() => handleViewReport(report.id)}
                      className="text-blue-600 hover:text-blue-800 font-medium text-xs px-2 py-1 bg-blue-50 rounded transition-colors"
                    >
                      Read
                    </button>
                    <button
                      onClick={() => handleStartEdit(report)}
                      className="text-amber-600 hover:text-amber-800 font-medium text-xs px-2 py-1 bg-amber-50 rounded transition-colors"
                    >
                      Update
                    </button>
                    <button
                      onClick={() => handleDelete(report.id)}
                      className="text-red-600 hover:text-red-800 font-medium text-xs px-2 py-1 bg-red-50 rounded transition-colors"
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
            <div className="mt-6 flex justify-between">
              <button
                onClick={() => {
                  const id = viewingReport.id;
                  setViewingReport(null);
                  handleEvaluateExisting(id);
                }}
                className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-1.5 rounded text-sm flex items-center gap-1"
              >
                <span>✨</span> Evaluate with Gemini
              </button>
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