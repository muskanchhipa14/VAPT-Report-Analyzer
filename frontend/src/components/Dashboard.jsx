import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { reportAPI, vulnerabilityAPI, analysisAPI } from '../services/api';
import RemediationInspector from './RemediationInspector';
import {
  Upload, FileText, Trash2, Download, ExternalLink,
  ShieldCheck, AlertTriangle, Loader, CheckCircle, RefreshCw, FolderGit2,
  Sparkles, Code2, Layers, FileCode, X
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from 'recharts';

const Dashboard = () => {
  const [reports, setReports] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloadingReportId, setDownloadingReportId] = useState(null);
  const navigate = useNavigate();

  // Multi-Flow Upload / Analysis State
  const [showAnalysisModal, setShowAnalysisModal] = useState(false);
  const [analysisTab, setAnalysisTab] = useState('report'); // 'report' | 'source' | 'combined'
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState('');

  // Flow A: VAPT Report
  const [reportFile, setReportFile] = useState(null);

  // Flow B: Source Code
  const [sourceFile, setSourceFile] = useState(null);
  const [sourceCodeText, setSourceCodeText] = useState('');
  const [sourceFileName, setSourceFileName] = useState('');
  const [sourceLanguage, setSourceLanguage] = useState('');

  // Flow C: Combined
  const [combReportFile, setCombReportFile] = useState(null);
  const [combSourceFile, setCombSourceFile] = useState(null);

  // Results & Inspection State
  const [activeAnalysisResult, setActiveAnalysisResult] = useState(null);
  const [inspectingFinding, setInspectingFinding] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const reportsData = await reportAPI.getReports();
      const vulnsData = await vulnerabilityAPI.getVulnerabilities();
      setReports(reportsData);
      setVulnerabilities(vulnsData);
    } catch (e) {
      console.error("Error fetching dashboard data", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRunReportAnalysis = async (e) => {
    e.preventDefault();
    if (!reportFile) {
      setUploadError('Please select a report file.');
      return;
    }
    setUploading(true);
    setUploadError('');
    try {
      const res = await analysisAPI.analyzeReport(reportFile);
      setActiveAnalysisResult({
        type: 'VAPT Report',
        title: res.filename,
        count: res.vulnerabilities_count,
        findings: res.findings
      });
      setReportFile(null);
      setShowAnalysisModal(false);
      fetchData();
    } catch (err) {
      setUploadError(err.response?.data?.detail || 'Failed to analyze VAPT report.');
    } finally {
      setUploading(false);
    }
  };

  const handleRunSourceAnalysis = async (e) => {
    e.preventDefault();
    if (!sourceFile && !sourceCodeText.trim()) {
      setUploadError('Please select a source code file or paste code.');
      return;
    }
    setUploading(true);
    setUploadError('');
    try {
      const res = await analysisAPI.analyzeSourceCode({
        file: sourceFile,
        codeContent: sourceCodeText,
        filename: sourceFileName || (sourceFile ? sourceFile.name : 'pasted_code.py'),
        language: sourceLanguage || undefined
      });
      setActiveAnalysisResult({
        type: 'Source Code Analysis',
        title: res.filename,
        count: res.vulnerabilities_found,
        findings: res.findings
      });
      setSourceFile(null);
      setSourceCodeText('');
      setShowAnalysisModal(false);
      fetchData();
    } catch (err) {
      setUploadError(err.response?.data?.detail || 'Failed to scan source code.');
    } finally {
      setUploading(false);
    }
  };

  const handleRunCombinedAnalysis = async (e) => {
    e.preventDefault();
    if (!combReportFile || !combSourceFile) {
      setUploadError('Please provide both a VAPT report and a source code package.');
      return;
    }
    setUploading(true);
    setUploadError('');
    try {
      const res = await analysisAPI.analyzeCombined(combReportFile, combSourceFile);
      setActiveAnalysisResult({
        type: 'Combined Correlation',
        title: `${res.report_filename} + ${res.source_filename}`,
        count: res.total_correlated_findings,
        confirmedCount: res.confirmed_in_code_count,
        findings: res.findings
      });
      setCombReportFile(null);
      setCombSourceFile(null);
      setShowAnalysisModal(false);
      fetchData();
    } catch (err) {
      setUploadError(err.response?.data?.detail || 'Failed to run combined correlation analysis.');
    } finally {
      setUploading(false);
    }
  };

  const handleDeleteReport = async (id) => {
    if (window.confirm("Are you sure you want to delete this report and all its vulnerabilities?")) {
      try {
        await reportAPI.deleteReport(id);
        fetchData();
      } catch (err) {
        alert("Failed to delete report.");
      }
    }
  };

  const handleDownloadReport = async (report) => {
    if (!report) return;
    setDownloadingReportId(report.id);
    try {
      const cleanName = report.filename.replace(/\.[^/.]+$/, "");
      await reportAPI.downloadReport(report.id, `VAPT_Analysis_Report_${cleanName}.pdf`);
    } catch (err) {
      console.error("Failed to download PDF report", err);
      alert(err.response?.data?.detail || "Failed to download PDF report.");
    } finally {
      setDownloadingReportId(null);
    }
  };

  // KPI Calculations
  const totalReports = reports.length;
  const openVulns = vulnerabilities.filter(v => v.status === 'Open').length;
  const criticalHighVulns = vulnerabilities.filter(v => ['Critical', 'High'].includes(v.severity)).length;
  const resolvedVulns = vulnerabilities.filter(v => v.status === 'Resolved').length;

  // Chart 1: Severity Breakdown
  const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  const capitalize = (str) => {
    if (!str) return 'Medium';
    return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
  };

  vulnerabilities.forEach(v => {
    const s = capitalize(v.severity);
    if (severityCounts[s] !== undefined) {
      severityCounts[s]++;
    }
  });

  const severityChartData = Object.keys(severityCounts).map(key => ({
    name: key,
    value: severityCounts[key]
  })).filter(item => item.value > 0);

  const SEVERITY_COLORS = {
    Critical: '#ef4444',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#3b82f6',
    Info: '#64748b'
  };

  // Chart 2: Open vs Resolved per Report
  const reportBreakdown = {};
  reports.forEach(r => {
    reportBreakdown[r.filename] = { name: r.filename.substring(0, 15), Open: 0, Resolved: 0 };
  });
  vulnerabilities.forEach(v => {
    if (reportBreakdown[v.report_name]) {
      if (v.status === 'Open') reportBreakdown[v.report_name].Open++;
      else reportBreakdown[v.report_name].Resolved++;
    }
  });
  const reportChartData = Object.values(reportBreakdown);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header section */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold font-outfit text-white tracking-wide flex items-center gap-3">
            <span>AI Security Remediation Engine</span>
            <span className="px-2.5 py-0.5 text-xs bg-primary-500/20 text-primary-400 border border-primary-500/30 rounded-full font-sans">
              v2.0
            </span>
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Autonomous vulnerability detection, Knowledge Base enrichment, and language-specific code remediation.
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <button
            onClick={fetchData}
            className="flex items-center justify-center p-3 text-slate-400 bg-slate-900 border border-slate-800 rounded-xl hover:text-white hover:border-slate-700 transition-all"
            title="Refresh Data"
          >
            <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
          </button>
          <button
            onClick={() => navigate('/source-code')}
            className="flex items-center gap-2 bg-slate-900 border border-slate-700 hover:border-primary-500/50 hover:bg-slate-800 text-slate-200 font-semibold px-4 py-3 rounded-xl transition-all shadow-lg active:scale-[0.98]"
          >
            <FolderGit2 size={18} className="text-primary-400" />
            <span>SAST Scanner</span>
          </button>
          <button
            onClick={() => {
              setUploadError('');
              setShowAnalysisModal(true);
            }}
            className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white font-semibold px-5 py-3 rounded-xl transition-all shadow-lg hover:shadow-primary-600/20 active:scale-[0.98]"
          >
            <Sparkles size={18} />
            <span>Analyze & Remediate</span>
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex flex-col items-center justify-center py-32 text-slate-500">
          <Loader size={36} className="animate-spin text-primary-500 mb-4" />
          <span>Loading security intelligence...</span>
        </div>
      ) : (
        <>
          {/* RECENT LIVE ANALYSIS RESULTS PANEL */}
          {activeAnalysisResult && (
            <div className="mb-8 p-6 glass-panel rounded-2xl border border-primary-500/30 shadow-2xl relative overflow-hidden bg-primary-500/[0.02]">
              <div className="flex items-center justify-between mb-4 border-b border-slate-800/80 pb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-primary-500/10 border border-primary-500/20 rounded-xl text-primary-400">
                    <Sparkles size={22} />
                  </div>
                  <div>
                    <span className="text-xs font-semibold text-primary-400 uppercase tracking-wider">
                      Live Analysis Output • {activeAnalysisResult.type}
                    </span>
                    <h3 className="text-xl font-bold font-outfit text-white">
                      {activeAnalysisResult.title} ({activeAnalysisResult.count} Vulnerabilities Detected)
                    </h3>
                  </div>
                </div>
                <button
                  onClick={() => setActiveAnalysisResult(null)}
                  className="text-xs text-slate-400 hover:text-white px-3 py-1.5 bg-slate-800 rounded-lg"
                >
                  Dismiss
                </button>
              </div>

              {/* Findings Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-sm">
                  <thead>
                    <tr className="border-b border-slate-800 text-xs font-bold uppercase tracking-wider text-slate-400">
                      <th className="py-3 px-4">Finding</th>
                      <th className="py-3 px-4">CWE</th>
                      <th className="py-3 px-4">Severity</th>
                      <th className="py-3 px-4">Language / Target</th>
                      <th className="py-3 px-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50 text-slate-300">
                    {activeAnalysisResult.findings.map((f, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                        <td className="py-3 px-4 font-semibold text-white">
                          <div className="flex items-center gap-2">
                            <span>{f.vulnerability}</span>
                            {f.correlation_status && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                {f.correlation_status}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-4 font-mono text-xs text-primary-400">{f.cwe_id}</td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${
                            (f.severity || '').toLowerCase() === 'critical' ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' :
                            (f.severity || '').toLowerCase() === 'high' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' :
                            'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
                          }`}>
                            {f.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-xs font-mono text-slate-400">
                          <span className="text-indigo-400 font-semibold">{f.language || 'Unknown'}</span>
                          <span className="text-slate-500 block truncate max-w-xs">{f.file}:{f.line || 1}</span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => setInspectingFinding(f)}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-primary-500/10 hover:bg-primary-500/20 text-primary-400 hover:text-primary-300 border border-primary-500/20 rounded-xl text-xs font-semibold transition-all"
                          >
                            <Sparkles size={13} />
                            <span>Inspect AI Fix</span>
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* KPI Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div className="glass-panel p-6 rounded-2xl hover-scale">
              <div className="flex items-center justify-between mb-4">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Reports Analyzed</span>
                <div className="p-2 bg-slate-800/60 border border-slate-700/50 rounded-lg text-slate-300">
                  <FileText size={18} />
                </div>
              </div>
              <h2 className="text-3xl font-bold text-white font-outfit">{totalReports}</h2>
              <p className="text-xs text-slate-500 mt-1">Active document scans</p>
            </div>

            <div className="glass-panel p-6 rounded-2xl hover-scale">
              <div className="flex items-center justify-between mb-4">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Open Findings</span>
                <div className="p-2 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400">
                  <AlertTriangle size={18} />
                </div>
              </div>
              <h2 className="text-3xl font-bold text-white font-outfit">{openVulns}</h2>
              <p className="text-xs text-slate-500 mt-1">Pending remediation</p>
            </div>

            <div className="glass-panel p-6 rounded-2xl hover-scale">
              <div className="flex items-center justify-between mb-4">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">High / Critical</span>
                <div className="p-2 bg-amber-500/10 border border-amber-500/20 rounded-lg text-amber-400">
                  <ShieldCheck size={18} />
                </div>
              </div>
              <h2 className="text-3xl font-bold text-white font-outfit">{criticalHighVulns}</h2>
              <p className="text-xs text-slate-500 mt-1">Require immediate patch</p>
            </div>

            <div className="glass-panel p-6 rounded-2xl hover-scale">
              <div className="flex items-center justify-between mb-4">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Resolved</span>
                <div className="p-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-emerald-400">
                  <CheckCircle size={18} />
                </div>
              </div>
              <h2 className="text-3xl font-bold text-white font-outfit">{resolvedVulns}</h2>
              <p className="text-xs text-slate-500 mt-1">Fixed vulnerabilities</p>
            </div>
          </div>

          {/* Visual Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
            <div className="glass-panel p-6 rounded-2xl flex flex-col">
              <h3 className="text-lg font-bold font-outfit text-white mb-2">Severity Distribution</h3>
              <p className="text-slate-400 text-xs mb-4">Aggregated findings categorized by threat severity</p>
              <div className="flex-1 min-h-[260px] flex items-center justify-center">
                {severityChartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={260}>
                    <PieChart>
                      <Pie
                        data={severityChartData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={90}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {severityChartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name] || '#3b82f6'} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          borderColor: '#1e293b',
                          borderRadius: '12px',
                          color: '#f8fafc',
                          fontSize: '12px'
                        }}
                      />
                      <Legend
                        verticalAlign="bottom"
                        height={36}
                        formatter={(value) => <span className="text-xs text-slate-300 mr-2">{value}</span>}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <span className="text-slate-500 text-sm">No findings detected yet.</span>
                )}
              </div>
            </div>

            <div className="glass-panel p-6 rounded-2xl flex flex-col">
              <h3 className="text-lg font-bold font-outfit text-white mb-2">Findings per Report</h3>
              <p className="text-slate-400 text-xs mb-4">Comparison of Open vs. Resolved items across reports</p>
              <div className="flex-1 min-h-[260px] flex items-center justify-center">
                {reportChartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={260}>
                    <BarChart data={reportChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                      <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                      <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          borderColor: '#1e293b',
                          borderRadius: '12px',
                          color: '#f8fafc',
                          fontSize: '12px'
                        }}
                      />
                      <Legend
                        verticalAlign="bottom"
                        height={36}
                        formatter={(value) => <span className="text-xs text-slate-300 mr-2">{value}</span>}
                      />
                      <Bar dataKey="Open" fill="#ef4444" radius={[4, 4, 0, 0]} />
                      <Bar dataKey="Resolved" fill="#10b981" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <span className="text-slate-500 text-sm">No report data to graph.</span>
                )}
              </div>
            </div>
          </div>

          {/* Uploaded Documents Table */}
          <div className="glass-panel rounded-2xl overflow-hidden border border-slate-800/80 mb-8">
            <div className="p-6 border-b border-slate-800/80 flex items-center justify-between">
              <div>
                <h3 className="text-lg font-bold font-outfit text-white">Vulnerability Reports</h3>
                <p className="text-slate-400 text-xs mt-1">Export executive PDF reports or browse findings</p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-xs font-bold uppercase tracking-wider text-slate-400 bg-slate-900/30">
                    <th className="py-4 px-6">Report File</th>
                    <th className="py-4 px-6">Status</th>
                    <th className="py-4 px-6">Vulnerabilities</th>
                    <th className="py-4 px-6 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-sm text-slate-300">
                  {reports.length > 0 ? (
                    reports.map((report) => (
                      <tr key={report.id} className="hover:bg-slate-900/40 transition-colors">
                        <td className="py-4 px-6">
                          <div className="flex items-center gap-3">
                            <div className="p-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-300">
                              <FileText size={16} />
                            </div>
                            <span className="font-semibold text-white truncate max-w-sm">{report.filename}</span>
                          </div>
                        </td>
                        <td className="py-4 px-6">
                          <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${
                            report.status === 'Completed'
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                              : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                          }`}>
                            {report.status}
                          </span>
                        </td>
                        <td className="py-4 px-6">
                          <span className="font-semibold text-white">{report.vulnerabilities_count || 0}</span>
                        </td>
                        <td className="py-4 px-6 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => handleDownloadReport(report)}
                              className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
                              title="Download PDF Summary"
                              disabled={downloadingReportId === report.id}
                            >
                              {downloadingReportId === report.id ? (
                                <Loader size={16} className="animate-spin text-primary-400" />
                              ) : (
                                <Download size={16} />
                              )}
                            </button>
                            <button
                              onClick={() => navigate(`/vulnerabilities?report=${encodeURIComponent(report.filename)}`)}
                              className="p-2 text-slate-400 hover:text-primary-400 hover:bg-slate-800 rounded-lg transition-colors"
                              title="View Findings"
                            >
                              <ExternalLink size={16} />
                            </button>
                            <button
                              onClick={() => handleDeleteReport(report.id)}
                              className="p-2 text-slate-400 hover:text-red-400 hover:bg-slate-800 rounded-lg transition-colors"
                              title="Delete Report"
                            >
                              <Trash2 size={16} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="4" className="text-center py-10 text-slate-500 text-sm">
                        No reports analyzed yet. Click "Analyze & Remediate" to start.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* UNIFIED 3-OPTION ANALYSIS MODAL */}
      {showAnalysisModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-dark-950/80 backdrop-blur-sm">
          <div className="w-full max-w-2xl glass-panel rounded-2xl p-6 relative border border-slate-800 shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold font-outfit text-white flex items-center gap-2">
                <Sparkles size={22} className="text-primary-400" />
                <span>AI Vulnerability & Remediation Engine</span>
              </h3>
              <button
                onClick={() => setShowAnalysisModal(false)}
                className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg"
              >
                <X size={18} />
              </button>
            </div>

            {/* Workflow Mode Selector (Option A, B, C) */}
            <div className="grid grid-cols-3 gap-2 p-1.5 bg-slate-900 border border-slate-800 rounded-xl mb-6">
              <button
                onClick={() => {
                  setAnalysisTab('report');
                  setUploadError('');
                }}
                className={`py-2 px-3 rounded-lg text-xs font-semibold transition-all flex items-center justify-center gap-1.5 ${
                  analysisTab === 'report'
                    ? 'bg-primary-600 text-white shadow-md'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <FileText size={14} />
                <span>Option A: VAPT Report</span>
              </button>

              <button
                onClick={() => {
                  setAnalysisTab('source');
                  setUploadError('');
                }}
                className={`py-2 px-3 rounded-lg text-xs font-semibold transition-all flex items-center justify-center gap-1.5 ${
                  analysisTab === 'source'
                    ? 'bg-primary-600 text-white shadow-md'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Code2 size={14} />
                <span>Option B: Source Code</span>
              </button>

              <button
                onClick={() => {
                  setAnalysisTab('combined');
                  setUploadError('');
                }}
                className={`py-2 px-3 rounded-lg text-xs font-semibold transition-all flex items-center justify-center gap-1.5 ${
                  analysisTab === 'combined'
                    ? 'bg-primary-600 text-white shadow-md'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Layers size={14} />
                <span>Option C: Combined</span>
              </button>
            </div>

            {uploadError && (
              <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-xl flex items-center gap-2">
                <AlertTriangle size={16} />
                <span>{uploadError}</span>
              </div>
            )}

            <div className="flex-1 overflow-y-auto pr-1">
              {/* TAB A: VAPT REPORT */}
              {analysisTab === 'report' && (
                <form onSubmit={handleRunReportAnalysis} className="space-y-4">
                  <p className="text-slate-400 text-xs">
                    Upload a penetration testing report (.pdf, .docx, .txt, or image). The engine extracts findings, matches them with the Knowledge Base, and synthesizes language-specific AI fixes.
                  </p>

                  <div className="border-2 border-dashed border-slate-800 hover:border-primary-500/50 rounded-2xl p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-colors relative">
                    <input
                      type="file"
                      required
                      accept=".pdf,.docx,.txt,.png,.jpg,.jpeg,.webp,.gif,image/*"
                      onChange={(e) => setReportFile(e.target.files[0])}
                      className="absolute inset-0 opacity-0 cursor-pointer"
                      disabled={uploading}
                    />
                    {reportFile ? (
                      <>
                        <CheckCircle className="text-emerald-500 mb-2" size={32} />
                        <span className="text-slate-200 text-sm font-semibold truncate max-w-xs">{reportFile.name}</span>
                        <span className="text-slate-500 text-xs mt-1">{(reportFile.size / 1024 / 1024).toFixed(2)} MB</span>
                      </>
                    ) : (
                      <>
                        <Upload className="text-slate-600 mb-2" size={32} />
                        <span className="text-slate-300 text-sm font-semibold">Select VAPT Report (.pdf, .docx, .txt, image)</span>
                        <span className="text-slate-500 text-xs mt-1">Extracts vulnerabilities, lines, and generates AI remediation</span>
                      </>
                    )}
                  </div>

                  <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                    <button
                      type="button"
                      onClick={() => setShowAnalysisModal(false)}
                      className="px-4 py-2 text-xs font-semibold bg-slate-900 border border-slate-800 rounded-xl hover:text-white"
                      disabled={uploading}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-5 py-2.5 text-xs font-semibold bg-primary-600 hover:bg-primary-700 text-white rounded-xl flex items-center gap-2 shadow-lg"
                      disabled={uploading || !reportFile}
                    >
                      {uploading ? <Loader size={14} className="animate-spin" /> : <Sparkles size={14} />}
                      <span>Analyze Report</span>
                    </button>
                  </div>
                </form>
              )}

              {/* TAB B: SOURCE CODE */}
              {analysisTab === 'source' && (
                <form onSubmit={handleRunSourceAnalysis} className="space-y-4">
                  <p className="text-slate-400 text-xs">
                    Upload source files (.py, .java, .cpp, .c, .js, .ts, .php, .cs, .go, .rb, or .zip archive) or paste code below. Automatic language and framework detection runs instantly.
                  </p>

                  {/* File Upload Option */}
                  <div className="border-2 border-dashed border-slate-800 hover:border-primary-500/50 rounded-2xl p-6 flex flex-col items-center justify-center text-center cursor-pointer relative">
                    <input
                      type="file"
                      accept=".py,.java,.cpp,.cc,.c,.h,.js,.ts,.tsx,.jsx,.php,.cs,.go,.rb,.zip"
                      onChange={(e) => setSourceFile(e.target.files[0])}
                      className="absolute inset-0 opacity-0 cursor-pointer"
                      disabled={uploading}
                    />
                    {sourceFile ? (
                      <>
                        <CheckCircle className="text-emerald-500 mb-2" size={28} />
                        <span className="text-slate-200 text-sm font-semibold truncate max-w-xs">{sourceFile.name}</span>
                        <span className="text-slate-500 text-xs mt-1">{(sourceFile.size / 1024 / 1024).toFixed(2)} MB</span>
                      </>
                    ) : (
                      <>
                        <FileCode className="text-slate-600 mb-2" size={28} />
                        <span className="text-slate-300 text-xs font-semibold">Upload Single Source File or Project .ZIP</span>
                        <span className="text-slate-500 text-[11px] mt-1">Supports Python, Java, C/C++, JS/TS, PHP, C#, Go</span>
                      </>
                    )}
                  </div>

                  {/* OR Paste Code */}
                  <div className="relative flex py-1 items-center">
                    <div className="flex-grow border-t border-slate-800"></div>
                    <span className="flex-shrink mx-3 text-slate-500 text-xs uppercase tracking-wider font-semibold">OR Paste Snippet</span>
                    <div className="flex-grow border-t border-slate-800"></div>
                  </div>

                  <div className="space-y-2">
                    <div className="grid grid-cols-2 gap-2">
                      <input
                        type="text"
                        placeholder="Filename (e.g. login.py, app.java)"
                        value={sourceFileName}
                        onChange={(e) => setSourceFileName(e.target.value)}
                        className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 outline-none focus:border-primary-500"
                      />
                      <select
                        value={sourceLanguage}
                        onChange={(e) => setSourceLanguage(e.target.value)}
                        className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 outline-none focus:border-primary-500"
                      >
                        <option value="">Auto-Detect Language</option>
                        <option value="python">Python</option>
                        <option value="java">Java</option>
                        <option value="javascript">JavaScript / React</option>
                        <option value="typescript">TypeScript</option>
                        <option value="c">C</option>
                        <option value="cpp">C++</option>
                        <option value="php">PHP</option>
                        <option value="csharp">C# (.NET)</option>
                        <option value="go">Go</option>
                      </select>
                    </div>

                    <textarea
                      placeholder="// Paste your source code snippet here..."
                      rows={5}
                      value={sourceCodeText}
                      onChange={(e) => setSourceCodeText(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 font-mono text-xs text-slate-300 outline-none focus:border-primary-500"
                    />
                  </div>

                  <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                    <button
                      type="button"
                      onClick={() => setShowAnalysisModal(false)}
                      className="px-4 py-2 text-xs font-semibold bg-slate-900 border border-slate-800 rounded-xl hover:text-white"
                      disabled={uploading}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-5 py-2.5 text-xs font-semibold bg-primary-600 hover:bg-primary-700 text-white rounded-xl flex items-center gap-2 shadow-lg"
                      disabled={uploading || (!sourceFile && !sourceCodeText.trim())}
                    >
                      {uploading ? <Loader size={14} className="animate-spin" /> : <Sparkles size={14} />}
                      <span>Scan & Remediate</span>
                    </button>
                  </div>
                </form>
              )}

              {/* TAB C: COMBINED */}
              {analysisTab === 'combined' && (
                <form onSubmit={handleRunCombinedAnalysis} className="space-y-4">
                  <p className="text-slate-400 text-xs">
                    Cross-correlate a VAPT report with actual source code. The engine verifies report claims against source code ground truth, confirms flaws, and generates verified code replacements.
                  </p>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    {/* Report File */}
                    <div className="border border-slate-800 rounded-xl p-4 bg-slate-900/40 text-center relative">
                      <span className="text-xs font-bold text-slate-300 block mb-2">1. VAPT Report File</span>
                      <input
                        type="file"
                        required
                        accept=".pdf,.docx,.txt,image/*"
                        onChange={(e) => setCombReportFile(e.target.files[0])}
                        className="text-xs text-slate-400 file:mr-2 file:py-1 file:px-2 file:rounded-lg file:border-0 file:text-xs file:bg-primary-500/20 file:text-primary-400"
                      />
                    </div>

                    {/* Source File */}
                    <div className="border border-slate-800 rounded-xl p-4 bg-slate-900/40 text-center relative">
                      <span className="text-xs font-bold text-slate-300 block mb-2">2. Source Code (.zip or file)</span>
                      <input
                        type="file"
                        required
                        accept=".zip,.py,.java,.cpp,.c,.js,.ts,.php,.cs,.go"
                        onChange={(e) => setCombSourceFile(e.target.files[0])}
                        className="text-xs text-slate-400 file:mr-2 file:py-1 file:px-2 file:rounded-lg file:border-0 file:text-xs file:bg-primary-500/20 file:text-primary-400"
                      />
                    </div>
                  </div>

                  <div className="p-3 bg-primary-500/5 border border-primary-500/15 rounded-xl text-xs text-slate-300 flex items-start gap-2">
                    <Sparkles size={16} className="text-primary-400 shrink-0 mt-0.5" />
                    <span>
                      High-Confidence Workflow: Correlates report line numbers and CWE identifiers directly with the uploaded code files to prove exploitability and generate line-by-line patch code.
                    </span>
                  </div>

                  <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                    <button
                      type="button"
                      onClick={() => setShowAnalysisModal(false)}
                      className="px-4 py-2 text-xs font-semibold bg-slate-900 border border-slate-800 rounded-xl hover:text-white"
                      disabled={uploading}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-5 py-2.5 text-xs font-semibold bg-primary-600 hover:bg-primary-700 text-white rounded-xl flex items-center gap-2 shadow-lg"
                      disabled={uploading || !combReportFile || !combSourceFile}
                    >
                      {uploading ? <Loader size={14} className="animate-spin" /> : <Sparkles size={14} />}
                      <span>Run Combined Correlation</span>
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Slide-over Deep AI Remediation Inspector */}
      {inspectingFinding && (
        <RemediationInspector
          finding={inspectingFinding}
          onClose={() => setInspectingFinding(null)}
        />
      )}
    </div>
  );
};

export default Dashboard;
