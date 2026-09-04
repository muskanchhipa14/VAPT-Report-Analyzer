import React, { useState, useEffect } from 'react';
import { sourceCodeAPI } from '../services/api';
import {
  Upload, FileCode2, ShieldAlert, CheckCircle2,
  Trash2, Download, Search, Sparkles, Layers,
  Code2, RefreshCw, AlertTriangle,
  FolderGit2, Terminal, Info, X, ChevronRight, Copy, Check
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';

const SourceCodeScanner = () => {
  const [analyses, setAnalyses] = useState([]);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [analysisDetail, setAnalysisDetail] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);

  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadError, setUploadError] = useState('');
  const [copiedFix, setCopiedFix] = useState(false);
  const [downloading, setDownloading] = useState(false);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [languageFilter, setLanguageFilter] = useState('');
  const [confidenceFilter, setConfidenceFilter] = useState('');

  const fetchAnalyses = async (selectLatest = false) => {
    setLoading(true);
    try {
      const data = await sourceCodeAPI.getAnalyses();
      setAnalyses(data);
      if (data.length > 0) {
        const target = selectLatest ? data[0] : (selectedAnalysis ? data.find(a => a.id === selectedAnalysis.id) || data[0] : data[0]);
        setSelectedAnalysis(target);
        fetchAnalysisDetail(target.id);
      } else {
        setSelectedAnalysis(null);
        setAnalysisDetail(null);
      }
    } catch (e) {
      console.error('Failed to load source code analyses', e);
    } finally {
      setLoading(false);
    }
  };

  const fetchAnalysisDetail = async (id) => {
    setDetailLoading(true);
    try {
      const detail = await sourceCodeAPI.getAnalysis(id);
      setAnalysisDetail(detail);
      setSelectedFinding(null);
    } catch (e) {
      console.error(`Failed to load analysis detail for ID ${id}`, e);
    } finally {
      setDetailLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalyses(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSelectAnalysis = (analysis) => {
    setSelectedAnalysis(analysis);
    fetchAnalysisDetail(analysis.id);
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      if (!file.name.toLowerCase().endsWith('.zip')) {
        setUploadError('Only .zip archive packages are supported.');
        setSelectedFile(null);
        return;
      }
      setSelectedFile(file);
      setUploadError('');
    }
  };

  const handleUploadAndScan = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      setUploadError('Please select a .zip project file.');
      return;
    }

    setUploading(true);
    setUploadError('');
    try {
      const result = await sourceCodeAPI.uploadAndScan(selectedFile);
      setSelectedFile(null);
      setShowUploadModal(false);
      await fetchAnalyses(true);
      if (result.analysis_id) {
        await fetchAnalysisDetail(result.analysis_id);
      }
    } catch (err) {
      setUploadError(err.response?.data?.detail || 'Failed to analyze source code project.');
    } finally {
      setUploading(false);
    }
  };

  const handleDeleteAnalysis = async (id) => {
    if (window.confirm('Are you sure you want to delete this source code scan and all its findings?')) {
      try {
        await sourceCodeAPI.deleteAnalysis(id);
        fetchAnalyses(true);
      } catch (err) {
        alert('Failed to delete analysis record.');
      }
    }
  };

  const handleDownloadReport = async (analysis) => {
    if (!analysis) return;
    setDownloading(true);
    try {
      const filename = `SAST_Security_Report_${analysis.project_name.replace(/\s+/g, '_')}.pdf`;
      await sourceCodeAPI.downloadReport(analysis.id, filename);
    } catch (e) {
      console.error('Failed to download PDF report', e);
      alert(e.response?.data?.detail || 'Failed to download SAST PDF report.');
    } finally {
      setDownloading(false);
    }
  };

  const handleCopyFix = (codeText) => {
    if (!codeText) return;
    navigator.clipboard.writeText(codeText);
    setCopiedFix(true);
    setTimeout(() => setCopiedFix(false), 2000);
  };

  // Severity Colors
  const SEVERITY_COLORS = {
    Critical: '#ef4444',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#3b82f6',
    Info: '#64748b',
  };

  const getSeverityBadgeClass = (sev) => {
    const s = (sev || 'Medium').toLowerCase();
    if (s === 'critical') return 'bg-red-500/10 text-red-400 border border-red-500/20';
    if (s === 'high') return 'bg-orange-500/10 text-orange-400 border border-orange-500/20';
    if (s === 'medium') return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20';
    if (s === 'low') return 'bg-blue-500/10 text-blue-400 border border-blue-500/20';
    return 'bg-slate-500/10 text-slate-400 border border-slate-500/20';
  };

  const getLanguageBadgeClass = (lang) => {
    const l = (lang || '').toLowerCase();
    if (l === 'python') return 'bg-blue-500/10 text-blue-400 border border-blue-500/20';
    if (l === 'javascript') return 'bg-amber-500/10 text-amber-300 border border-amber-500/20';
    if (l === 'java') return 'bg-red-500/10 text-red-300 border border-red-500/20';
    return 'bg-slate-800 text-slate-300 border border-slate-700';
  };

  // Filter findings
  const rawFindings = analysisDetail?.findings || [];
  const filteredFindings = rawFindings.filter((f) => {
    const matchesSearch =
      f.vulnerability_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.cwe_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.file_name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter ? f.severity.toLowerCase() === severityFilter.toLowerCase() : true;
    const matchesLanguage = languageFilter ? f.language.toLowerCase() === languageFilter.toLowerCase() : true;
    const matchesConfidence = confidenceFilter ? f.confidence.toLowerCase() === confidenceFilter.toLowerCase() : true;

    return matchesSearch && matchesSeverity && matchesLanguage && matchesConfidence;
  });

  // Chart data calculations
  const severityBreakdown = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  rawFindings.forEach((f) => {
    const s = f.severity ? f.severity.charAt(0).toUpperCase() + f.severity.slice(1).toLowerCase() : 'Medium';
    if (severityBreakdown[s] !== undefined) severityBreakdown[s]++;
    else severityBreakdown['Medium']++;
  });
  const severityChartData = Object.keys(severityBreakdown)
    .map((k) => ({ name: k, value: severityBreakdown[k] }))
    .filter((d) => d.value > 0);

  const languageBreakdown = {};
  rawFindings.forEach((f) => {
    const l = f.language ? f.language.charAt(0).toUpperCase() + f.language.slice(1).toLowerCase() : 'Unknown';
    languageBreakdown[l] = (languageBreakdown[l] || 0) + 1;
  });
  const languageChartData = Object.keys(languageBreakdown).map((k) => ({
    name: k,
    findings: languageBreakdown[k],
  }));

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 relative">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider rounded-md bg-primary-500/10 text-primary-400 border border-primary-500/20">
              SAST Engine
            </span>
            <span className="text-xs text-slate-500">AST & Structural Static Analyzer</span>
          </div>
          <h1 className="text-3xl font-bold font-outfit text-white tracking-wide mt-1">Source Code Scanner</h1>
          <p className="text-slate-400 text-sm mt-1">
            Analyze Python, JavaScript/React, and Java repositories for security flaws with Knowledge Base remediation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchAnalyses(false)}
            className="p-3 text-slate-400 bg-slate-900 border border-slate-800 rounded-xl hover:text-white hover:border-slate-700 transition-all"
            title="Refresh Scans"
          >
            <RefreshCw size={18} className={loading || detailLoading ? 'animate-spin' : ''} />
          </button>
          <button
            onClick={() => setShowUploadModal(true)}
            className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white font-semibold px-5 py-3 rounded-xl transition-all shadow-lg hover:shadow-primary-600/10 active:scale-[0.98]"
          >
            <FolderGit2 size={18} />
            <span>Scan Project ZIP</span>
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex flex-col items-center justify-center py-32 text-slate-500">
          <div className="w-10 h-10 border-4 border-primary-500/20 border-t-primary-500 rounded-full animate-spin mb-4"></div>
          <span>Loading source code analysis history...</span>
        </div>
      ) : analyses.length === 0 ? (
        <div className="glass-panel p-16 rounded-2xl border border-slate-800 text-center flex flex-col items-center justify-center">
          <div className="p-4 bg-primary-500/10 rounded-2xl text-primary-400 mb-4 border border-primary-500/20">
            <Code2 size={48} />
          </div>
          <h3 className="text-xl font-bold font-outfit text-white mb-2">No Source Code Projects Scanned Yet</h3>
          <p className="text-slate-400 text-sm max-w-md mb-6">
            Upload your project ZIP archive to scan Python, JavaScript/JSX, TypeScript, and Java files for security vulnerabilities and automated fixes.
          </p>
          <button
            onClick={() => setShowUploadModal(true)}
            className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white font-semibold px-6 py-3 rounded-xl transition-all shadow-lg"
          >
            <Upload size={18} />
            <span>Upload Your First Project</span>
          </button>
        </div>
      ) : (
        <>
          {/* Analysis Selector Toolbar */}
          <div className="glass-panel p-4 rounded-2xl border border-slate-800/80 mb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Active Project:</span>
              <select
                className="bg-slate-900 border border-slate-800 text-white text-sm font-semibold rounded-xl px-4 py-2 outline-none focus:border-primary-500 transition-colors"
                value={selectedAnalysis?.id || ''}
                onChange={(e) => {
                  const target = analyses.find((a) => a.id === parseInt(e.target.value));
                  if (target) handleSelectAnalysis(target);
                }}
              >
                {analyses.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.project_name} ({a.filename}) — {a.vulnerabilities_count} findings
                  </option>
                ))}
              </select>
            </div>

            {selectedAnalysis && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleDownloadReport(selectedAnalysis)}
                  disabled={downloading}
                  className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-slate-300 hover:text-white bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl transition-all active:scale-95 disabled:opacity-50"
                  title="Download SAST PDF Report"
                >
                  <Download size={14} className={downloading ? 'animate-bounce text-primary-400' : 'text-primary-400'} />
                  <span>{downloading ? 'Downloading...' : 'Download PDF'}</span>
                </button>
                <button
                  onClick={() => handleDeleteAnalysis(selectedAnalysis.id)}
                  className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-red-400 hover:text-red-300 bg-red-500/10 border border-red-500/20 hover:border-red-500/30 rounded-xl transition-all"
                  title="Delete Analysis"
                >
                  <Trash2 size={14} />
                  <span>Delete</span>
                </button>
              </div>
            )}
          </div>

          {/* KPI Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div className="glass-panel p-6 rounded-2xl hover-scale">
              <div className="flex items-center justify-between mb-3">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Files Scanned</span>
                <div className="p-2 bg-slate-800/60 border border-slate-700/50 rounded-lg text-slate-300">
                  <FileCode2 size={18} />
                </div>
              </div>
              <h2 className="text-3xl font-bold text-white font-outfit">{selectedAnalysis?.files_scanned || 0}</h2>
              <p className="text-xs text-slate-500 mt-1">Source modules analyzed</p>
            </div>

            <div className="glass-panel p-6 rounded-2xl hover-scale">
              <div className="flex items-center justify-between mb-3">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Lines of Code</span>
                <div className="p-2 bg-slate-800/60 border border-slate-700/50 rounded-lg text-primary-400">
                  <Terminal size={18} />
                </div>
              </div>
              <h2 className="text-3xl font-bold text-white font-outfit">
                {(selectedAnalysis?.lines_scanned || 0).toLocaleString()}
              </h2>
              <p className="text-xs text-slate-500 mt-1">Total scanned statements</p>
            </div>

            <div className="glass-panel p-6 rounded-2xl hover-scale">
              <div className="flex items-center justify-between mb-3">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Total Findings</span>
                <div className="p-2 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400">
                  <ShieldAlert size={18} />
                </div>
              </div>
              <h2 className="text-3xl font-bold text-white font-outfit">
                {selectedAnalysis?.vulnerabilities_count || 0}
              </h2>
              <p className="text-xs text-red-400 mt-1">Security rules triggered</p>
            </div>

            <div className="glass-panel p-6 rounded-2xl hover-scale">
              <div className="flex items-center justify-between mb-3">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Critical & High</span>
                <div className="p-2 bg-orange-500/10 border border-orange-500/20 rounded-lg text-orange-400">
                  <AlertTriangle size={18} />
                </div>
              </div>
              <h2 className="text-3xl font-bold text-white font-outfit">
                {(selectedAnalysis?.critical_count || 0) + (selectedAnalysis?.high_count || 0)}
              </h2>
              <p className="text-xs text-orange-400 mt-1">Immediate remediation targets</p>
            </div>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 mb-8">
            {/* Severity Breakdown Donut */}
            <div className="glass-panel p-6 rounded-2xl lg:col-span-2 flex flex-col h-[320px]">
              <h3 className="text-slate-200 text-sm font-semibold tracking-wider uppercase mb-4">Severity Breakdown</h3>
              <div className="flex-1 relative">
                {severityChartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityChartData}
                        cx="50%"
                        cy="50%"
                        innerRadius={55}
                        outerRadius={75}
                        paddingAngle={4}
                        dataKey="value"
                      >
                        {severityChartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name] || '#334155'} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '8px' }}
                        itemStyle={{ color: '#fff' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center text-slate-500 text-sm">
                    No vulnerabilities detected
                  </div>
                )}
              </div>
              <div className="grid grid-cols-3 gap-2 mt-3 text-xs text-slate-400">
                {Object.keys(severityBreakdown).map(
                  (sev) =>
                    severityBreakdown[sev] > 0 && (
                      <div key={sev} className="flex items-center gap-1.5">
                        <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ backgroundColor: SEVERITY_COLORS[sev] }}></span>
                        <span>{sev}: {severityBreakdown[sev]}</span>
                      </div>
                    )
                )}
              </div>
            </div>

            {/* Findings by Language Bar */}
            <div className="glass-panel p-6 rounded-2xl lg:col-span-3 h-[320px] flex flex-col">
              <h3 className="text-slate-200 text-sm font-semibold tracking-wider uppercase mb-4">Vulnerabilities by Language</h3>
              <div className="flex-1">
                {languageChartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={languageChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                      <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                      <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                      <Tooltip
                        contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '8px' }}
                        itemStyle={{ color: '#fff' }}
                      />
                      <Bar dataKey="findings" fill="#0284c7" radius={[6, 6, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center text-slate-500 text-sm">
                    No language distribution data available
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Search and Filters Toolbar */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
            <div className="relative lg:col-span-2">
              <Search size={18} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                className="w-full bg-slate-900 border border-slate-800 focus:border-primary-500 rounded-xl py-3 pl-11 pr-4 text-white placeholder-slate-500 outline-none transition-colors text-sm"
                placeholder="Search vulnerability, CWE, file..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>

            <div>
              <select
                className="w-full bg-slate-900 border border-slate-800 focus:border-primary-500 rounded-xl py-3 px-4 text-slate-300 outline-none transition-colors text-sm"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>

            <div>
              <select
                className="w-full bg-slate-900 border border-slate-800 focus:border-primary-500 rounded-xl py-3 px-4 text-slate-300 outline-none transition-colors text-sm"
                value={languageFilter}
                onChange={(e) => setLanguageFilter(e.target.value)}
              >
                <option value="">All Languages</option>
                <option value="python">Python</option>
                <option value="javascript">JavaScript / JSX</option>
                <option value="java">Java</option>
              </select>
            </div>

            <div>
              <select
                className="w-full bg-slate-900 border border-slate-800 focus:border-primary-500 rounded-xl py-3 px-4 text-slate-300 outline-none transition-colors text-sm"
                value={confidenceFilter}
                onChange={(e) => setConfidenceFilter(e.target.value)}
              >
                <option value="">All Confidences</option>
                <option value="High">High Confidence</option>
                <option value="Medium">Medium Confidence</option>
                <option value="Low">Low Confidence</option>
              </select>
            </div>
          </div>

          {/* Findings Table */}
          <div className="glass-panel rounded-2xl overflow-hidden border border-slate-800/80">
            <div className="px-6 py-4 border-b border-slate-800/80 flex items-center justify-between bg-slate-900/40">
              <h3 className="text-base font-bold font-outfit text-white tracking-wide">
                Detected Security Flaws ({filteredFindings.length})
              </h3>
              <span className="text-xs text-slate-500 font-medium">Click any row to inspect code snippet & fix</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-900/60 text-slate-400 text-xs font-semibold uppercase tracking-wider border-b border-slate-800/50">
                    <th className="px-6 py-4">Vulnerability</th>
                    <th className="px-6 py-4">Severity</th>
                    <th className="px-6 py-4">CWE ID</th>
                    <th className="px-6 py-4">Language</th>
                    <th className="px-6 py-4">Location</th>
                    <th className="px-6 py-4">Confidence</th>
                    <th className="px-6 py-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/40">
                  {filteredFindings.length > 0 ? (
                    filteredFindings.map((f) => (
                      <tr
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className={`hover:bg-slate-800/20 cursor-pointer transition-colors ${
                          selectedFinding?.id === f.id ? 'bg-primary-500/10' : ''
                        }`}
                      >
                        <td className="px-6 py-4">
                          <span className="text-slate-200 text-sm font-semibold block">{f.vulnerability_name}</span>
                          <span className="text-xs text-slate-500 mt-0.5 block truncate max-w-xs">{f.owasp_category || 'General'}</span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex px-2.5 py-1 rounded-lg text-xs font-bold ${getSeverityBadgeClass(f.severity)}`}>
                            {f.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-slate-300 text-sm font-medium">{f.cwe_id}</span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex px-2.5 py-0.5 rounded-md text-xs font-semibold uppercase ${getLanguageBadgeClass(f.language)}`}>
                            {f.language}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-slate-300 text-xs font-mono font-medium block truncate max-w-xs" title={`${f.file_name}:${f.line_number}`}>
                            {f.file_name} <span className="text-primary-400 font-bold">:L{f.line_number}</span>
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex items-center gap-1 text-xs font-medium ${
                            f.confidence.toLowerCase() === 'high' ? 'text-green-400' : (
                              f.confidence.toLowerCase() === 'medium' ? 'text-yellow-400' : 'text-slate-400'
                            )
                          }`}>
                            <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
                            <span>{f.confidence}</span>
                          </span>
                        </td>
                        <td className="px-6 py-4 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedFinding(f);
                            }}
                            className="p-1.5 text-slate-400 hover:text-primary-400 hover:bg-slate-800 rounded-lg transition-all"
                            title="Inspect Code Context & Fix"
                          >
                            <ChevronRight size={18} />
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="7" className="text-center py-16 text-slate-500 text-sm">
                        No vulnerabilities match the selected filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* Slide-over Side Drawer for Selected Finding */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 overflow-hidden flex justify-end">
          <div
            className="absolute inset-0 bg-slate-950/70 backdrop-blur-xs transition-opacity"
            onClick={() => setSelectedFinding(null)}
          ></div>

          <div className="w-full max-w-2xl bg-dark-900 border-l border-slate-800 shadow-2xl relative z-10 flex flex-col h-full">
            {/* Drawer Header */}
            <div className="px-6 py-5 border-b border-slate-800/80 flex items-center justify-between bg-dark-950/50">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-xl border ${getSeverityBadgeClass(selectedFinding.severity)}`}>
                  <AlertTriangle size={20} />
                </div>
                <div>
                  <h3 className="text-lg font-bold font-outfit text-white tracking-wide">
                    {selectedFinding.vulnerability_name}
                  </h3>
                  <span className="text-xs text-slate-400">SAST Finding Inspection</span>
                </div>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
              >
                <X size={20} />
              </button>
            </div>

            {/* Drawer Body Scroll */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {/* Badges strip */}
              <div className="flex flex-wrap gap-2">
                <span className={`inline-flex px-3 py-1 rounded-xl text-xs font-bold ${getSeverityBadgeClass(selectedFinding.severity)}`}>
                  Severity: {selectedFinding.severity}
                </span>
                <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-slate-800/80 border border-slate-700 rounded-xl text-xs text-slate-300 font-semibold">
                  <Layers size={13} className="text-primary-400" />
                  <span>{selectedFinding.cwe_id}</span>
                </span>
                <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-slate-800/80 border border-slate-700 rounded-xl text-xs text-slate-300 font-semibold">
                  <Terminal size={13} className="text-amber-400" />
                  <span>Language: {selectedFinding.language.toUpperCase()}</span>
                </span>
                <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-slate-800/80 border border-slate-700 rounded-xl text-xs text-slate-300 font-semibold">
                  <Info size={13} className="text-cyan-400" />
                  <span>Confidence: {selectedFinding.confidence}</span>
                </span>
              </div>

              {/* Location Box */}
              <div className="space-y-2">
                <h4 className="text-slate-400 text-xs font-bold uppercase tracking-wider">File & Line Target</h4>
                <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl font-mono text-sm text-slate-300 flex items-center justify-between">
                  <span className="text-slate-200 truncate">{selectedFinding.file_name}</span>
                  <span className="text-primary-400 font-bold shrink-0 ml-3">Line {selectedFinding.line_number}</span>
                </div>
              </div>

              {/* Vulnerable Code Context Box */}
              {selectedFinding.code_snippet && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h4 className="text-slate-400 text-xs font-bold uppercase tracking-wider flex items-center gap-1.5">
                      <Code2 size={14} className="text-red-400" />
                      <span>Vulnerable Code Context</span>
                    </h4>
                    <span className="text-xs text-red-400 font-mono font-semibold">&gt; marks vulnerable line</span>
                  </div>

                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 overflow-x-auto font-mono text-xs text-slate-300 leading-relaxed shadow-inner">
                    {selectedFinding.code_snippet.split('\n').map((line, idx) => {
                      const isTarget = line.startsWith('>');
                      return (
                        <div
                          key={idx}
                          className={`py-0.5 px-2 rounded ${
                            isTarget ? 'bg-red-500/15 text-red-300 font-bold border-l-2 border-red-500' : 'text-slate-400'
                          }`}
                        >
                          {line}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Vulnerability Explanation (from KB) */}
              <div className="space-y-2">
                <h4 className="text-slate-400 text-xs font-bold uppercase tracking-wider">Why this is vulnerable</h4>
                <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl text-slate-300 text-sm leading-relaxed">
                  {selectedFinding.description || 'Vulnerability detected during static structural analysis.'}
                </div>
              </div>

              {/* Remediation Guidelines (from KB) */}
              <div className="space-y-2">
                <h4 className="text-slate-400 text-xs font-bold uppercase tracking-wider flex items-center gap-1.5">
                  <Sparkles size={14} className="text-primary-400" />
                  <span>Secure Coding & Remediation Guidelines</span>
                </h4>
                <div className="bg-primary-500/5 border border-primary-500/10 rounded-xl p-4 space-y-2.5">
                  {(selectedFinding.remediation || selectedFinding.recommendation || 'Validate all untrusted input parameters.').split('\n').map((rec, rIdx) => (
                    <div key={rIdx} className="flex gap-2.5 text-slate-300 text-sm leading-relaxed">
                      <span className="text-primary-400 shrink-0 font-bold">•</span>
                      <span>{rec.replace(/^\d+\.\s*/, '')}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Suggested Fix Box */}
              {selectedFinding.suggested_fix && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h4 className="text-slate-400 text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 text-primary-400">
                      <Sparkles size={14} />
                      <span>Suggested Fix (Example Safer Implementation)</span>
                    </h4>
                    <button
                      onClick={() => handleCopyFix(selectedFinding.suggested_fix)}
                      className="flex items-center gap-1 text-xs text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 transition-colors"
                    >
                      {copiedFix ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
                      <span>{copiedFix ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>

                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs text-emerald-400 leading-relaxed overflow-x-auto shadow-inner">
                    <pre>{selectedFinding.suggested_fix}</pre>
                  </div>
                  <p className="text-[11px] text-slate-500 italic">
                    Note: Suggested implementations are defensive examples. Review context and test thoroughly before applying to production.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Upload Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-dark-950/80 backdrop-blur-sm">
          <div className="w-full max-w-lg glass-panel rounded-2xl p-6 relative border border-slate-800">
            <h3 className="text-xl font-bold font-outfit text-white mb-2 flex items-center gap-2">
              <FolderGit2 size={22} className="text-primary-500" />
              <span>Upload Source Code Project</span>
            </h3>
            <p className="text-slate-400 text-sm mb-6">
              Select or drop your application project ZIP archive (.zip). The SAST engine extracts and analyzes Python, JavaScript/React, and Java files safely.
            </p>

            {uploadError && (
              <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-xl">
                {uploadError}
              </div>
            )}

            <form onSubmit={handleUploadAndScan}>
              <div className="border-2 border-dashed border-slate-800 hover:border-primary-500/50 rounded-2xl p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-colors relative mb-6">
                <input
                  type="file"
                  required
                  accept=".zip"
                  onChange={handleFileChange}
                  className="absolute inset-0 opacity-0 cursor-pointer"
                  disabled={uploading}
                />

                {selectedFile ? (
                  <>
                    <CheckCircle2 className="text-green-500 mb-3" size={32} />
                    <span className="text-slate-200 text-sm font-semibold truncate max-w-xs">{selectedFile.name}</span>
                    <span className="text-slate-500 text-xs mt-1">{(selectedFile.size / 1024 / 1024).toFixed(2)} MB</span>
                  </>
                ) : (
                  <>
                    <Upload className="text-slate-600 mb-3" size={32} />
                    <span className="text-slate-300 text-sm font-semibold">Click to select project ZIP or drag it here</span>
                    <span className="text-slate-500 text-xs mt-1">Accepts standard .zip archives (max 50MB)</span>
                  </>
                )}
              </div>

              <div className="flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => {
                    setSelectedFile(null);
                    setShowUploadModal(false);
                  }}
                  className="px-5 py-2.5 text-sm font-semibold bg-slate-900 border border-slate-800 rounded-xl hover:text-white transition-all"
                  disabled={uploading}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2.5 text-sm font-semibold bg-primary-600 text-white rounded-xl hover:bg-primary-700 transition-all flex items-center gap-2 shadow-lg hover:shadow-primary-600/10"
                  disabled={uploading || !selectedFile}
                >
                  {uploading ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                      <span>Analyzing AST...</span>
                    </>
                  ) : (
                    <span>Start SAST Scan</span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default SourceCodeScanner;
