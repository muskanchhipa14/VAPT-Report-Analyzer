import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { reportAPI, vulnerabilityAPI } from '../services/api';
import {
  Upload, FileText, Trash2, Download, ExternalLink,
  ShieldCheck, AlertTriangle, FileUp, Loader, CheckCircle, RefreshCw
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from 'recharts';

const Dashboard = () => {
  const [reports, setReports] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadError, setUploadError] = useState('');
  const navigate = useNavigate();

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

  const handleFileChange = (e) => {
    setSelectedFile(e.target.files[0]);
    setUploadError('');
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      setUploadError('Please select a file.');
      return;
    }
    const fileName = selectedFile.name.toLowerCase();
    if (!fileName.endsWith('.pdf') && !fileName.endsWith('.docx')) {
      setUploadError('Only PDF and DOCX files are allowed.');
      return;
    }

    setUploading(true);
    setUploadError('');
    try {
      await reportAPI.uploadReport(selectedFile);
      setSelectedFile(null);
      setShowUploadModal(false);
      fetchData();
    } catch (err) {
      setUploadError(err.response?.data?.detail || 'Failed to upload and parse report.');
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
          <h1 className="text-3xl font-bold font-outfit text-white tracking-wide">Security Dashboard</h1>
          <p className="text-slate-400 text-sm mt-1">Review system posture, parse reports, and download analysis logs.</p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={fetchData}
            className="flex items-center justify-center p-3 text-slate-400 bg-slate-900 border border-slate-800 rounded-xl hover:text-white hover:border-slate-700 transition-all"
            title="Refresh Dashboard"
          >
            <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
          </button>
          <button
            onClick={() => setShowUploadModal(true)}
            className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white font-semibold px-5 py-3 rounded-xl transition-all shadow-lg hover:shadow-primary-600/10 active:scale-[0.98]"
          >
            <Upload size={18} />
            <span>Upload Scan PDF</span>
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex flex-col items-center justify-center py-32 text-slate-500">
          <Loader size={36} className="animate-spin text-primary-500 mb-4" />
          <span>Loading security data...</span>
        </div>
      ) : (
        <>
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
              <p className="text-xs text-red-500 mt-1">Require immediate verification</p>
            </div>

            <div className="glass-panel p-6 rounded-2xl hover-scale">
              <div className="flex items-center justify-between mb-4">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Critical & High Issues</span>
                <div className="p-2 bg-orange-500/10 border border-orange-500/20 rounded-lg text-orange-400">
                  <AlertTriangle size={18} />
                </div>
              </div>
              <h2 className="text-3xl font-bold text-white font-outfit">{criticalHighVulns}</h2>
              <p className="text-xs text-orange-500 mt-1">Key targets for remediation</p>
            </div>

            <div className="glass-panel p-6 rounded-2xl hover-scale">
              <div className="flex items-center justify-between mb-4">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Remediation Rate</span>
                <div className="p-2 bg-green-500/10 border border-green-500/20 rounded-lg text-green-400">
                  <ShieldCheck size={18} />
                </div>
              </div>
              <h2 className="text-3xl font-bold text-white font-outfit">
                {vulnerabilities.length > 0
                  ? `${Math.round((resolvedVulns / vulnerabilities.length) * 100)}%`
                  : '0%'
                }
              </h2>
              <p className="text-xs text-green-500 mt-1">Issues marked as Resolved</p>
            </div>
          </div>

          {/* Visual Charts section */}
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 mb-8">
            {/* Pie Chart: Severity breakdown */}
            <div className="glass-panel p-6 rounded-2xl lg:col-span-2 flex flex-col h-[350px]">
              <h3 className="text-slate-200 text-sm font-semibold tracking-wider uppercase mb-4">Severity breakdown</h3>
              <div className="flex-1 relative">
                {severityChartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityChartData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
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
              {/* Legend grid */}
              <div className="grid grid-cols-3 gap-2 mt-4 text-xs text-slate-400">
                {Object.keys(severityCounts).map(sev => (
                  severityCounts[sev] > 0 && (
                    <div key={sev} className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ backgroundColor: SEVERITY_COLORS[sev] }}></span>
                      <span>{sev}: {severityCounts[sev]}</span>
                    </div>
                  )
                ))}
              </div>
            </div>

            {/* Stacked Bar Chart: Findings by Report */}
            <div className="glass-panel p-6 rounded-2xl lg:col-span-3 h-[350px] flex flex-col">
              <h3 className="text-slate-200 text-sm font-semibold tracking-wider uppercase mb-4">Findings Breakdown by Report</h3>
              <div className="flex-1">
                {reportChartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={reportChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                      <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                      <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                      <Tooltip
                        contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '8px' }}
                        itemStyle={{ color: '#fff' }}
                      />
                      <Legend wrapperStyle={{ fontSize: 10, paddingTop: 10 }} />
                      <Bar dataKey="Resolved" stackId="a" fill="#10b981" radius={[0, 0, 0, 0]} />
                      <Bar dataKey="Open" stackId="a" fill="#f43f5e" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center text-slate-500 text-sm">
                    No data available
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Recent Reports Table */}
          <div className="glass-panel rounded-2xl overflow-hidden">
            <div className="px-6 py-5 border-b border-slate-800/80 flex items-center justify-between">
              <h3 className="text-lg font-bold font-outfit text-white tracking-wide">Recent Report Uploads</h3>
              <span className="text-xs text-slate-500 font-medium">Total: {reports.length} files</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-900/40 text-slate-400 text-xs font-semibold uppercase tracking-wider border-b border-slate-800/50">
                    <th className="px-6 py-4">Report Name</th>
                    <th className="px-6 py-4">Parse Status</th>
                    <th className="px-6 py-4">Findings</th>
                    <th className="px-6 py-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {reports.length > 0 ? (
                    reports.map((report) => (
                      <tr key={report.id} className="hover:bg-slate-800/10 transition-colors">
                        <td className="px-6 py-4 flex items-center gap-3">
                          <div className="p-2 bg-slate-900 border border-slate-800 rounded-lg text-primary-400">
                            <FileText size={16} />
                          </div>
                          <span className="text-slate-200 text-sm font-semibold truncate max-w-xs">{report.filename}</span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
                            report.status === 'Completed' ? 'bg-green-500/10 text-green-400 border border-green-500/20' :
                            report.status === 'Parsing' ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20' :
                            'bg-red-500/10 text-red-400 border border-red-500/20'
                          }`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${
                              report.status === 'Completed' ? 'bg-green-400' :
                              report.status === 'Parsing' ? 'bg-yellow-400' :
                              'bg-red-400'
                            } ${report.status === 'Parsing' ? 'animate-ping' : ''}`}></span>
                            <span>{report.status}</span>
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-slate-300 text-sm font-semibold">{report.vulnerabilities_count} issues</span>
                        </td>
                        <td className="px-6 py-4 text-right">
                          <div className="inline-flex gap-2">
                            <button
                              onClick={() => navigate(`/vulnerabilities?report=${encodeURIComponent(report.filename)}`)}
                              disabled={report.status !== 'Completed'}
                              className="p-2 text-slate-400 hover:text-primary-400 hover:bg-slate-800 rounded-lg transition-all"
                              title="View Findings"
                            >
                              <ExternalLink size={16} />
                            </button>
                            <a
                              href={`http://localhost:8000/reports/${report.id}/download`}
                              className={`p-2 text-slate-400 hover:text-green-400 hover:bg-slate-800 rounded-lg transition-all ${
                                report.status !== 'Completed' ? 'pointer-events-none opacity-40' : ''
                              }`}
                              title="Download PDF Report"
                              download
                            >
                              <Download size={16} />
                            </a>
                            <button
                              onClick={() => handleDeleteReport(report.id)}
                              className="p-2 text-slate-400 hover:text-red-400 hover:bg-slate-800 rounded-lg transition-all"
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
                        No vulnerability reports uploaded yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* Upload scan report modal */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-dark-950/80 backdrop-blur-sm">
          <div className="w-full max-w-lg glass-panel rounded-2xl p-6 relative border border-slate-800">
            <h3 className="text-xl font-bold font-outfit text-white mb-2 flex items-center gap-2">
              <FileUp size={22} className="text-primary-500" />
              <span>Upload Vulnerability Report</span>
            </h3>
            <p className="text-slate-400 text-sm mb-6">Select the VAPT security scan file (.pdf, .docx) to extract and map recommendations.</p>
            
            {uploadError && (
              <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-xl">
                {uploadError}
              </div>
            )}

            <form onSubmit={handleUpload}>
              <div className="border-2 border-dashed border-slate-800 hover:border-primary-500/50 rounded-2xl p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-colors relative mb-6">
                <input
                  type="file"
                  required
                  accept=".pdf,.docx"
                  onChange={handleFileChange}
                  className="absolute inset-0 opacity-0 cursor-pointer"
                  disabled={uploading}
                />
                
                {selectedFile ? (
                  <>
                    <CheckCircle className="text-green-500 mb-3" size={32} />
                    <span className="text-slate-200 text-sm font-semibold truncate max-w-xs">{selectedFile.name}</span>
                    <span className="text-slate-500 text-xs mt-1">{(selectedFile.size / 1024 / 1024).toFixed(2)} MB</span>
                  </>
                ) : (
                  <>
                    <Upload className="text-slate-600 mb-3" size={32} />
                    <span className="text-slate-300 text-sm font-semibold">Click to select PDF/DOCX or drag it here</span>
                    <span className="text-slate-500 text-xs mt-1">Accepts standard PDF or DOCX scan logs</span>
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
                      <Loader size={16} className="animate-spin" />
                      <span>Parsing...</span>
                    </>
                  ) : (
                    <span>Parse Report</span>
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

export default Dashboard;
