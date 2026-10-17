import React, { useState, useEffect, useRef } from 'react';
import {
  X, Sparkles, Check, Copy, Code2, AlertTriangle,
  Terminal, CheckCircle2, Layers, Cpu,
  Play, Download, ShieldCheck, Lock,
  RotateCcw, Loader2, StopCircle, FileCode2
} from 'lucide-react';
import { remediationAPI } from '../services/api';

const RemediationInspector = ({ finding, onClose }) => {
  const [copiedVulnerable, setCopiedVulnerable] = useState(false);
  const [copiedSecure, setCopiedSecure] = useState(false);
  const [copiedDiff, setCopiedDiff] = useState(false);
  const [activeTab, setActiveTab] = useState('remediation'); // 'remediation' | 'code' | 'verification' | 'workbench'

  // Continuous Remediation Loop State
  const [maxAttempts, setMaxAttempts] = useState(5);
  const [remediationJob, setRemediationJob] = useState(null);
  const [jobAttempts, setJobAttempts] = useState([]);
  const [startingLoop, setStartingLoop] = useState(false);
  const [cancellingLoop, setCancellingLoop] = useState(false);
  const [exportingPatch, setExportingPatch] = useState(false);
  const [remediationError, setRemediationError] = useState('');
  const pollIntervalRef = useRef(null);

  // Clearance check
  const storedUser = (() => {
    try {
      return JSON.parse(localStorage.getItem('user') || '{}');
    } catch {
      return {};
    }
  })();
  const userRole = (storedUser?.role || 'user').toLowerCase();
  const canAccessSourceCode = ['cdac_officer', 'admin', 'officer', 'security_officer', 'security_analyst', 'auditor'].includes(userRole);

  useEffect(() => {
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, []);

  // Poll active remediation job
  const pollJobStatus = (jobId) => {
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);

    pollIntervalRef.current = setInterval(async () => {
      try {
        const job = await remediationAPI.getJob(jobId);
        setRemediationJob(job);

        const attempts = await remediationAPI.getJobAttempts(jobId);
        setJobAttempts(attempts || []);

        const terminalStates = ['VERIFIED_FIXED', 'NEEDS_MANUAL_REVIEW', 'CANCELLED', 'FAILED'];
        if (terminalStates.includes(job.state)) {
          clearInterval(pollIntervalRef.current);
          pollIntervalRef.current = null;
        }
      } catch (err) {
        console.error("Error polling remediation job:", err);
      }
    }, 1500);
  };

  const handleStartRemediation = async () => {
    if (!canAccessSourceCode) {
      setRemediationError("Access Denied: C-DAC Confidentiality Guidelines restrict source code remediation to authorized Officers and Analysts.");
      return;
    }
    setStartingLoop(true);
    setRemediationError('');

    try {
      const payload = {
        finding_id: finding?.id,
        vulnerability_id: finding?.vulnerability_id,
        code_snippet: finding?.matched_code || finding?.vulnerable_code || finding?.code_snippet,
        file_path: finding?.file || finding?.file_name || 'source_code.py',
        line_number: finding?.line || finding?.line_number || 1,
        language: finding?.language,
        framework: finding?.framework,
        cwe_id: finding?.cwe_id || 'CWE-89',
        vulnerability_name: finding?.vulnerability || finding?.vulnerability_name || 'Security Finding',
        severity: finding?.severity || 'Medium',
        max_attempts: maxAttempts,
        timeout_seconds: 300
      };

      const job = await remediationAPI.createJob(payload, false);
      setRemediationJob(job);
      setActiveTab('workbench');
      pollJobStatus(job.id);
    } catch (err) {
      setRemediationError(err.response?.data?.detail || "Failed to start continuous remediation loop.");
    } finally {
      setStartingLoop(false);
    }
  };

  const handleCancelJob = async () => {
    if (!remediationJob) return;
    setCancellingLoop(true);
    try {
      const updated = await remediationAPI.cancelJob(remediationJob.id);
      setRemediationJob(updated);
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    } catch (err) {
      setRemediationError(err.response?.data?.detail || "Failed to cancel remediation job.");
    } finally {
      setCancellingLoop(false);
    }
  };

  const handleExportPatch = async () => {
    if (!remediationJob) return;
    setExportingPatch(true);
    try {
      const filename = `remediation_${remediationJob.job_uuid}_${(remediationJob.cwe_id || 'patch').toLowerCase()}.patch`;
      await remediationAPI.exportPatch(remediationJob.id, filename);
    } catch (err) {
      setRemediationError(err.response?.data?.detail || "Failed to export verified patch.");
    } finally {
      setExportingPatch(false);
    }
  };

  const handleCopy = (text, type) => {
    navigator.clipboard.writeText(text);
    if (type === 'vulnerable') {
      setCopiedVulnerable(true);
      setTimeout(() => setCopiedVulnerable(false), 2000);
    } else if (type === 'diff') {
      setCopiedDiff(true);
      setTimeout(() => setCopiedDiff(false), 2000);
    } else {
      setCopiedSecure(true);
      setTimeout(() => setCopiedSecure(false), 2000);
    }
  };

  const getSeverityBadge = (sev) => {
    const s = (sev || 'Medium').toLowerCase();
    if (s === 'critical') return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
    if (s === 'high') return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    if (s === 'medium') return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
  };

  const getStateBadge = (state) => {
    switch (state) {
      case 'VERIFIED_FIXED':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      case 'NEEDS_MANUAL_REVIEW':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'TESTS_FAILED':
      case 'FAILED':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      case 'CANCELLED':
        return 'bg-slate-700/50 text-slate-400 border-slate-600';
      default:
        return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    }
  };

  const parseList = (val) => {
    if (!val) return [];
    if (Array.isArray(val)) return val;
    if (typeof val === 'string') {
      try {
        const parsed = JSON.parse(val);
        if (Array.isArray(parsed)) return parsed;
      } catch (e) {
        return val.split('\n').map(s => s.replace(/^\d+\.\s*/, '').trim()).filter(Boolean);
      }
    }
    return [String(val)];
  };

  const implementationSteps = parseList(finding?.implementation_steps);
  const verificationSteps = parseList(finding?.verification_steps);

  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-slate-950/75 backdrop-blur-xs transition-opacity"
        onClick={onClose}
      />

      {/* Drawer Container */}
      <div className="w-full max-w-3xl bg-dark-900 border-l border-slate-800 shadow-2xl relative z-10 flex flex-col h-full overflow-hidden text-slate-200">
        {/* Header */}
        <div className="px-6 py-5 border-b border-slate-800/80 flex items-center justify-between bg-dark-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary-500/10 border border-primary-500/20 rounded-xl text-primary-400">
              <Sparkles size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-500 font-semibold uppercase tracking-wider">
                  Continuous Remediation Engine
                </span>
                {remediationJob && (
                  <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold border uppercase ${getStateBadge(remediationJob.state)}`}>
                    {remediationJob.state.replace(/_/g, ' ')}
                  </span>
                )}
              </div>
              <h2 className="text-lg font-bold font-outfit text-white tracking-wide">
                {finding.vulnerability || finding.vulnerability_name || 'Vulnerability Finding'}
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
          >
            <X size={20} />
          </button>
        </div>

        {/* Badges / Metadata Banner */}
        <div className="px-6 py-3 bg-dark-950/30 border-b border-slate-800/60 flex flex-wrap items-center gap-2 text-xs">
          <span className={`px-2.5 py-1 rounded-lg border font-semibold ${getSeverityBadge(finding.severity)}`}>
            {finding.severity || 'Medium'} Severity
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-slate-800 border border-slate-700 font-mono text-slate-300">
            {finding.cwe_id || 'CWE'}
          </span>
          {finding.cve_id && (
            <span className="px-2.5 py-1 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 font-mono">
              {finding.cve_id}
            </span>
          )}
          <span className="px-2.5 py-1 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 font-semibold flex items-center gap-1">
            <Cpu size={12} />
            {finding.language || 'Unknown Language'}
          </span>
          {finding.framework && finding.framework !== 'Unknown' && (
            <span className="px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-semibold flex items-center gap-1">
              <Layers size={12} />
              {finding.framework}
            </span>
          )}
          <span className="ml-auto text-slate-400 font-mono text-xs">
            {finding.file || finding.file_name || 'N/A'}:{finding.line || finding.line_number || 1}
          </span>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-800 px-6 bg-dark-950/20 overflow-x-auto">
          <button
            onClick={() => setActiveTab('remediation')}
            className={`py-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition-all shrink-0 ${
              activeTab === 'remediation'
                ? 'border-primary-500 text-primary-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            Root Cause & Fix
          </button>
          <button
            onClick={() => setActiveTab('code')}
            className={`py-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition-all shrink-0 ${
              activeTab === 'code'
                ? 'border-primary-500 text-primary-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            Code Fix (Diff View)
          </button>
          <button
            onClick={() => setActiveTab('verification')}
            className={`py-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition-all shrink-0 ${
              activeTab === 'verification'
                ? 'border-primary-500 text-primary-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            Verification Steps
          </button>
          <button
            onClick={() => setActiveTab('workbench')}
            className={`py-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition-all shrink-0 flex items-center gap-1.5 ${
              activeTab === 'workbench'
                ? 'border-sky-500 text-sky-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <RotateCcw size={13} className={remediationJob && !['VERIFIED_FIXED', 'NEEDS_MANUAL_REVIEW', 'CANCELLED'].includes(remediationJob.state) ? 'animate-spin text-sky-400' : ''} />
            <span>Remediation Loop</span>
            {remediationJob?.state === 'VERIFIED_FIXED' && (
              <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block ml-0.5"></span>
            )}
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* TAB 4: CONTINUOUS REMEDIATION WORKBENCH */}
          {activeTab === 'workbench' && (
            <div className="space-y-6">
              {/* Clearance Banner */}
              {!canAccessSourceCode && (
                <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl text-amber-300 text-sm flex items-start gap-3">
                  <Lock size={18} className="shrink-0 mt-0.5" />
                  <div>
                    <h4 className="font-bold">Confidential Clearance Required</h4>
                    <p className="text-xs text-amber-400/80 mt-1">
                      C-DAC Information Security Guidelines classify source code assets as confidential. Continuous automated patching and rescan are restricted to C-DAC Officers and Security Analysts.
                    </p>
                  </div>
                </div>
              )}

              {remediationError && (
                <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-300 text-sm flex items-start gap-3">
                  <AlertTriangle size={18} className="shrink-0 mt-0.5" />
                  <p>{remediationError}</p>
                </div>
              )}

              {/* Launcher Card when no job or completed */}
              <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <Sparkles size={16} className="text-sky-400" />
                      Continuous Vulnerability Remediation Loop
                    </h3>
                    <p className="text-xs text-slate-400 mt-1">
                      Iteratively generates fixes, applies to an isolated sandbox workspace, checks syntax, and independently rescans code until verified fixed.
                    </p>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="flex items-center gap-2 text-xs text-slate-400">
                      <span>Max Retries:</span>
                      <select
                        value={maxAttempts}
                        onChange={(e) => setMaxAttempts(Number(e.target.value))}
                        disabled={remediationJob && !['VERIFIED_FIXED', 'NEEDS_MANUAL_REVIEW', 'CANCELLED', 'FAILED'].includes(remediationJob.state)}
                        className="bg-slate-800 border border-slate-700 text-white rounded-lg px-2 py-1 text-xs outline-none"
                      >
                        <option value={1}>1</option>
                        <option value={3}>3</option>
                        <option value={5}>5 (Standard)</option>
                        <option value={7}>7</option>
                        <option value={10}>10 (Thorough)</option>
                      </select>
                    </div>

                    <button
                      onClick={handleStartRemediation}
                      disabled={startingLoop || (!canAccessSourceCode) || (remediationJob && !['VERIFIED_FIXED', 'NEEDS_MANUAL_REVIEW', 'CANCELLED', 'FAILED'].includes(remediationJob.state))}
                      className="px-4 py-2 bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 disabled:opacity-50 text-white rounded-xl text-xs font-semibold flex items-center gap-2 shadow-lg shadow-sky-600/20 transition-all cursor-pointer"
                    >
                      {startingLoop ? (
                        <>
                          <Loader2 size={14} className="animate-spin" />
                          <span>Initiating...</span>
                        </>
                      ) : (
                        <>
                          <Play size={14} />
                          <span>Start Remediation Loop</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Active Job Stepper */}
                {remediationJob && (
                  <div className="pt-4 border-t border-slate-800/80 space-y-4">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-400 font-mono">Job ID: {remediationJob.job_uuid}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-400">Progress:</span>
                        <span className="font-bold text-white">Attempt {remediationJob.current_attempt} of {remediationJob.max_attempts}</span>
                      </div>
                    </div>

                    {/* Stage Pipeline Visualization */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                      <div className={`p-2.5 rounded-xl border flex flex-col gap-1 ${
                        ['GENERATING_FIX', 'APPLYING_PATCH', 'VALIDATING_PATCH', 'RESCANNING', 'VERIFIED_FIXED'].includes(remediationJob.state)
                          ? 'bg-sky-500/10 border-sky-500/30 text-sky-300'
                          : 'bg-slate-900 border-slate-800 text-slate-500'
                      }`}>
                        <span className="font-semibold">1. Synthesize Fix</span>
                        <span className="text-[10px] opacity-80">AI / Semantic Code</span>
                      </div>

                      <div className={`p-2.5 rounded-xl border flex flex-col gap-1 ${
                        ['APPLYING_PATCH', 'VALIDATING_PATCH', 'RESCANNING', 'VERIFIED_FIXED'].includes(remediationJob.state)
                          ? 'bg-indigo-500/10 border-indigo-500/30 text-indigo-300'
                          : 'bg-slate-900 border-slate-800 text-slate-500'
                      }`}>
                        <span className="font-semibold">2. Apply to Sandbox</span>
                        <span className="text-[10px] opacity-80">Anti-ZipSlip Isolation</span>
                      </div>

                      <div className={`p-2.5 rounded-xl border flex flex-col gap-1 ${
                        ['VALIDATING_PATCH', 'RESCANNING', 'VERIFIED_FIXED'].includes(remediationJob.state)
                          ? 'bg-purple-500/10 border-purple-500/30 text-purple-300'
                          : 'bg-slate-900 border-slate-800 text-slate-500'
                      }`}>
                        <span className="font-semibold">3. Syntax Validation</span>
                        <span className="text-[10px] opacity-80">AST / Structural Check</span>
                      </div>

                      <div className={`p-2.5 rounded-xl border flex flex-col gap-1 ${
                        remediationJob.state === 'VERIFIED_FIXED'
                          ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300 font-bold'
                          : (remediationJob.state === 'NEEDS_MANUAL_REVIEW'
                              ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                              : (remediationJob.state === 'RESCANNING'
                                  ? 'bg-blue-500/10 border-blue-500/30 text-blue-300 animate-pulse'
                                  : 'bg-slate-900 border-slate-800 text-slate-500'))
                      }`}>
                        <span className="font-semibold">4. Rescan Result</span>
                        <span className="text-[10px] opacity-80">
                          {remediationJob.state === 'VERIFIED_FIXED' ? 'Verified Fixed ✓' : remediationJob.state.replace(/_/g, ' ')}
                        </span>
                      </div>
                    </div>

                    {/* Evidence & Verification Box */}
                    {remediationJob.verification_evidence && (
                      <div className="p-3.5 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-xs text-emerald-300 flex items-start gap-2.5">
                        <ShieldCheck size={18} className="shrink-0 mt-0.5 text-emerald-400" />
                        <div>
                          <strong className="block font-semibold">Independent Verification Passed:</strong>
                          <p className="mt-0.5 text-emerald-400/90 leading-relaxed">{remediationJob.verification_evidence}</p>
                        </div>
                      </div>
                    )}

                    {remediationJob.failure_reason && (
                      <div className="p-3.5 bg-amber-500/10 border border-amber-500/20 rounded-xl text-xs text-amber-300 flex items-start gap-2.5">
                        <AlertTriangle size={18} className="shrink-0 mt-0.5 text-amber-400" />
                        <div>
                          <strong className="block font-semibold">Remediation Status Notice:</strong>
                          <p className="mt-0.5 text-amber-400/90 leading-relaxed">{remediationJob.failure_reason}</p>
                        </div>
                      </div>
                    )}

                    {/* Job Actions */}
                    <div className="flex items-center gap-3 pt-2">
                      {['VERIFIED_FIXED'].includes(remediationJob.state) && remediationJob.final_patch_diff && (
                        <button
                          onClick={handleExportPatch}
                          disabled={exportingPatch}
                          className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-semibold flex items-center gap-2 shadow-lg shadow-emerald-600/20 transition-all cursor-pointer"
                        >
                          <Download size={14} />
                          <span>Export Verified Patch (.patch)</span>
                        </button>
                      )}

                      {!['VERIFIED_FIXED', 'NEEDS_MANUAL_REVIEW', 'CANCELLED', 'FAILED'].includes(remediationJob.state) && (
                        <button
                          onClick={handleCancelJob}
                          disabled={cancellingLoop}
                          className="px-3.5 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer"
                        >
                          <StopCircle size={14} />
                          <span>Cancel Job</span>
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Verified Patch Diff Viewer */}
              {remediationJob?.final_patch_diff && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                      <FileCode2 size={14} className="text-emerald-400" />
                      Verified Unified Patch Diff
                    </span>
                    <button
                      onClick={() => handleCopy(remediationJob.final_patch_diff, 'diff')}
                      className="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg flex items-center gap-1 transition-colors"
                    >
                      {copiedDiff ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                      <span>{copiedDiff ? 'Copied Diff' : 'Copy Patch'}</span>
                    </button>
                  </div>

                  <pre className="p-4 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono overflow-x-auto text-slate-300 max-h-80 leading-relaxed">
                    {remediationJob.final_patch_diff.split('\n').map((line, idx) => {
                      let color = 'text-slate-400';
                      if (line.startsWith('+') && !line.startsWith('+++')) color = 'text-emerald-400 bg-emerald-500/10 block';
                      else if (line.startsWith('-') && !line.startsWith('---')) color = 'text-rose-400 bg-rose-500/10 block';
                      else if (line.startsWith('@@')) color = 'text-cyan-400';
                      return (
                        <span key={idx} className={color}>
                          {line}
                          {'\n'}
                        </span>
                      );
                    })}
                  </pre>
                </div>
              )}

              {/* Chronological Attempts History */}
              {jobAttempts.length > 0 && (
                <div className="space-y-3">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
                    Remediation Attempt History ({jobAttempts.length})
                  </span>
                  <div className="space-y-3">
                    {jobAttempts.map((att) => (
                      <div key={att.id} className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-2 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-white">Attempt #{att.attempt_number}</span>
                          <span className={`px-2 py-0.5 rounded-full font-bold uppercase text-[10px] border ${getStateBadge(att.state)}`}>
                            {att.state.replace(/_/g, ' ')}
                          </span>
                        </div>
                        {att.status_message && (
                          <p className="text-slate-300">{att.status_message}</p>
                        )}
                        {att.syntax_errors && (
                          <div className="p-2 bg-rose-500/10 border border-rose-500/20 text-rose-300 rounded font-mono text-[11px]">
                            {att.syntax_errors}
                          </div>
                        )}
                        {att.patch_diff && (
                          <details className="mt-2 text-slate-400">
                            <summary className="cursor-pointer hover:text-white font-semibold">View Attempt Diff</summary>
                            <pre className="mt-2 p-2 bg-slate-950 rounded border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-40">
                              {att.patch_diff}
                            </pre>
                          </details>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 1: REMEDIATION & ANALYSIS */}
          {activeTab === 'remediation' && (
            <div className="space-y-6">
              {/* Why It Is Vulnerable */}
              <div className="space-y-2">
                <span className="text-xs font-bold uppercase tracking-wider text-rose-400 flex items-center gap-1.5">
                  <AlertTriangle size={14} />
                  Root Cause Analysis (Why It Is Vulnerable)
                </span>
                <div className="p-4 bg-rose-500/5 border border-rose-500/20 rounded-xl text-slate-300 text-sm leading-relaxed">
                  {finding.why_vulnerable || finding.description || "Vulnerable input pattern detected in application flow."}
                </div>
              </div>

              {/* AI Remediation Guidance */}
              <div className="space-y-2">
                <span className="text-xs font-bold uppercase tracking-wider text-sky-400 flex items-center gap-1.5">
                  <Sparkles size={14} />
                  AI Secure Remediation Guidance
                </span>
                <div className="p-4 bg-sky-500/5 border border-sky-500/20 rounded-xl text-slate-300 text-sm leading-relaxed">
                  {finding.ai_remediation || finding.remediation || "Apply strict validation and parameterized API constructs."}
                </div>
              </div>

              {/* Implementation Steps */}
              {implementationSteps.length > 0 && (
                <div className="space-y-3">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
                    Developer Implementation Checklist
                  </span>
                  <div className="space-y-2">
                    {implementationSteps.map((step, idx) => (
                      <div key={idx} className="flex items-start gap-3 p-3 bg-slate-900/40 border border-slate-800 rounded-xl text-xs text-slate-300">
                        <div className="p-1 rounded bg-slate-800 text-primary-400 font-bold shrink-0 text-[10px]">
                          0{idx + 1}
                        </div>
                        <span className="leading-relaxed">{step}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: CODE FIX (DIFF VIEW) */}
          {activeTab === 'code' && (
            <div className="space-y-6">
              {/* Vulnerable Code */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-rose-400 flex items-center gap-1.5">
                    <Code2 size={14} />
                    Current Vulnerable Code Snippet
                  </span>
                  {finding.matched_code && (
                    <button
                      onClick={() => handleCopy(finding.matched_code, 'vulnerable')}
                      className="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg flex items-center gap-1 transition-colors"
                    >
                      {copiedVulnerable ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                      <span>{copiedVulnerable ? 'Copied' : 'Copy'}</span>
                    </button>
                  )}
                </div>
                <pre className="p-4 bg-slate-950 border border-rose-500/30 rounded-xl text-xs font-mono overflow-x-auto text-rose-300 max-h-60 leading-relaxed">
                  {finding.matched_code || finding.vulnerable_code || finding.code_snippet || "# Vulnerable snippet not available"}
                </pre>
              </div>

              {/* Secure Replacement Code */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle2 size={14} />
                    Secure Replacement Code (Synthesized Fix)
                  </span>
                  {finding.secure_code && (
                    <button
                      onClick={() => handleCopy(finding.secure_code, 'secure')}
                      className="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg flex items-center gap-1 transition-colors"
                    >
                      {copiedSecure ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                      <span>{copiedSecure ? 'Copied Secure Code' : 'Copy Code'}</span>
                    </button>
                  )}
                </div>
                <pre className="p-4 bg-slate-950 border border-emerald-500/30 rounded-xl text-xs font-mono overflow-x-auto text-emerald-300 max-h-72 leading-relaxed">
                  {finding.secure_code || finding.suggested_fix || "// Secure implementation not synthesized."}
                </pre>
              </div>
            </div>
          )}

          {/* TAB 3: VERIFICATION & RETESTING */}
          {activeTab === 'verification' && (
            <div className="space-y-6">
              <div className="p-4 bg-amber-500/5 border border-amber-500/20 rounded-xl text-xs text-amber-300 flex items-start gap-2">
                <AlertTriangle size={16} className="shrink-0 mt-0.5" />
                <span>
                  Never assume a vulnerability is resolved solely because code was regenerated. Always conduct targeted verification and regression testing.
                </span>
              </div>

              {verificationSteps.length > 0 ? (
                <div className="space-y-3">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
                    Retesting Guidelines & Verification Commands
                  </span>
                  <div className="space-y-3">
                    {verificationSteps.map((step, idx) => (
                      <div key={idx} className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-1">
                        <div className="flex items-center gap-2 text-xs font-bold text-primary-400">
                          <Terminal size={14} />
                          <span>Test Check #{idx + 1}</span>
                        </div>
                        <p className="text-sm text-slate-300 leading-relaxed pl-5">{step}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="text-sm text-slate-400 p-4 bg-slate-900/20 border border-slate-800 rounded-xl">
                  Perform automated security regression testing and verify the finding is cleared in the next SAST scan.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Drawer Footer */}
        <div className="p-4 border-t border-slate-800 bg-dark-950/80 flex items-center justify-between text-xs text-slate-500">
          <span>Target: <strong className="text-slate-300">{finding.file || finding.file_name || 'N/A'}</strong></span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('workbench')}
              className="px-3 py-1.5 bg-sky-600/20 hover:bg-sky-600/30 text-sky-300 border border-sky-500/30 rounded-xl font-medium transition-colors cursor-pointer flex items-center gap-1.5"
            >
              <RotateCcw size={13} />
              <span>Remediation Workbench</span>
            </button>
            <button
              onClick={onClose}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl font-medium transition-colors cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RemediationInspector;
