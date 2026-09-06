import React, { useState } from 'react';
import {
  X, Sparkles, Check, Copy, Code2, AlertTriangle,
  BookOpen, Terminal, CheckCircle2, Layers, Cpu, Database
} from 'lucide-react';

const RemediationInspector = ({ finding, onClose }) => {
  const [copiedVulnerable, setCopiedVulnerable] = useState(false);
  const [copiedSecure, setCopiedSecure] = useState(false);
  const [activeTab, setActiveTab] = useState('remediation'); // 'remediation' | 'code' | 'verification'

  if (!finding) return null;

  const handleCopy = (text, type) => {
    navigator.clipboard.writeText(text);
    if (type === 'vulnerable') {
      setCopiedVulnerable(true);
      setTimeout(() => setCopiedVulnerable(false), 2000);
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

  const implementationSteps = parseList(finding.implementation_steps);
  const verificationSteps = parseList(finding.verification_steps);

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
                  AI Remediation Engine
                </span>
                {finding.correlation_status && (
                  <span className={`text-xs px-2 py-0.5 rounded-md font-semibold border ${
                    finding.correlation_status === 'CONFIRMED'
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}>
                    {finding.correlation_status}
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
          {finding.database_or_lib && finding.database_or_lib !== 'Standard' && (
            <span className="px-2.5 py-1 rounded-lg bg-violet-500/10 border border-violet-500/20 text-violet-400 font-semibold flex items-center gap-1">
              <Database size={12} />
              {finding.database_or_lib}
            </span>
          )}
          <span className="ml-auto text-slate-400 font-mono text-xs">
            {finding.file || finding.file_name || 'N/A'}:{finding.line || finding.line_number || 1}
          </span>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-800 px-6 bg-dark-950/20">
          <button
            onClick={() => setActiveTab('remediation')}
            className={`py-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition-all ${
              activeTab === 'remediation'
                ? 'border-primary-500 text-primary-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            Remediation & Analysis
          </button>
          <button
            onClick={() => setActiveTab('code')}
            className={`py-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition-all ${
              activeTab === 'code'
                ? 'border-primary-500 text-primary-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            Code Fix (Diff View)
          </button>
          <button
            onClick={() => setActiveTab('verification')}
            className={`py-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition-all ${
              activeTab === 'verification'
                ? 'border-primary-500 text-primary-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            Verification & Retesting
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* TAB 1: REMEDIATION & ANALYSIS */}
          {activeTab === 'remediation' && (
            <div className="space-y-6">
              {/* Why It Is Vulnerable */}
              <div className="space-y-2">
                <span className="text-xs font-bold uppercase tracking-wider text-rose-400 flex items-center gap-1.5">
                  <AlertTriangle size={14} />
                  Why It Is Vulnerable
                </span>
                <div className="p-4 bg-rose-500/5 border border-rose-500/15 rounded-xl text-sm leading-relaxed text-slate-300">
                  {finding.why_vulnerable || finding.description || 'Untrusted input is processed without adequate defensive validation.'}
                </div>
              </div>

              {/* AI Language-Specific Remediation */}
              <div className="space-y-2">
                <span className="text-xs font-bold uppercase tracking-wider text-primary-400 flex items-center gap-1.5">
                  <Sparkles size={14} />
                  AI Context-Aware Remediation ({finding.language || 'Language-Specific'})
                </span>
                <div className="p-4 bg-primary-500/5 border border-primary-500/20 rounded-xl text-sm leading-relaxed text-slate-200">
                  {finding.ai_remediation || 'Refer to language-specific secure APIs and input validation.'}
                </div>
              </div>

              {/* Implementation Steps Checklist */}
              {implementationSteps.length > 0 && (
                <div className="space-y-3">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
                    Implementation Steps
                  </span>
                  <div className="space-y-2">
                    {implementationSteps.map((step, idx) => (
                      <div key={idx} className="flex items-start gap-3 p-3 bg-slate-900/40 border border-slate-800 rounded-xl text-sm">
                        <span className="w-5 h-5 rounded-full bg-primary-500/20 text-primary-400 text-xs flex items-center justify-center font-bold shrink-0 mt-0.5">
                          {idx + 1}
                        </span>
                        <span className="text-slate-300 leading-normal">{step}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Knowledge Base Baseline Guidance */}
              <div className="space-y-2 pt-2 border-t border-slate-800/80">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                  <BookOpen size={14} />
                  Knowledge Base Security Baseline (Generic Context)
                </span>
                <div className="p-4 bg-slate-900/20 border border-slate-800/60 rounded-xl text-xs text-slate-400 leading-relaxed space-y-1">
                  <p>{finding.knowledge_base_remediation || finding.remediation || 'Use defense-in-depth principles.'}</p>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: CODE FIX (DIFF VIEW) */}
          {activeTab === 'code' && (
            <div className="space-y-6">
              {/* Vulnerable Code Snippet */}
              {(finding.vulnerable_code || finding.code_snippet || finding.evidence) && (finding.vulnerable_code !== 'N/A' && finding.evidence !== 'N/A') && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold uppercase tracking-wider text-rose-400 flex items-center gap-1.5">
                      <Code2 size={14} />
                      Vulnerable Code
                    </span>
                    <button
                      onClick={() => handleCopy(finding.vulnerable_code || finding.code_snippet || finding.evidence, 'vulnerable')}
                      className="text-xs text-slate-400 hover:text-white flex items-center gap-1 bg-slate-800/50 hover:bg-slate-800 px-2.5 py-1 rounded-lg transition-colors"
                    >
                      {copiedVulnerable ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                      <span>{copiedVulnerable ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <div className="bg-slate-950 border border-rose-500/20 rounded-xl p-4 overflow-x-auto font-mono text-xs text-rose-200">
                    <pre>{finding.vulnerable_code || finding.code_snippet || finding.evidence}</pre>
                  </div>
                </div>
              )}

              {/* Remediated Secure Code */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle2 size={14} />
                    Remediated Secure Code ({finding.language || 'Language-Specific'})
                  </span>
                  <button
                    onClick={() => handleCopy(finding.secure_code || finding.suggested_fix || '', 'secure')}
                    className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20 px-3 py-1 rounded-lg transition-colors font-semibold"
                  >
                    {copiedSecure ? <Check size={12} className="text-emerald-300" /> : <Copy size={12} />}
                    <span>{copiedSecure ? 'Copied to Clipboard' : 'Copy Secure Code'}</span>
                  </button>
                </div>
                <div className="bg-slate-950 border border-emerald-500/30 rounded-xl p-4 overflow-x-auto font-mono text-xs text-emerald-200 shadow-inner">
                  <pre>{finding.secure_code || finding.suggested_fix || '// No secure replacement available.'}</pre>
                </div>
                <p className="text-xs text-slate-500 italic">
                  Note: The generated fix preserves original application flow while enforcing safe parameterized or bounds-checked execution.
                </p>
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
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl font-medium transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};

export default RemediationInspector;
