import React, { useState, useEffect } from 'react';
import { getReports, getVulnerabilities } from '../services/api';

export default function Dashboard() {
  const [metrics, setMetrics] = useState({
    totalReports: 0,
    totalVulnerabilities: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    open: 0,
    closed: 0
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadData = async () => {
    setLoading(true);
    setError('');
    try {
      const [reportsRes, vulnsRes] = await Promise.all([
        getReports(),
        getVulnerabilities()
      ]);

      const reports = reportsRes.data;
      const vulns = vulnsRes.data;

      const calculatedMetrics = {
        totalReports: reports.length,
        totalVulnerabilities: vulns.length,
        critical: vulns.filter(v => v.severity === 'Critical').length,
        high: vulns.filter(v => v.severity === 'High').length,
        medium: vulns.filter(v => v.severity === 'Medium').length,
        low: vulns.filter(v => v.severity === 'Low' || v.severity === 'Info').length,
        open: vulns.filter(v => (v.status || 'Open').toLowerCase() === 'open').length,
        closed: vulns.filter(v => (v.status || 'Open').toLowerCase() !== 'open').length
      };

      setMetrics(calculatedMetrics);
    } catch (err) {
      setError('Failed to fetch dashboard data. Make sure the backend server is running.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px]">
        <div className="w-12 h-12 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
        <p className="mt-4 text-sm font-medium text-gray-500">Loading system metrics...</p>
      </div>
    );
  }

  const openPercentage = metrics.totalVulnerabilities > 0 
    ? Math.round((metrics.open / metrics.totalVulnerabilities) * 100) 
    : 0;
  
  const closedPercentage = metrics.totalVulnerabilities > 0 
    ? Math.round((metrics.closed / metrics.totalVulnerabilities) * 100) 
    : 0;

  return (
    <div className="space-y-8">
      {/* Heading */}
      <div className="flex justify-between items-center border-b pb-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-800 tracking-tight">Security Overview</h2>
          <p className="text-sm text-gray-500">Real-time status of your applications' security posture</p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center space-x-2 text-sm bg-blue-50 text-blue-700 hover:bg-blue-100 px-4 py-2 rounded-xl font-medium border border-blue-200 shadow-sm transition-all duration-150 active:scale-95"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 15.89M9 11l3-3 3 3m-3-3v12" />
          </svg>
          <span>Sync Dashboard</span>
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl text-sm flex items-center space-x-3">
          <svg className="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <span>{error}</span>
        </div>
      )}

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Card 1: Reports */}
        <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm hover:shadow-md transition-shadow relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-blue-50 rounded-full translate-x-12 -translate-y-12 group-hover:scale-110 transition-transform duration-300" />
          <div className="relative">
            <div className="w-10 h-10 rounded-xl bg-blue-100 flex items-center justify-center text-blue-600 mb-4">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            <h3 className="text-sm font-semibold text-gray-500">Total VAPT Reports</h3>
            <p className="text-3xl font-bold text-gray-900 mt-1">{metrics.totalReports}</p>
          </div>
        </div>

        {/* Card 2: Total Vulnerabilities */}
        <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm hover:shadow-md transition-shadow relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-red-50 rounded-full translate-x-12 -translate-y-12 group-hover:scale-110 transition-transform duration-300" />
          <div className="relative">
            <div className="w-10 h-10 rounded-xl bg-red-100 flex items-center justify-center text-red-600 mb-4">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <h3 className="text-sm font-semibold text-gray-500">Total Vulnerabilities</h3>
            <p className="text-3xl font-bold text-gray-900 mt-1">{metrics.totalVulnerabilities}</p>
          </div>
        </div>

        {/* Card 3: Open Vulnerabilities */}
        <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm hover:shadow-md transition-shadow relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-amber-50 rounded-full translate-x-12 -translate-y-12 group-hover:scale-110 transition-transform duration-300" />
          <div className="relative">
            <div className="w-10 h-10 rounded-xl bg-amber-100 flex items-center justify-center text-amber-600 mb-4">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
            </div>
            <h3 className="text-sm font-semibold text-gray-500">Open Status</h3>
            <p className="text-3xl font-bold text-gray-900 mt-1">{metrics.open}</p>
          </div>
        </div>

        {/* Card 4: Resolved Vulnerabilities */}
        <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm hover:shadow-md transition-shadow relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-50 rounded-full translate-x-12 -translate-y-12 group-hover:scale-110 transition-transform duration-300" />
          <div className="relative">
            <div className="w-10 h-10 rounded-xl bg-emerald-100 flex items-center justify-center text-emerald-600 mb-4">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h3 className="text-sm font-semibold text-gray-500">Closed / Resolved</h3>
            <p className="text-3xl font-bold text-gray-900 mt-1">{metrics.closed}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Severity Breakdown */}
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6 lg:col-span-2">
          <h3 className="text-base font-bold text-slate-800 mb-6">Severity Breakdown</h3>
          <div className="space-y-5">
            {/* Critical */}
            <div>
              <div className="flex justify-between text-sm font-semibold mb-1">
                <span className="text-purple-700 flex items-center">
                  <span className="w-2.5 h-2.5 rounded-full bg-purple-600 mr-2"></span>
                  Critical Risk
                </span>
                <span className="text-slate-800">{metrics.critical}</span>
              </div>
              <div className="w-full bg-gray-100 h-3 rounded-full overflow-hidden">
                <div 
                  className="bg-purple-600 h-full rounded-full transition-all duration-500" 
                  style={{ width: `${metrics.totalVulnerabilities > 0 ? (metrics.critical / metrics.totalVulnerabilities) * 100 : 0}%` }}
                />
              </div>
            </div>

            {/* High */}
            <div>
              <div className="flex justify-between text-sm font-semibold mb-1">
                <span className="text-red-700 flex items-center">
                  <span className="w-2.5 h-2.5 rounded-full bg-red-600 mr-2"></span>
                  High Risk
                </span>
                <span className="text-slate-800">{metrics.high}</span>
              </div>
              <div className="w-full bg-gray-100 h-3 rounded-full overflow-hidden">
                <div 
                  className="bg-red-600 h-full rounded-full transition-all duration-500" 
                  style={{ width: `${metrics.totalVulnerabilities > 0 ? (metrics.high / metrics.totalVulnerabilities) * 100 : 0}%` }}
                />
              </div>
            </div>

            {/* Medium */}
            <div>
              <div className="flex justify-between text-sm font-semibold mb-1">
                <span className="text-amber-700 flex items-center">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500 mr-2"></span>
                  Medium Risk
                </span>
                <span className="text-slate-800">{metrics.medium}</span>
              </div>
              <div className="w-full bg-gray-100 h-3 rounded-full overflow-hidden">
                <div 
                  className="bg-amber-500 h-full rounded-full transition-all duration-500" 
                  style={{ width: `${metrics.totalVulnerabilities > 0 ? (metrics.medium / metrics.totalVulnerabilities) * 100 : 0}%` }}
                />
              </div>
            </div>

            {/* Low */}
            <div>
              <div className="flex justify-between text-sm font-semibold mb-1">
                <span className="text-gray-700 flex items-center">
                  <span className="w-2.5 h-2.5 rounded-full bg-gray-400 mr-2"></span>
                  Low / Info Risk
                </span>
                <span className="text-slate-800">{metrics.low}</span>
              </div>
              <div className="w-full bg-gray-100 h-3 rounded-full overflow-hidden">
                <div 
                  className="bg-gray-400 h-full rounded-full transition-all duration-500" 
                  style={{ width: `${metrics.totalVulnerabilities > 0 ? (metrics.low / metrics.totalVulnerabilities) * 100 : 0}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Resolution Ratio */}
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6 flex flex-col justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-800 mb-6">Resolution Progress</h3>
            <div className="space-y-4">
              <div className="flex justify-between items-center text-sm border-b pb-2">
                <span className="text-gray-500 font-medium">Open Bugs</span>
                <span className="font-semibold text-amber-600 bg-amber-50 px-2.5 py-0.5 rounded-full">{openPercentage}% ({metrics.open})</span>
              </div>
              <div className="flex justify-between items-center text-sm border-b pb-2">
                <span className="text-gray-500 font-medium">Resolved Bugs</span>
                <span className="font-semibold text-emerald-600 bg-emerald-50 px-2.5 py-0.5 rounded-full">{closedPercentage}% ({metrics.closed})</span>
              </div>
            </div>
          </div>

          <div className="mt-8 pt-4 border-t">
            <div className="flex items-center space-x-3 text-xs text-slate-500 bg-slate-50 p-3 rounded-xl border border-slate-100">
              <svg className="w-4 h-4 text-blue-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span>Vulnerabilities are updated immediately on uploading newer scans. Use the sync button to fetch the latest scans.</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
