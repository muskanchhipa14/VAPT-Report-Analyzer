import React, { useState } from 'react';
import Users from './components/Users';
import Reports from './components/Reports';
import Vulnerabilities from './components/Vulnerabilities';
import KnowledgeBase from './components/KnowledgeBase';

export default function App() {
  const [activeTab, setActiveTab] = useState('users');

  const tabs = [
    { id: 'users', label: 'User Management' },
    { id: 'reports', label: 'VAPT Reports' },
    { id: 'vulnerabilities', label: 'Vulnerability Information' },
    { id: 'kb', label: 'Knowledge Base' },
  ];

  return (
    <div className="min-h-screen bg-gray-100 text-gray-900 font-sans">
      <header className="bg-slate-900 text-white py-4 px-6 shadow-md">
        <h1 className="text-xl font-bold">Intelligent VAPT Report Analysis & Remediation System</h1>
      </header>

      <nav className="bg-white border-b border-gray-200 shadow-sm">
        <div className="max-w-6xl mx-auto flex space-x-1 px-6">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-3 px-5 text-sm font-semibold border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-600 text-blue-600 bg-blue-50/50'
                  : 'border-transparent text-gray-600 hover:text-gray-900 hover:border-gray-300'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </nav>

      <main className="max-w-6xl mx-auto p-6">
        {activeTab === 'users' && <Users />}
        {activeTab === 'reports' && <Reports />}
        {activeTab === 'vulnerabilities' && <Vulnerabilities />}
        {activeTab === 'kb' && <KnowledgeBase />}
      </main>
    </div>
  );
}