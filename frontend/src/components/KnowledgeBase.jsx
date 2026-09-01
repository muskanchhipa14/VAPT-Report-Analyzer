import React, { useState, useEffect } from 'react';
import { kbAPI } from '../services/api';
import { BookOpen, Search, Sparkles, Layers, Terminal, Loader2 } from 'lucide-react';


const KnowledgeBase = () => {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedItem, setSelectedItem] = useState(null);

  const fetchKB = async () => {
    setLoading(true);
    try {
      const data = await kbAPI.getKBItems();
      setItems(data);
      if (data.length > 0) setSelectedItem(data[0]);
    } catch (e) {
      console.error("Failed to fetch knowledge base", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchKB();
  }, []);

  const filteredItems = items.filter(item =>
    item.cwe_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.vulnerability_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.owasp_category.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold font-outfit text-white tracking-wide font-outfit">Vulnerability Knowledge Base</h1>
        <p className="text-slate-400 text-sm mt-1">Browse secure coding guidelines, OWASP categories, and CAPEC attack vectors.</p>
      </div>

      {loading ? (
        <div className="flex flex-col items-center justify-center py-32 text-slate-500">
          <Loader2 size={36} className="animate-spin text-primary-500 mb-4" />
          <span>Loading knowledge base logs...</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left panel: List */}
          <div className="lg:col-span-1 flex flex-col gap-4">
            {/* Search */}
            <div className="relative">
              <Search size={18} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                className="w-full bg-slate-900 border border-slate-800 focus:border-primary-500 rounded-xl py-3 pl-11 pr-4 text-white placeholder-slate-500 outline-none transition-colors"
                placeholder="Search CWE or name..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>

            <div className="glass-panel rounded-2xl overflow-hidden border border-slate-800/80 max-h-[500px] overflow-y-auto divide-y divide-slate-800/40">
              {filteredItems.length > 0 ? (
                filteredItems.map(item => (
                  <div
                    key={item.id}
                    onClick={() => setSelectedItem(item)}
                    className={`p-4 cursor-pointer transition-colors hover:bg-slate-800/20 ${
                      selectedItem?.id === item.id ? 'bg-primary-500/10 border-l-2 border-primary-500' : ''
                    }`}
                  >
                    <span className="text-xs text-primary-400 font-bold block">{item.cwe_id}</span>
                    <span className="text-slate-200 text-sm font-semibold mt-1 block">{item.vulnerability_name}</span>
                  </div>
                ))
              ) : (
                <div className="p-8 text-center text-slate-500 text-sm">
                  No matching items found.
                </div>
              )}
            </div>
          </div>

          {/* Right panel: Detail */}
          <div className="lg:col-span-2">
            {selectedItem ? (
              <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 space-y-6">
                <div>
                  <span className="text-xs text-primary-400 font-bold tracking-wider uppercase">{selectedItem.cwe_id}</span>
                  <h2 className="text-2xl font-bold font-outfit text-white tracking-wide mt-1">{selectedItem.vulnerability_name}</h2>
                </div>

                {/* Metadata badges */}
                <div className="flex flex-wrap gap-2.5">
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-slate-900/60 border border-slate-800 rounded-xl text-xs text-slate-300 font-semibold">
                    <Layers size={13} className="text-primary-400" />
                    <span>OWASP: {selectedItem.owasp_category}</span>
                  </span>
                  {selectedItem.capec_id && selectedItem.capec_id !== 'N/A' && (
                    <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-slate-900/60 border border-slate-800 rounded-xl text-xs text-slate-300 font-semibold">
                      <Terminal size={13} className="text-orange-400" />
                      <span>CAPEC ID: {selectedItem.capec_id}</span>
                    </span>
                  )}
                </div>

                {/* Description */}
                <div className="space-y-2">
                  <h4 className="text-slate-400 text-xs font-bold uppercase tracking-wider">Vulnerability Description</h4>
                  <p className="text-slate-300 text-sm leading-relaxed">{selectedItem.description}</p>
                </div>

                {/* Secure Coding Guidelines (Remediation) */}
                <div className="space-y-3 pt-2">
                  <h4 className="text-slate-400 text-xs font-bold uppercase tracking-wider flex items-center gap-1.5">
                    <Sparkles size={14} className="text-primary-400" />
                    <span>Secure Coding & Remediation Guidelines</span>
                  </h4>
                  <div className="bg-primary-500/5 border border-primary-500/10 rounded-2xl p-5 space-y-3">
                    {(selectedItem.remediation || selectedItem.recommendations || "No remediation guidelines available.").split('\n').map((rec, rIdx) => (
                      <div key={rIdx} className="flex gap-2.5 text-slate-300 text-sm leading-relaxed">
                        <span className="text-primary-400 shrink-0 font-bold">•</span>
                        <span>{rec.replace(/^\d+\.\s*/, '')}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="glass-panel p-12 rounded-2xl border border-slate-800/80 text-center text-slate-500 flex flex-col items-center justify-center">
                <BookOpen size={48} className="text-slate-600 mb-4" />
                <span>Select a vulnerability from the list to view secure coding recommendations.</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default KnowledgeBase;
