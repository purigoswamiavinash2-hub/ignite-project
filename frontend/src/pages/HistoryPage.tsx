import React, { useState, useEffect } from 'react';
import { Archive, Search, Filter, Trash2, Eye } from 'lucide-react';
import { fetchHistory, deleteCase, AnalysisResult } from '../api/client';
import { RiskBadge } from '../components/RiskBadge';

interface HistoryPageProps {
  onInspect: (caseId: string) => void;
}

export const HistoryPage: React.FC<HistoryPageProps> = ({ onInspect }) => {
  const [items, setItems] = useState<AnalysisResult[]>([]);
  const [search, setSearch] = useState('');
  const [riskLevel, setRiskLevel] = useState('');
  const [loading, setLoading] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await fetchHistory(search, riskLevel);
      setItems(data.items || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [search, riskLevel]);

  const handleDelete = async (caseId: string) => {
    if (!confirm(`Are you sure you want to delete case ${caseId}?`)) return;
    try {
      await deleteCase(caseId);
      loadData();
    } catch (err) {
      alert('Could not delete case.');
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-navy-700 border border-navy-500 rounded-xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div className="flex items-center gap-2">
            <Archive className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-bold text-white">Scan History & Case Files</h2>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search case ID or content..."
                className="bg-navy-900 border border-navy-500 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-400 focus:outline-none transition-all w-60"
              />
            </div>

            <div className="relative">
              <Filter className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
              <select
                value={riskLevel}
                onChange={(e) => setRiskLevel(e.target.value)}
                className="bg-navy-900 border border-navy-500 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-100 focus:border-cyan-400 focus:outline-none transition-all appearance-none cursor-pointer"
              >
                <option value="">All Risks</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-navy-800 text-slate-400 uppercase text-[11px] font-semibold border-b border-navy-500">
              <tr>
                <th className="px-4 py-3">Scan ID</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Preview</th>
                <th className="px-4 py-3">Risk Level</th>
                <th className="px-4 py-3">Score</th>
                <th className="px-4 py-3">Date</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-navy-500 text-slate-200">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-400">Loading cases...</td>
                </tr>
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-400">No matching scan records found.</td>
                </tr>
              ) : (
                items.map((item) => (
                  <tr key={item.scan_id} className="hover:bg-navy-600/50 transition-colors">
                    <td className="px-4 py-3 font-mono font-semibold text-cyan-400">{item.scan_id}</td>
                    <td className="px-4 py-3 capitalize">{item.input_type}</td>
                    <td className="px-4 py-3 max-w-xs truncate">{item.content_preview}</td>
                    <td className="px-4 py-3"><RiskBadge level={item.risk_level} /></td>
                    <td className="px-4 py-3 font-bold">{item.risk_score}</td>
                    <td className="px-4 py-3 text-xs text-slate-400">{new Date(item.created_at).toLocaleString()}</td>
                    <td className="px-4 py-3 flex items-center gap-2">
                      <button
                        onClick={() => onInspect(item.scan_id)}
                        className="p-1.5 bg-navy-800 hover:bg-navy-600 border border-navy-500 rounded text-slate-300 hover:text-white transition-all"
                        title="View Case"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDelete(item.scan_id)}
                        className="p-1.5 bg-navy-800 hover:bg-red-500/20 border border-navy-500 rounded text-red-400 hover:border-red-500/40 transition-all"
                        title="Delete Case"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
