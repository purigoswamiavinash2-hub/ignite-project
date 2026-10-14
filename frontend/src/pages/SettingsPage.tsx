import React from 'react';
import { Server, ShieldCheck, AlertTriangle } from 'lucide-react';
import { API_BASE_URL, checkHealth } from '../api/client';

interface SettingsPageProps {
  isConnected: boolean;
  onRefreshHealth: () => void;
}

export const SettingsPage: React.FC<SettingsPageProps> = ({ isConnected, onRefreshHealth }) => {
  return (
    <div className="space-y-6 max-w-2xl">
      <div className="bg-navy-700 border border-navy-500 rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-2 mb-2">
          <Server className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-bold text-white">API Connection & System Status</h2>
        </div>

        <div className="space-y-3">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Configured Backend Base Endpoint</label>
            <input
              type="text"
              readOnly
              value={API_BASE_URL}
              className="w-full bg-navy-900 border border-navy-500 rounded-lg px-3.5 py-2 text-sm font-mono text-cyan-400 outline-none"
            />
          </div>

          <div className="flex items-center justify-between p-3.5 bg-navy-900 border border-navy-500 rounded-lg">
            <div className="flex items-center gap-2 text-sm">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span className="text-slate-300">FastAPI Backend Status:</span>
            </div>
            <span className={`text-xs font-bold px-2.5 py-1 rounded-full border ${isConnected ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' : 'bg-red-500/15 text-red-400 border-red-500/30'}`}>
              {isConnected ? 'ONLINE & CONNECTED' : 'OFFLINE'}
            </span>
          </div>

          <button
            onClick={onRefreshHealth}
            className="w-full py-2.5 bg-navy-800 hover:bg-navy-600 border border-navy-500 text-slate-200 text-sm font-semibold rounded-lg transition-all"
          >
            Ping API Health Check
          </button>
        </div>
      </div>

      <div className="bg-navy-700 border border-navy-500 rounded-xl p-6 space-y-3">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
          <h2 className="text-base font-bold text-white">Detection Limitations Disclosure</h2>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          ThreatGuard AI utilizes trained machine learning pattern classification, heuristic rule matching, and structural domain analysis. While highly effective against common phishing schemes, a low risk score does not guarantee 100% safety. Always verify sender identity independently.
        </p>
      </div>
    </div>
  );
};
