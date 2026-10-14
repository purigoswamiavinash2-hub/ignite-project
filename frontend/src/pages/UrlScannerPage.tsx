import React, { useState } from 'react';
import { Link as LinkIcon, Search, AlertCircle, Loader2 } from 'lucide-react';
import { analyzeUrl, AnalysisResult } from '../api/client';
import { RiskBadge } from '../components/RiskBadge';

export const UrlScannerPage: React.FC = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const data = await analyzeUrl(url);
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to inspect URL.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-navy-700 border border-navy-500 rounded-xl p-6">
        <div className="flex items-center gap-2 mb-2">
          <LinkIcon className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-bold text-white">Inspect Suspicious URL / Link</h2>
        </div>
        <p className="text-sm text-slate-400 mb-4">
          Enter a domain name or full URL to inspect structural integrity, IP hosting, lookalike domain indicators, and top-level domain risk.
        </p>

        <div className="flex gap-3">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="e.g., http://paypa1-security-update.xyz/verify-login.php"
            className="flex-1 bg-navy-900 border border-navy-500 rounded-lg px-4 py-2.5 text-slate-100 placeholder-slate-500 text-sm font-mono focus:border-cyan-400 focus:outline-none transition-all"
          />
          <button
            onClick={handleScan}
            disabled={loading || !url.trim()}
            className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-400 to-brand-blue hover:opacity-90 disabled:opacity-50 text-navy-900 font-bold rounded-lg text-sm transition-all shadow-lg shadow-cyan-400/20 whitespace-nowrap"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            <span>{loading ? 'Inspecting...' : 'Analyze URL'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-xl p-4 flex items-center gap-3 text-sm">
          <AlertCircle className="w-5 h-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {result && (
        <div className="bg-navy-700 border border-navy-500 rounded-xl p-6 space-y-5 animate-fadeIn">
          <div className="flex justify-between items-start border-b border-navy-500 pb-4">
            <div>
              <div className="flex items-center gap-3 mb-1">
                <span className="font-mono font-bold text-cyan-400">Case #{result.scan_id}</span>
                <RiskBadge level={result.risk_level} />
              </div>
              <p className="text-xs text-slate-400">Analysis: <strong>Structural & Domain Heuristics</strong></p>
            </div>
            <div className="text-right">
              <div className="text-3xl font-extrabold text-white">{result.risk_score}</div>
              <div className="text-xs text-slate-400">Risk Score / 100</div>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-bold text-cyan-400 mb-2">Safety Recommendation</h3>
            <div className="bg-navy-900 border-l-4 border-cyan-400 p-3.5 rounded text-sm text-slate-200">
              {result.recommendation}
            </div>
          </div>

          <div>
            <h3 className="text-sm font-bold text-slate-200 mb-2">Domain Structural Evidence</h3>
            <ul className="space-y-1.5 text-sm text-slate-300">
              {result.reasons.length === 0 ? (
                <li className="text-emerald-400">No suspicious domain flags detected.</li>
              ) : (
                result.reasons.map((r, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    <span>{r}</span>
                  </li>
                ))
              )}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};
