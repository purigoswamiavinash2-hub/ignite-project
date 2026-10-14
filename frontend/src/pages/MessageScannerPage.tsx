import React, { useState } from 'react';
import { MailCheck, ShieldAlert, AlertCircle, Loader2, Sparkles } from 'lucide-react';
import { analyzeMessage, AnalysisResult } from '../api/client';
import { RiskBadge } from '../components/RiskBadge';

export const MessageScannerPage: React.FC = () => {
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!text.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const data = await analyzeMessage(text);
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'API engine is offline or unreachable.');
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = (presetKey: 'sbi' | 'fedex' | 'netflix' | 'amazon' | 'legit') => {
    const samples = {
      sbi: "URGENT SBI ALERT: Your NetBanking account has been blocked due to suspicious activity. Verify your details & enter OTP at http://sbi-netbanking-verify.xyz/login.php to reactivate immediately!",
      fedex: "FINAL NOTICE: Your FedEx package #FX-92810 could not be delivered due to unpaid customs fee of $2.99. Confirm delivery address now: http://fedex-redelivery.top",
      netflix: "Netflix Security Warning: Your monthly membership subscription payment was declined. Update your credit card details immediately to avoid account termination: http://netflix-billing.info",
      amazon: "CONGRATULATIONS! You have won an Amazon $500 Gift Card reward in our 2026 customer appreciation draw. Claim reward instantly: http://amz-rewards.site/claim",
      legit: "Hi Rahul, attached is the updated sprint retrospective document for next week's engineering sync. Please review when free!"
    };
    setText(samples[presetKey]);
  };

  return (
    <div className="space-y-6">
      <div className="bg-navy-700 border border-navy-500 rounded-xl p-6 shadow-xl">
        <div className="flex items-center gap-2 mb-2">
          <MailCheck className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-bold text-white">AI Phishing & Scam Text Inspector</h2>
        </div>
        <p className="text-sm text-slate-400 mb-4">
          Paste suspicious email body, SMS text, WhatsApp message, or social media post. Our multi-tiered ML pipeline will extract embedded links, inspect scam heuristics, and evaluate threat levels.
        </p>

        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste suspicious text here..."
          className="w-full h-44 bg-navy-900 border border-navy-500 rounded-xl p-4 text-slate-100 placeholder-slate-500 text-sm focus:border-cyan-400 focus:outline-none transition-all resize-y font-sans"
        />

        <div className="mt-4 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-400 font-semibold flex items-center gap-1">
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" /> Quick Demo Presets:
            </span>
            <button
              onClick={() => loadPreset('sbi')}
              className="px-2.5 py-1 bg-navy-800 hover:bg-navy-600 border border-navy-500 text-xs text-red-300 rounded-lg transition-all"
            >
              🏦 SBI Bank OTP Fraud
            </button>
            <button
              onClick={() => loadPreset('fedex')}
              className="px-2.5 py-1 bg-navy-800 hover:bg-navy-600 border border-navy-500 text-xs text-orange-300 rounded-lg transition-all"
            >
              📦 FedEx Package Scam
            </button>
            <button
              onClick={() => loadPreset('netflix')}
              className="px-2.5 py-1 bg-navy-800 hover:bg-navy-600 border border-navy-500 text-xs text-amber-300 rounded-lg transition-all"
            >
              🎬 Netflix Billing
            </button>
            <button
              onClick={() => loadPreset('amazon')}
              className="px-2.5 py-1 bg-navy-800 hover:bg-navy-600 border border-navy-500 text-xs text-cyan-300 rounded-lg transition-all"
            >
              🎁 Gift Card Lure
            </button>
            <button
              onClick={() => loadPreset('legit')}
              className="px-2.5 py-1 bg-navy-800 hover:bg-navy-600 border border-navy-500 text-xs text-emerald-300 rounded-lg transition-all"
            >
              ✅ Safe Email
            </button>
          </div>

          <div className="flex justify-end">
            <button
              onClick={handleScan}
              disabled={loading || !text.trim()}
              className="flex items-center gap-2 px-6 py-2.5 bg-gradient-to-r from-cyan-400 to-brand-blue hover:opacity-90 disabled:opacity-50 text-navy-900 font-bold rounded-xl text-sm transition-all shadow-lg shadow-cyan-400/20"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldAlert className="w-4 h-4" />}
              <span>{loading ? 'Analyzing with AI Model...' : 'Run AI Threat Analysis'}</span>
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-xl p-4 flex items-center gap-3 text-sm">
          <AlertCircle className="w-5 h-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {result && (
        <div className="bg-navy-700 border border-navy-500 rounded-xl p-6 space-y-5 animate-fadeIn shadow-2xl">
          <div className="flex justify-between items-start border-b border-navy-500 pb-4">
            <div>
              <div className="flex items-center gap-3 mb-1">
                <span className="font-mono font-bold text-cyan-400">Case #{result.scan_id}</span>
                <RiskBadge level={result.risk_level} />
              </div>
              <p className="text-xs text-slate-400">Analysis Engine: <strong>{result.analysis_type}</strong></p>
            </div>
            <div className="text-right">
              <div className="text-3xl font-extrabold text-white">{result.risk_score}</div>
              <div className="text-xs text-slate-400">Risk Score / 100</div>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-bold text-cyan-400 mb-2">Safety Recommendation</h3>
            <div className="bg-navy-900 border-l-4 border-cyan-400 p-3.5 rounded-xl text-sm text-slate-200">
              {result.recommendation}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h3 className="text-sm font-bold text-slate-200 mb-2">Identified Evidence & Threat Factors</h3>
              <ul className="space-y-2 text-sm text-slate-300">
                {result.reasons.length === 0 ? (
                  <li className="text-emerald-400">✅ No explicit scam patterns detected.</li>
                ) : (
                  result.reasons.map((reason, idx) => (
                    <li key={idx} className="flex items-start gap-2 bg-navy-900/60 p-2.5 rounded-lg border border-navy-500/60">
                      <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                      <span>{reason}</span>
                    </li>
                  ))
                )}
              </ul>
            </div>

            <div>
              <h3 className="text-sm font-bold text-slate-200 mb-2">Extracted Destination URLs</h3>
              {result.urls_found.length === 0 ? (
                <p className="text-xs text-slate-500">No embedded URLs found in text body.</p>
              ) : (
                <div className="space-y-1.5">
                  {result.urls_found.map((url, idx) => (
                    <div key={idx} className="bg-navy-900 p-2.5 rounded-lg text-xs font-mono text-cyan-400 border border-navy-500 break-all">
                      {url}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
