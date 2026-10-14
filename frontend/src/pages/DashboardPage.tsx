import React from 'react';
import { Shield, AlertTriangle, Cpu, CheckCircle2, TrendingUp, PieChart, Activity } from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, PieChart as RePieChart, Pie, Cell } from 'recharts';
import { AnalyticsData, AnalysisResult } from '../api/client';
import { RiskBadge } from '../components/RiskBadge';

interface DashboardPageProps {
  analytics: AnalyticsData | null;
  recentScans: AnalysisResult[];
  onInspect: (caseId: string) => void;
  onNavigateHistory: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  analytics,
  recentScans,
  onInspect,
  onNavigateHistory
}) => {
  const trendData = analytics?.recent_trend || [
    { day: 'Mon', scans: 12, threats: 3 },
    { day: 'Tue', scans: 18, threats: 5 },
    { day: 'Wed', scans: 15, threats: 4 },
    { day: 'Thu', scans: 22, threats: 8 },
    { day: 'Fri', scans: 28, threats: 10 },
    { day: 'Sat', scans: 10, threats: 2 },
    { day: 'Sun', scans: 8, threats: 1 }
  ];

  const pieData = [
    { name: 'Critical', value: analytics?.risk_distribution.CRITICAL || 0, color: '#ef4444' },
    { name: 'High', value: analytics?.risk_distribution.HIGH || 0, color: '#f97316' },
    { name: 'Medium', value: analytics?.risk_distribution.MEDIUM || 0, color: '#f59e0b' },
    { name: 'Low', value: analytics?.risk_distribution.LOW || 0, color: '#10b981' },
  ];

  return (
    <div className="space-y-6">
      {/* Stats Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="bg-navy-700 border border-navy-500 rounded-xl p-5 hover:border-brand-blue transition-all">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-slate-400">Total Scans</span>
            <div className="w-9 h-9 rounded-lg bg-navy-600 flex items-center justify-center text-cyan-400">
              <Shield className="w-5 h-5" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-white">{analytics?.total_scans || 0}</div>
        </div>

        <div className="bg-navy-700 border border-navy-500 rounded-xl p-5 hover:border-brand-blue transition-all">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-slate-400">Critical & High Threats</span>
            <div className="w-9 h-9 rounded-lg bg-navy-600 flex items-center justify-center text-red-400">
              <AlertTriangle className="w-5 h-5" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-red-400">{analytics?.high_risk_count || 0}</div>
        </div>

        <div className="bg-navy-700 border border-navy-500 rounded-xl p-5 hover:border-brand-blue transition-all">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-slate-400">Engine Architecture</span>
            <div className="w-9 h-9 rounded-lg bg-navy-600 flex items-center justify-center text-brand-blue">
              <Cpu className="w-5 h-5" />
            </div>
          </div>
          <div className="text-base font-bold text-slate-200 mt-1">Hybrid ML + Rules</div>
        </div>

        <div className="bg-navy-700 border border-navy-500 rounded-xl p-5 hover:border-brand-blue transition-all">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold text-slate-400">Classifier Status</span>
            <div className="w-9 h-9 rounded-lg bg-navy-600 flex items-center justify-center text-emerald-400">
              <CheckCircle2 className="w-5 h-5" />
            </div>
          </div>
          <div className="text-base font-bold text-emerald-400 mt-1">TF-IDF Model Active</div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-navy-700 border border-navy-500 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white">7-Day Detection Trend</h2>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#4cc9f0" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#4cc9f0" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip contentStyle={{ backgroundColor: '#1c2541', borderColor: '#2b3a67', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="scans" stroke="#4cc9f0" fillOpacity={1} fill="url(#colorScans)" name="Total Scans" />
                <Area type="monotone" dataKey="threats" stroke="#ef4444" fillOpacity={1} fill="url(#colorThreats)" name="Threats" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-navy-700 border border-navy-500 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <PieChart className="w-5 h-5 text-amber-400" />
            <h2 className="text-base font-bold text-white">Risk Distribution</h2>
          </div>
          <div className="h-64 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <RePieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={4}>
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#1c2541', borderColor: '#2b3a67', borderRadius: '8px' }} />
              </RePieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="bg-navy-700 border border-navy-500 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white">Recent Case Files</h2>
          </div>
          <button onClick={onNavigateHistory} className="text-xs text-cyan-400 hover:underline">
            View All History &rarr;
          </button>
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
                <th className="px-4 py-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-navy-500 text-slate-200">
              {recentScans.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-slate-400">
                    No scan history available yet. Submit a message or URL to begin!
                  </td>
                </tr>
              ) : (
                recentScans.map((scan) => (
                  <tr key={scan.scan_id} className="hover:bg-navy-600/50 transition-colors">
                    <td className="px-4 py-3 font-mono font-semibold text-cyan-400">{scan.scan_id}</td>
                    <td className="px-4 py-3 capitalize">{scan.input_type}</td>
                    <td className="px-4 py-3 max-w-xs truncate">{scan.content_preview}</td>
                    <td className="px-4 py-3"><RiskBadge level={scan.risk_level} /></td>
                    <td className="px-4 py-3 font-bold">{scan.risk_score}/100</td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => onInspect(scan.scan_id)}
                        className="px-3 py-1 bg-navy-800 hover:bg-navy-600 border border-navy-500 text-xs text-slate-200 rounded transition-all"
                      >
                        Inspect
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
