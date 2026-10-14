import React from 'react';
import { ShieldAlert, Layers } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';
import { AnalyticsData } from '../api/client';

interface AnalyticsPageProps {
  analytics: AnalyticsData | null;
}

export const AnalyticsPage: React.FC<AnalyticsPageProps> = ({ analytics }) => {
  const categoriesData = analytics?.top_threat_categories || [
    { category: 'Urgency & Coercion', count: 42 },
    { category: 'Credential Harvesting', count: 35 },
    { category: 'Brand Impersonation', count: 20 },
    { category: 'Suspicious TLDs', count: 14 }
  ];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-navy-700 border border-navy-500 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            <h2 className="text-base font-bold text-white">Top Scam Categories Detected</h2>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoriesData} layout="vertical">
                <XAxis type="number" stroke="#64748b" fontSize={12} />
                <YAxis dataKey="category" type="category" stroke="#94a3b8" fontSize={11} width={130} />
                <Tooltip contentStyle={{ backgroundColor: '#1c2541', borderColor: '#2b3a67', borderRadius: '8px' }} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {categoriesData.map((_, idx) => (
                    <Cell key={idx} fill={['#ef4444', '#f97316', '#4cc9f0', '#3b82f6'][idx % 4]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-navy-700 border border-navy-500 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 mb-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white">Detection Weight Weights</h2>
          </div>

          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-300 font-medium">Machine Learning Text Vectorizer (TF-IDF)</span>
                <span className="font-bold text-cyan-400">45% Weight</span>
              </div>
              <div className="h-2 bg-navy-900 rounded-full overflow-hidden">
                <div className="h-full bg-cyan-400 w-[45%]"></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-300 font-medium">Scam Language Heuristic Patterns</span>
                <span className="font-bold text-brand-blue">30% Weight</span>
              </div>
              <div className="h-2 bg-navy-900 rounded-full overflow-hidden">
                <div className="h-full bg-brand-blue w-[30%]"></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-300 font-medium">Domain Structural Feature Extraction</span>
                <span className="font-bold text-amber-400">25% Weight</span>
              </div>
              <div className="h-2 bg-navy-900 rounded-full overflow-hidden">
                <div className="h-full bg-amber-400 w-[25%]"></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
