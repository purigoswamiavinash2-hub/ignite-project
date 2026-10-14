import React from 'react';
import { Plus, Sparkles } from 'lucide-react';

interface HeaderProps {
  title: string;
  onNewScan: () => void;
  onLoadDemo: () => void;
}

export const Header: React.FC<HeaderProps> = ({ title, onNewScan, onLoadDemo }) => {
  return (
    <header className="h-[70px] border-b border-navy-500 flex items-center justify-between px-8 bg-navy-900/80 backdrop-blur-md sticky top-0 z-40">
      <h1 className="text-xl font-bold text-white">{title}</h1>
      <div className="flex items-center gap-3">
        <button
          onClick={onNewScan}
          className="flex items-center gap-2 px-4 py-2 bg-navy-700 hover:bg-navy-600 border border-navy-500 text-slate-200 rounded-lg text-sm font-medium transition-all"
        >
          <Plus className="w-4 h-4" />
          <span>New Scan</span>
        </button>
        <button
          onClick={onLoadDemo}
          className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-400 to-brand-blue hover:opacity-90 text-navy-900 rounded-lg text-sm font-semibold transition-all shadow-lg shadow-cyan-400/20"
        >
          <Sparkles className="w-4 h-4" />
          <span>Load Demo Scan</span>
        </button>
      </div>
    </header>
  );
};
