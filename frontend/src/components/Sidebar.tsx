import React from 'react';
import { 
  ShieldAlert, LayoutDashboard, MailSearch, Link as LinkIcon, 
  History, BarChart3, Sliders, HelpCircle 
} from 'lucide-react';

interface SidebarProps {
  currentView: string;
  onNavigate: (view: string) => void;
  isConnected: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentView, onNavigate, isConnected }) => {
  const navItems = [
    { id: 'dashboard', label: 'Overview Dashboard', icon: LayoutDashboard },
    { id: 'message-scanner', label: 'Message Scanner', icon: MailSearch },
    { id: 'url-scanner', label: 'URL Scanner', icon: LinkIcon },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'analytics', label: 'Threat Analytics', icon: BarChart3 },
    { id: 'settings', label: 'API & Settings', icon: Sliders },
    { id: 'help', label: 'Safety Guidance', icon: HelpCircle },
  ];

  return (
    <aside className="w-64 bg-navy-800 border-r border-navy-500 flex flex-col justify-between p-5 z-50 shrink-0">
      <div>
        <div className="flex items-center gap-3 px-2 mb-8 cursor-pointer" onClick={() => onNavigate('dashboard')}>
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-400 to-brand-blue flex items-center justify-center text-navy-900 shadow-lg shadow-cyan-400/20">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-lg font-extrabold bg-gradient-to-r from-white to-cyan-400 bg-clip-text text-transparent leading-tight">
              ThreatGuard AI
            </h1>
            <p className="text-[11px] text-slate-400 font-medium">AI Phishing Protection</p>
          </div>
        </div>

        <nav>
          <ul className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = currentView === item.id;
              return (
                <li key={item.id}>
                  <button
                    onClick={() => onNavigate(item.id)}
                    className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                      active
                        ? 'bg-gradient-to-r from-cyan-400/15 to-transparent border-l-4 border-cyan-400 text-cyan-400 font-semibold'
                        : 'text-slate-400 hover:bg-navy-600 hover:text-slate-100'
                    }`}
                  >
                    <Icon className={`w-5 h-5 ${active ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span>{item.label}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>
      </div>

      <div className="pt-4 border-t border-navy-500">
        <div className="flex items-center gap-2.5 px-3 py-2 bg-navy-700 border border-navy-500 rounded-lg text-xs text-slate-300">
          <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-400 shadow-[0_0_8px_#10b981]' : 'bg-red-500 shadow-[0_0_8px_#ef4444]'}`}></span>
          <span>{isConnected ? 'API Connected' : 'API Disconnected'}</span>
        </div>
      </div>
    </aside>
  );
};
