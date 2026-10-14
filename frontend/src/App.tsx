import React, { useState, useEffect } from 'react';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { ScanModal } from './components/ScanModal';
import { DashboardPage } from './pages/DashboardPage';
import { MessageScannerPage } from './pages/MessageScannerPage';
import { UrlScannerPage } from './pages/UrlScannerPage';
import { HistoryPage } from './pages/HistoryPage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { SettingsPage } from './pages/SettingsPage';
import { HelpPage } from './pages/HelpPage';

import {
  checkHealth,
  fetchAnalytics,
  fetchHistory,
  fetchCaseDetail,
  analyzeMessage,
  AnalyticsData,
  AnalysisResult
} from './api/client';

export const App: React.FC = () => {
  const [currentView, setCurrentView] = useState('dashboard');
  const [isConnected, setIsConnected] = useState(true);
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [recentScans, setRecentScans] = useState<AnalysisResult[]>([]);
  const [selectedCase, setSelectedCase] = useState<AnalysisResult | null>(null);

  const checkConnection = async () => {
    const ok = await checkHealth();
    setIsConnected(ok);
  };

  const loadData = async () => {
    try {
      const [analyticsData, historyData] = await Promise.all([
        fetchAnalytics().catch(() => null),
        fetchHistory('', '', '', 1, 5).catch(() => ({ items: [] }))
      ]);
      if (analyticsData) setAnalytics(analyticsData);
      if (historyData?.items) setRecentScans(historyData.items);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    checkConnection();
    loadData();
    const interval = setInterval(checkConnection, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleInspectCase = async (caseId: string) => {
    try {
      const detail = await fetchCaseDetail(caseId);
      setSelectedCase(detail);
    } catch (err) {
      alert('Could not load case details.');
    }
  };

  const handleLoadDemo = async () => {
    try {
      const demoMsg = "URGENT: Your account has been suspended! Verify your OTP at http://paypa1-security-update.xyz/verify";
      const result = await analyzeMessage(demoMsg);
      setSelectedCase(result);
      loadData();
    } catch (err) {
      alert('Failed to execute demo scan. Ensure API server is running.');
    }
  };

  const getTitle = () => {
    const titles: Record<string, string> = {
      dashboard: 'Overview Dashboard',
      'message-scanner': 'AI Message Scanner',
      'url-scanner': 'Malicious URL Inspector',
      history: 'Scan History & Case Files',
      analytics: 'Threat Analytics & Trends',
      settings: 'API & System Settings',
      help: 'Safety Guidance',
    };
    return titles[currentView] || 'Overview Dashboard';
  };

  return (
    <div className="flex w-screen h-screen bg-navy-900 text-slate-100 font-sans overflow-hidden">
      <Sidebar
        currentView={currentView}
        onNavigate={setCurrentView}
        isConnected={isConnected}
      />

      <main className="flex-1 flex flex-col overflow-y-auto bg-[radial-gradient(circle_at_top_right,rgba(76,201,240,0.05),transparent_50%)]">
        <Header
          title={getTitle()}
          onNewScan={() => setCurrentView('message-scanner')}
          onLoadDemo={handleLoadDemo}
        />

        <div className="p-8">
          {currentView === 'dashboard' && (
            <DashboardPage
              analytics={analytics}
              recentScans={recentScans}
              onInspect={handleInspectCase}
              onNavigateHistory={() => setCurrentView('history')}
            />
          )}

          {currentView === 'message-scanner' && <MessageScannerPage />}
          {currentView === 'url-scanner' && <UrlScannerPage />}
          {currentView === 'history' && <HistoryPage onInspect={handleInspectCase} />}
          {currentView === 'analytics' && <AnalyticsPage analytics={analytics} />}
          {currentView === 'settings' && <SettingsPage isConnected={isConnected} onRefreshHealth={checkConnection} />}
          {currentView === 'help' && <HelpPage />}
        </div>
      </main>

      {selectedCase && (
        <ScanModal
          caseData={selectedCase}
          onClose={() => setSelectedCase(null)}
        />
      )}
    </div>
  );
};

export default App;
