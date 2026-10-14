export const API_BASE_URL = ((import.meta as any).env?.VITE_API_BASE_URL as string) || 'http://127.0.0.1:8000';

export interface AnalysisResult {
  scan_id: string;
  input_type: 'message' | 'url';
  content_preview: string;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_score: number;
  reasons: string[];
  urls_found: string[];
  url_analysis?: {
    total_urls?: number;
    max_url_score?: number;
    details?: any[];
    url?: string;
    domain?: string;
    is_ip?: boolean;
    is_shortener?: boolean;
    suspicious_tld?: boolean;
    subdomain_count?: number;
    lookalike_detected?: boolean;
    entropy?: number;
    reputation_status?: string;
  };
  recommendation: string;
  analysis_type: string;
  model_confidence?: number;
  created_at: string;
}

export interface HistoryResponse {
  total: number;
  page: number;
  limit: number;
  items: AnalysisResult[];
}

export interface AnalyticsData {
  total_scans: number;
  risk_distribution: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  high_risk_count: number;
  recent_trend: Array<{ day: string; scans: number; threats: number }>;
  top_threat_categories: Array<{ category: string; count: number; percentage: number }>;
  demo_mode: boolean;
}

export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE_URL}/health`);
    return res.ok;
  } catch {
    return false;
  }
}

export async function analyzeMessage(text: string): Promise<AnalysisResult> {
  const res = await fetch(`${API_BASE_URL}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Analysis failed' }));
    throw new Error(err.detail || 'Failed to analyze message content');
  }
  return res.json();
}

export async function analyzeUrl(url: string): Promise<AnalysisResult> {
  const res = await fetch(`${API_BASE_URL}/api/analyze-url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'URL Analysis failed' }));
    throw new Error(err.detail || 'Failed to analyze URL');
  }
  return res.json();
}

export async function fetchHistory(
  search = '',
  riskLevel = '',
  inputType = '',
  page = 1,
  limit = 20
): Promise<HistoryResponse> {
  const params = new URLSearchParams({
    page: page.toString(),
    limit: limit.toString(),
  });
  if (search) params.append('search', search);
  if (riskLevel) params.append('risk_level', riskLevel);
  if (inputType) params.append('input_type', inputType);

  const res = await fetch(`${API_BASE_URL}/api/history?${params.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch scan history');
  return res.json();
}

export async function fetchCaseDetail(caseId: string): Promise<AnalysisResult> {
  const res = await fetch(`${API_BASE_URL}/api/history/${caseId}`);
  if (!res.ok) throw new Error('Case not found');
  return res.json();
}

export async function deleteCase(caseId: string): Promise<void> {
  const res = await fetch(`${API_BASE_URL}/api/history/${caseId}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete case file');
}

export async function fetchAnalytics(): Promise<AnalyticsData> {
  const res = await fetch(`${API_BASE_URL}/api/analytics`);
  if (!res.ok) throw new Error('Failed to fetch analytics');
  return res.json();
}
