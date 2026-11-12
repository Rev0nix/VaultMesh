export type UserRole = 'ADMIN' | 'SECURITY_ANALYST' | 'VIEWER';

export type NavSection =
  | 'overview'
  | 'accounts'
  | 'findings'
  | 'threats'
  | 'iam'
  | 'network'
  | 'compliance'
  | 'audit'
  | 'reports'
  | 'settings';

export interface User {
  id: number;
  organization_id: number;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in_minutes: number;
}

export interface DashboardOverview {
  organization_id: number;
  aws_mode: string;
  has_scan_data: boolean;
  security_score: number | null;
  aws_accounts_connected: number;
  monitored_resources: number;
  findings_by_severity: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  total_open_findings: number;
  resource_distribution: { service: string; count: number }[];
  scan_history: {
    id: number;
    status: string;
    security_score: number;
    findings_count: number;
    resources_scanned: number;
    is_mock: boolean;
    started_at: string;
  }[];
  recent_threats: {
    id: number;
    event_name: string;
    severity: string;
    rule_triggered: string;
    region: string;
    occurred_at: string;
  }[];
}
