export type UserRole = 'ADMIN' | 'SECURITY_ANALYST' | 'VIEWER';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingStatus = 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'RISK_ACCEPTED';

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

export interface AWSRegion {
  id: number;
  region_code: string;
  is_enabled: boolean;
}

export interface AWSAccount {
  id: number;
  organization_id: number;
  aws_account_id: string;
  alias: string;
  role_arn: string | null;
  external_id: string | null;
  default_region: string;
  is_mock: boolean;
  connection_status: string;
  last_synced_at: string | null;
  created_at: string;
  regions: AWSRegion[];
}

export interface ConnectionValidation {
  account_id: number;
  aws_account_id: string;
  is_mock: boolean;
  status: string;
  caller_arn: string;
  message: string;
  validated_at: string;
}

export interface ScanJob {
  id: number;
  aws_account_id: number;
  status: string;
  regions_scanned: string[];
  resources_scanned: number;
  findings_count: number;
  security_score: number;
  is_mock: boolean;
  started_at: string;
  completed_at: string | null;
}

export interface Finding {
  id: number;
  finding_uid: string;
  scan_job_id: number;
  rule_id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  status: FindingStatus;
  evidence: Record<string, unknown>;
  remediation_summary: string;
  remediation_cli: string | null;
  remediation_terraform: string | null;
  aws_doc_url: string | null;
  investigation_notes: string | null;
  is_mock: boolean;
  detected_at: string;
  updated_at: string;
  resource: {
    id: number;
    resource_arn: string;
    resource_id: string;
    resource_name: string | null;
    service: string;
    resource_type: string;
    region: string;
  };
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

export interface IAMPrincipalAnalysis {
  id: number;
  name: string;
  arn: string;
  principal_type: string;
  mfa_enabled: boolean | null;
  trust_principal: string;
  attached_policies: string[];
  has_wildcard_admin: boolean;
  risk_score: number;
  risk_level: string;
  issues: string[];
  recommendations: string[];
  is_mock: boolean;
}

export interface IAMAnalysisResponse {
  summary: {
    total_principals: number;
    wildcard_admin_principals: number;
    users_missing_mfa: number;
    risky_trust_policies: number;
  };
  principals: IAMPrincipalAnalysis[];
}

export interface NetworkIngressRule {
  security_group_id: string;
  security_group_name: string;
  region: string;
  vpc_id: string;
  protocol: string;
  port_range: string;
  service_label: string;
  source_cidr: string;
  is_public: boolean;
  risk_level: string;
  recommendation: string;
  is_mock: boolean;
}

export interface NetworkAnalysisResponse {
  summary: {
    total_security_groups: number;
    public_ingress_rules: number;
    critical_admin_or_db_exposures: number;
  };
  security_groups: {
    id: number;
    group_id: string;
    group_name: string;
    arn: string;
    region: string;
    vpc_id: string;
    total_ingress_rules: number;
    public_ingress_rules: number;
    is_mock: boolean;
  }[];
  ingress_rules: NetworkIngressRule[];
}
