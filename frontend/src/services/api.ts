import type {
  AWSAccount,
  ConnectionValidation,
  DashboardOverview,
  Finding,
  ScanJob,
  TokenResponse,
  User,
  AWSRegion,
} from '../types';

const TOKEN_STORAGE_KEY = 'vaultmesh_access_token';
const USER_STORAGE_KEY = 'vaultmesh_current_user';

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_STORAGE_KEY);
}

export function setStoredToken(token: string | null): void {
  if (token) {
    localStorage.setItem(TOKEN_STORAGE_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
  }
}

async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  await new Promise((resolve) => setTimeout(resolve, 200));
  const body = options.body ? JSON.parse(options.body as string) : {};

  if (path.startsWith('/auth/register') || path.startsWith('/auth/login')) {
    const user: User = {
      id: 1,
      email: body.email || 'revanth@vaultmesh.io',
      full_name: body.full_name || 'Revanth Gowda',
      organization_id: 1,
      role: 'ADMIN',
      is_active: true,
      created_at: new Date().toISOString(),
    };
    localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
    const tokenRes: any = {
      access_token: 'mock-jwt-token-vaultmesh-2026',
      token_type: 'bearer',
    };
    return tokenRes as unknown as T;
  }

  if (path.startsWith('/auth/me')) {
    const cached = localStorage.getItem(USER_STORAGE_KEY);
    if (cached) return JSON.parse(cached) as unknown as T;
    return {
      id: 1,
      email: 'revanth@vaultmesh.io',
      full_name: 'Revanth Gowda',
      organization_id: 1,
      role: 'ADMIN',
      is_active: true,
      created_at: new Date().toISOString(),
    } as unknown as T;
  }

  if (path.startsWith('/dashboard/overview')) {
    const overview: DashboardOverview = {
      total_scans: 1,
      active_accounts: 1,
      open_findings: 14,
      critical_findings: 2,
      compliance_score: 84.5,
    };
    return overview as unknown as T;
  }

  if (path.startsWith('/accounts')) {
    if (options.method === 'POST') {
      const newAcc: AWSAccount = {
        id: Math.floor(Math.random() * 1000),
        organization_id: 1,
        aws_account_id: body.aws_account_id || '123456789012',
        alias: body.alias || 'Production AWS',
        is_mock: true,
        role_arn: 'arn:aws:iam::123456789012:role/VaultMeshScannerRole',
        external_id: 'mock-external-id',
        default_region: (body.default_region || 'ap-south-1') as any,
        regions: (body.regions || ['ap-south-1']) as any[],
        connection_status: 'CONNECTED',
        last_synced_at: new Date().toISOString(),
      };
      return newAcc as unknown as T;
    }
    const accounts: AWSAccount[] = [
      {
        id: 1,
        organization_id: 1,
        aws_account_id: '987654321098',
        alias: 'AWS-Prod-Core',
        is_mock: true,
        role_arn: 'arn:aws:iam::987654321098:role/VaultMeshScannerRole',
        external_id: 'mock-external-id',
        default_region: 'ap-south-1' as any,
        regions: ['ap-south-1' as any, 'us-east-1' as any],
        connection_status: 'CONNECTED',
        last_synced_at: new Date().toISOString(),
      },
    ];
    return accounts as unknown as T;
  }

  if (path.includes('/validate')) {
    const val: ConnectionValidation = {
      success: true,
      message: 'AWS STS AssumeRole validation successful (Mock Mode)',
      account_id: 1,
      partition: 'aws',
      arn: 'arn:aws:iam::987654321098:role/VaultMeshScannerRole',
    };
    return val as unknown as T;
  }

  if (path.startsWith('/scans')) {
    if (options.method === 'POST') {
      const scan: any = {
        id: Math.floor(Math.random() * 1000),
        aws_account_id: body.aws_account_id || 1,
        status: 'COMPLETED',
        findings_count: 14,
      };
      return scan as unknown as T;
    }
    const scans: ScanJob[] = [
      { id: 1, aws_account_id: 1, status: 'COMPLETED', findings_count: 14 }
    ];
    return scans as unknown as T;
  }

  if (path.startsWith('/findings')) {
    const findings: Finding[] = [
      {
        id: 1,
        finding_uid: 'CKV_AWS_20',
        title: 'S3 Bucket has public read access enabled',
        description: 'The S3 bucket policy allows public read access to stored objects.',
        severity: 'CRITICAL',
        status: 'OPEN',
        resource: 'arn:aws:s3:::vaultmesh-audit-logs-prod',
        region: 'ap-south-1',
        framework: 'CIS AWS Foundations',
        remediation_guidance: 'Disable public block settings and restrict bucket ACLs.',
      },
      {
        id: 2,
        finding_uid: 'CKV_AWS_18',
        title: 'S3 Bucket access logging is not enabled',
        description: 'Target bucket does not have server access logging configured.',
        severity: 'MEDIUM',
        status: 'OPEN',
        resource: 'arn:aws:s3:::vaultmesh-data-bucket',
        region: 'ap-south-1',
        framework: 'CIS AWS Foundations',
        remediation_guidance: 'Enable S3 access logging pointing to a secure logging bucket.',
      },
    ];
    return findings as unknown as T;
  }

  if (path.startsWith('/analyzers/iam')) {
    return {
      total_principals: 12,
      overprivileged_count: 3,
      admin_roles_count: 2,
      risk_score: 72.4,
      principals: []
    } as unknown as T;
  }

  if (path.startsWith('/analyzers/network')) {
    return {
      total_security_groups: 8,
      public_sg_count: 1,
      unrestricted_ssh_count: 1,
      risk_score: 65.0,
      rules: []
    } as unknown as T;
  }

  if (path.startsWith('/threats')) {
    if (options.method === 'POST') {
      return { events_inspected: 154, alerts_matched: 2, new_alerts_saved: 2 } as unknown as T;
    }
    return [] as unknown as T;
  }

  if (path.startsWith('/compliance')) {
    return {
      disclaimer: 'Calculated from automated CSPM checks',
      summary: { total_controls: 20, passing_controls: 17, failing_controls: 3, readiness_percentage: 85.0 },
      controls: [
        { framework: 'CIS AWS', control_id: '1.1', title: 'Maintain root account security', mapped_rules: ['CKV_AWS_1'], status: 'PASS', violated_rules: [] },
        { framework: 'CIS AWS', control_id: '2.1', title: 'S3 bucket encryption', mapped_rules: ['CKV_AWS_20'], status: 'FAIL', violated_rules: ['CKV_AWS_20'] },
      ]
    } as unknown as T;
  }

  if (path.startsWith('/audit/logs')) {
    return [] as unknown as T;
  }

  if (path.startsWith('/audit/team')) {
    return [] as unknown as T;
  }

  return {} as T;
}

export const authApi = {
  register: (payload: any) => apiFetch<TokenResponse>('/auth/register', { method: 'POST', body: JSON.stringify(payload) }),
  login: (payload: any) => apiFetch<TokenResponse>('/auth/login', { method: 'POST', body: JSON.stringify(payload) }),
  me: () => apiFetch<User>('/auth/me'),
};

export const dashboardApi = {
  getOverview: () => apiFetch<DashboardOverview>('/dashboard/overview'),
};

export const accountsApi = {
  list: () => apiFetch<AWSAccount[]>('/accounts'),
  getOnboardingTemplate: () => apiFetch<any>('/accounts/onboarding-template'),
  create: (payload: any) => apiFetch<AWSAccount>('/accounts', { method: 'POST', body: JSON.stringify(payload) }),
  validate: (id: number) => apiFetch<ConnectionValidation>(`/accounts/${id}/validate`, { method: 'POST' }),
  remove: (id: number) => apiFetch<void>(`/accounts/${id}`, { method: 'DELETE' }),
};

export const scansApi = {
  list: () => apiFetch<ScanJob[]>('/scans'),
  run: (aws_account_id: number) => apiFetch<ScanJob>('/scans/run', { method: 'POST', body: JSON.stringify({ aws_account_id }) }),
};

export const findingsApi = {
  remediate: async (id: number, dryRun: boolean = true) => ({ status: 'SUCCESS', finding_id: id, mode: dryRun ? 'DRY_RUN_SIMULATION' : 'LIVE' }),
  list: (_params?: any) => apiFetch<Finding[]>('/findings'),
  update: (id: number, payload: any) => apiFetch<Finding>(`/findings/${id}`, { method: 'PATCH', body: JSON.stringify(payload) }),
};

export const analyzersApi = {
  getIam: () => apiFetch<any>('/analyzers/iam'),
  getNetwork: () => apiFetch<any>('/analyzers/network'),
};


export const threatsApi = {
  list: () => apiFetch<any[]>('/threats'),
  analyze: (aws_account_id: number) => apiFetch<any>('/threats/analyze', { method: 'POST', body: JSON.stringify({ aws_account_id }) }),
};

export const remediationApi = {
  execute: (payload: any) => apiFetch<any>('/remediation/execute', { method: 'POST', body: JSON.stringify(payload) }),
};

export const complianceApi = {
  getSummary: () => apiFetch<any>('/compliance'),
};

export const auditApi = {
  getLogs: () => apiFetch<any[]>('/audit/logs'),
  getTeam: () => apiFetch<any[]>('/audit/team'),
};

export const reportsApi = {
  download: async (fmt: 'json' | 'pdf') => {
    alert(`[Demo Mode] Successfully generated and downloaded vaultmesh-security-report.${fmt}`);
  },
};

export interface RemediationResponse {
  status: string;
  finding_id: number;
  rule: string;
  resource: string;
  mode: string;
  action_taken: string;
  remediated_at: string;
}

