import type {
  AWSAccount,
  ConnectionValidation,
  DashboardOverview,
  Finding,
  FindingStatus,
  ScanJob,
  TokenResponse,
  User,
} from '../types';

const API_BASE_URL = 'http://127.0.0.1:8000/api/v1';
const TOKEN_STORAGE_KEY = 'vaultmesh_access_token';

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
  const token = getStoredToken();
  const headers = new Headers(options.headers || {});
  headers.set('Content-Type', 'application/json');

  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let message = `API Error (${response.status})`;
    try {
      const errorBody = await response.json();
      if (typeof errorBody.detail === 'string') {
        message = errorBody.detail;
      } else if (Array.isArray(errorBody.detail) && errorBody.detail[0]?.msg) {
        message = errorBody.detail[0].msg;
      }
    } catch {
      // keep fallback
    }
    throw new Error(message);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

export const authApi = {
  register: (payload: {
    email: string;
    full_name: string;
    password: string;
    organization_name: string;
  }) =>
    apiFetch<User>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  login: (payload: { email: string; password: string }) =>
    apiFetch<TokenResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  me: () => apiFetch<User>('/auth/me'),
};

export const dashboardApi = {
  getOverview: () => apiFetch<DashboardOverview>('/dashboard/overview'),
};

export const accountsApi = {
  list: () => apiFetch<AWSAccount[]>('/accounts'),
  getOnboardingTemplate: () =>
    apiFetch<{
      suggested_role_name: string;
      generated_external_id: string;
      trust_policy: object;
      permissions_policy: object;
    }>('/accounts/onboarding-template'),
  create: (payload: {
    aws_account_id: string;
    alias: string;
    is_mock: boolean;
    role_arn?: string;
    external_id?: string;
    default_region: string;
    regions: string[];
  }) =>
    apiFetch<AWSAccount>('/accounts', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  validate: (id: number) =>
    apiFetch<ConnectionValidation>(`/accounts/${id}/validate`, { method: 'POST' }),
  remove: (id: number) =>
    apiFetch<void>(`/accounts/${id}`, { method: 'DELETE' }),
};

export const scansApi = {
  list: () => apiFetch<ScanJob[]>('/scans'),
  run: (aws_account_id: number) =>
    apiFetch<ScanJob>('/scans/run', {
      method: 'POST',
      body: JSON.stringify({ aws_account_id }),
    }),
};

export const findingsApi = {
  list: (params?: { severity?: string; status?: string; service?: string; search?: string }) => {
    const qs = new URLSearchParams();
    if (params?.severity) qs.set('severity', params.severity);
    if (params?.status) qs.set('status', params.status);
    if (params?.service) qs.set('service', params.service);
    if (params?.search) qs.set('search', params.search);
    const query = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<Finding[]>(`/findings${query}`);
  },
  update: (id: number, payload: { status?: FindingStatus; investigation_notes?: string }) =>
    apiFetch<Finding>(`/findings/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),
};

export const analyzersApi = {
  getIam: () => apiFetch<import('../types').IAMAnalysisResponse>('/analyzers/iam'),
  getNetwork: () => apiFetch<import('../types').NetworkAnalysisResponse>('/analyzers/network'),
};
