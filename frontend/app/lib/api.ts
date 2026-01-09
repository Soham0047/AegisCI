/**
 * API Client for SecureDev Guardian
 * Provides type-safe API calls with error handling
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  request_id?: string;
}

export class ApiException extends Error {
  public readonly statusCode: number;
  public readonly error: ApiError;

  constructor(statusCode: number, error: ApiError) {
    super(error.message);
    this.name = "ApiException";
    this.statusCode = statusCode;
    this.error = error;
  }
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let error: ApiError;
    try {
      const data = await response.json();
      error = data.error || { code: "UNKNOWN_ERROR", message: response.statusText };
    } catch {
      error = { code: "PARSE_ERROR", message: response.statusText };
    }
    throw new ApiException(response.status, error);
  }
  return response.json();
}

// =============================================================================
// Types
// =============================================================================

export interface Report {
  id: number;
  repo: string;
  pr_number: number;
  commit_sha: string;
  created_at: string;
  findings: {
    bandit: number;
    semgrep: number;
    total: number;
  };
}

export interface ReportDetail extends Report {
  findings_list?: Finding[];
}

export interface Finding {
  id: string;
  rule_id: string;
  severity: string;
  message: string;
  file: string;
  line: number;
  tool: string;
}

export interface PatchJob {
  job_id: string;
  repo: string;
  commit_sha: string;
  status: string;
  created_at: string;
  completed_at?: string;
  findings_count: number;
  patches_generated: number;
}

export interface PatchDetail extends PatchJob {
  findings: Finding[];
  patches: Patch[];
  diff?: string;
}

export interface Patch {
  finding_id: string;
  status: string;
  diff: string;
  validated: boolean;
}

export interface GatewayEvent {
  id: string;
  timestamp: string;
  tool: string;
  decision: string;
  reason?: string;
  caller?: string;
  correlation_id?: string;
}

export interface GatewaySummary {
  total: number;
  allowed: number;
  denied: number;
  by_tool: Record<string, number>;
}

// =============================================================================
// API Functions
// =============================================================================

export const api = {
  // Health
  async health(): Promise<{ ok: boolean; version: string; environment: string }> {
    const response = await fetch(`${API_BASE}/health`);
    return handleResponse(response);
  },

  // Reports
  async listReports(params?: { repo?: string; limit?: number }): Promise<Report[]> {
    const searchParams = new URLSearchParams();
    if (params?.repo) searchParams.set("repo", params.repo);
    if (params?.limit) searchParams.set("limit", String(params.limit));

    const url = `${API_BASE}/api/v1/dashboard/reports?${searchParams}`;
    const response = await fetch(url);
    return handleResponse(response);
  },

  async getReport(reportId: string): Promise<ReportDetail> {
    const response = await fetch(`${API_BASE}/api/v1/dashboard/reports/${reportId}`);
    return handleResponse(response);
  },

  // Patches
  async listPatches(params?: {
    repo?: string;
    status?: string;
    limit?: number;
  }): Promise<PatchJob[]> {
    const searchParams = new URLSearchParams();
    if (params?.repo) searchParams.set("repo", params.repo);
    if (params?.status) searchParams.set("status", params.status);
    if (params?.limit) searchParams.set("limit", String(params.limit));

    const url = `${API_BASE}/api/v1/dashboard/patches?${searchParams}`;
    const response = await fetch(url);
    return handleResponse(response);
  },

  async getPatch(jobId: string): Promise<PatchDetail> {
    const response = await fetch(`${API_BASE}/api/v1/dashboard/patches/${jobId}`);
    return handleResponse(response);
  },

  // Gateway
  async listGatewayEvents(params?: { decision?: string; limit?: number }): Promise<GatewayEvent[]> {
    const searchParams = new URLSearchParams();
    if (params?.decision) searchParams.set("decision", params.decision);
    if (params?.limit) searchParams.set("limit", String(params.limit));

    const url = `${API_BASE}/api/v1/dashboard/gateway/events?${searchParams}`;
    const response = await fetch(url);
    return handleResponse(response);
  },

  async getGatewaySummary(): Promise<GatewaySummary> {
    const response = await fetch(`${API_BASE}/api/v1/dashboard/gateway/summary`);
    return handleResponse(response);
  },
};

export default api;
