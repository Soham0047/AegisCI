/**
 * API Client utilities for SecureDev Guardian
 */

export type ApiResult<T> = {
  ok: boolean;
  data: T | null;
  error: string | null;
  statusCode?: number;
};

export const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

export function buildQuery(params: Record<string, string | number | undefined | null>) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    query.set(key, String(value));
  }
  const suffix = query.toString();
  return suffix ? `?${suffix}` : "";
}

export async function fetchJson<T>(path: string): Promise<ApiResult<T>> {
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      cache: "no-store",
      headers: {
        Accept: "application/json",
      },
    });
    if (!res.ok) {
      // Try to parse error response
      let errorMessage = `HTTP ${res.status}`;
      try {
        const errorData = await res.json();
        if (errorData.error?.message) {
          errorMessage = errorData.error.message;
        } else if (errorData.detail) {
          errorMessage = errorData.detail;
        }
      } catch {
        // Use status text if can't parse
        errorMessage = res.statusText || errorMessage;
      }
      return { ok: false, data: null, error: errorMessage, statusCode: res.status };
    }
    const data = (await res.json()) as T;
    return { ok: true, data, error: null, statusCode: res.status };
  } catch (err) {
    return {
      ok: false,
      data: null,
      error: err instanceof Error ? err.message : "Network error - is the API running?",
    };
  }
}

export async function postJson<T>(
  path: string,
  body: Record<string, unknown>,
): Promise<ApiResult<T>> {
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      let errorMessage = `HTTP ${res.status}`;
      try {
        const errorData = await res.json();
        if (errorData.error?.message) {
          errorMessage = errorData.error.message;
        } else if (errorData.detail) {
          errorMessage = errorData.detail;
        }
      } catch {
        errorMessage = res.statusText || errorMessage;
      }
      return { ok: false, data: null, error: errorMessage, statusCode: res.status };
    }
    const data = (await res.json()) as T;
    return { ok: true, data, error: null, statusCode: res.status };
  } catch (err) {
    return {
      ok: false,
      data: null,
      error: err instanceof Error ? err.message : "Network error - is the API running?",
    };
  }
}

/**
 * Health check utility
 */
export async function checkApiHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/health`, { cache: "no-store" });
    return res.ok;
  } catch {
    return false;
  }
}
