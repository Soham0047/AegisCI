"use client";

import React, { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { API_BASE, buildQuery, fetchJson } from "../../lib/api";
import { formatDate } from "../../lib/format";

type ReportRow = {
  report_id: string;
  job_id: string;
  repo: string;
  commit: string;
  created_at: string;
  findings_count: number;
  high_critical: number;
  severity_counts?: Record<string, number>;
};

const severities = ["", "info", "low", "medium", "high", "critical"] as const;

export default function ReportsPage() {
  return (
    <Suspense fallback={<div className="card">Loading reports...</div>}>
      <ReportsPageContent />
    </Suspense>
  );
}

function ReportsPageContent() {
  const [rows, setRows] = useState<ReportRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const searchParams = useSearchParams();
  const defaultFrom = useMemo(
    () => new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10),
    [],
  );

  const repo = searchParams.get("repo") ?? "";
  const commit = searchParams.get("commit") ?? "";
  const severity = searchParams.get("severity") ?? "";
  const from = searchParams.get("from") ?? defaultFrom;
  const to = searchParams.get("to") ?? "";

  useEffect(() => {
    const query = buildQuery({ repo, commit, severity, from, to });
    fetchJson<ReportRow[]>(`/api/v1/dashboard/reports${query}`).then((result) => {
      setLoading(false);
      if (!result.ok || !result.data) {
        setError(result.error || "Failed to load reports");
        return;
      }
      setRows(result.data);
    });
  }, [repo, commit, severity, from, to]);

  return (
    <div className="grid">
      <div className="card">
        <h3>Reports</h3>
        <p style={{ color: "var(--muted)", marginTop: 4 }}>
          Source: {API_BASE}/api/v1/dashboard/reports
        </p>
        <form className="filters" method="get">
          <label>
            Repo
            <input name="repo" defaultValue={repo} placeholder="org/repo" />
          </label>
          <label>
            Commit or branch
            <input name="commit" defaultValue={commit} placeholder="sha or branch" />
          </label>
          <label>
            Severity
            <select name="severity" defaultValue={severity}>
              {severities.map((value) => (
                <option key={value} value={value}>
                  {value ? value : "any"}
                </option>
              ))}
            </select>
          </label>
          <label>
            From
            <input type="date" name="from" defaultValue={from} />
          </label>
          <label>
            To
            <input type="date" name="to" defaultValue={to} />
          </label>
          <label>
            &nbsp;
            <button className="button" type="submit">
              Apply filters
            </button>
          </label>
        </form>
      </div>

      {error && (
        <div className="error">
          <strong>Demo mode:</strong> {error}. Ensure the backend is running and reachable.
          <div style={{ marginTop: 8 }}>
            <button
              className="button secondary"
              type="button"
              onClick={() => window.location.reload()}
            >
              Retry
            </button>
          </div>
        </div>
      )}

      <div className="card">
        {loading ? (
          <p>Loading reports...</p>
        ) : rows.length === 0 ? (
          <p>No reports found for the current filters.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Report</th>
                <th>Repo</th>
                <th>Commit</th>
                <th>Created</th>
                <th>Findings</th>
                <th>High/Critical</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.report_id}>
                  <td>
                    <Link href={`/reports/${row.report_id}`}>{row.report_id}</Link>
                  </td>
                  <td>{row.repo}</td>
                  <td>{row.commit?.slice(0, 8) || "unknown"}</td>
                  <td>{formatDate(row.created_at)}</td>
                  <td>{row.findings_count}</td>
                  <td>
                    <span className="badge high">{row.high_critical}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
