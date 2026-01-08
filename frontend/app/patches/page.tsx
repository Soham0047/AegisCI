"use client";

import React, { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { API_BASE, buildQuery, fetchJson } from "../../lib/api";
import { formatDate, formatPercent } from "../../lib/format";

type PatchRow = {
  job_id: string;
  repo: string;
  commit: string;
  status: string;
  validated_count: number;
  rejected_count: number;
  avg_validation_time: number | null;
  success_rate: number;
  created_at: string;
};

export default function PatchesPage() {
  return (
    <Suspense fallback={<div className="card">Loading patches...</div>}>
      <PatchesPageContent />
    </Suspense>
  );
}

function PatchesPageContent() {
  const [rows, setRows] = useState<PatchRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const searchParams = useSearchParams();
  const defaultFrom = useMemo(
    () => new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10),
    [],
  );

  const repo = searchParams.get("repo") ?? "";
  const commit = searchParams.get("commit") ?? "";
  const status = searchParams.get("status") ?? "";
  const from = searchParams.get("from") ?? defaultFrom;
  const to = searchParams.get("to") ?? "";

  useEffect(() => {
    const query = buildQuery({ repo, commit, status, from, to });
    fetchJson<PatchRow[]>(`/api/v1/dashboard/patches${query}`).then((result) => {
      setLoading(false);
      if (!result.ok || !result.data) {
        setError(result.error || "Failed to load patches");
        return;
      }
      setRows(result.data);
    });
  }, [repo, commit, status, from, to]);

  return (
    <div className="grid">
      <div className="card">
        <h3>Patches</h3>
        <p style={{ color: "var(--muted)", marginTop: 4 }}>
          Source: {API_BASE}/api/v1/dashboard/patches
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
            Status
            <input name="status" defaultValue={status} placeholder="completed" />
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
          <strong>Demo mode:</strong> {error}. Ensure the backend is running and
          reachable.
          <div style={{ marginTop: 8 }}>
            <button className="button secondary" type="button" onClick={() => window.location.reload()}>
              Retry
            </button>
          </div>
        </div>
      )}

      <div className="card">
        {loading ? (
          <p>Loading patch attempts...</p>
        ) : rows.length === 0 ? (
          <p>No patch attempts found for the current filters.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Job</th>
                <th>Repo</th>
                <th>Commit</th>
                <th>Status</th>
                <th>Validated</th>
                <th>Rejected</th>
                <th>Success</th>
                <th>Avg time</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.job_id}>
                  <td>
                    <Link href={`/patches/${row.job_id}`}>{row.job_id}</Link>
                  </td>
                  <td>{row.repo}</td>
                  <td>{row.commit?.slice(0, 8) || "unknown"}</td>
                  <td>{row.status}</td>
                  <td>{row.validated_count}</td>
                  <td>{row.rejected_count}</td>
                  <td>{formatPercent(row.success_rate)}</td>
                  <td>
                    {row.avg_validation_time ? `${row.avg_validation_time.toFixed(1)}s` : "n/a"}
                  </td>
                  <td>{formatDate(row.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
