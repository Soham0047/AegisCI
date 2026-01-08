"use client";

import React, { useEffect, useState } from "react";
import { useParams } from "next/navigation";

import { fetchJson } from "../../../lib/api";

type PatchDetail = {
  job_id: string;
  repo: string;
  commit: string;
  status: string;
  summary: {
    total: number;
    validated: number;
    rejected: number;
    patched: number;
    avg_validation_time: number | null;
  };
  findings: Array<{
    finding_id: string;
    rule_id: string;
    filepath: string;
    start_line: number;
    end_line: number;
    status: string;
    reason: string | null;
    source: string | null;
  }>;
  diff: string;
  run_id: string | null;
};

export default function PatchDetailPage() {
  const params = useParams<{ jobId: string }>();
  const jobId = params?.jobId;
  const [detail, setDetail] = useState<PatchDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!jobId) return;
    fetchJson<PatchDetail>(`/api/v1/dashboard/patches/${jobId}`).then((result) => {
      setLoading(false);
      if (!result.ok || !result.data) {
        setError(result.error || "Failed to load patch detail");
        return;
      }
      setDetail(result.data);
    });
  }, [jobId]);

  if (loading) {
    return <div className="card">Loading patch detail...</div>;
  }

  if (error || !detail) {
    return (
      <div className="error">
        {error || "Patch job not found"}
        <div style={{ marginTop: 8 }}>
          <button className="button secondary" type="button" onClick={() => window.location.reload()}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="grid">
      <div className="card">
        <h3>Patch job {detail.job_id}</h3>
        <p style={{ color: "var(--muted)", marginTop: 4 }}>
          {detail.repo} • {detail.commit?.slice(0, 8) || "unknown"} • status{" "}
          {detail.status}
        </p>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 12 }}>
          <span className="badge">total: {detail.summary.total}</span>
          <span className="badge low">validated: {detail.summary.validated}</span>
          <span className="badge high">rejected: {detail.summary.rejected}</span>
          {detail.summary.avg_validation_time ? (
            <span className="badge">avg {detail.summary.avg_validation_time.toFixed(1)}s</span>
          ) : null}
        </div>
      </div>

      <div className="card">
        <h3>Findings</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Finding</th>
              <th>Rule</th>
              <th>Location</th>
              <th>Status</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {detail.findings.map((finding) => (
              <tr key={finding.finding_id}>
                <td>{finding.finding_id}</td>
                <td>{finding.rule_id}</td>
                <td>
                  {finding.filepath}:{finding.start_line}-{finding.end_line}
                </td>
                <td>{finding.status}</td>
                <td>{finding.source || "unknown"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <details className="card">
        <summary>Validated patch diff</summary>
        {detail.diff ? <pre>{detail.diff}</pre> : <p>No diff available.</p>}
      </details>
    </div>
  );
}
