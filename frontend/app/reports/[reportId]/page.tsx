"use client";

import React, { Suspense, useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "next/navigation";

import { buildQuery, fetchJson } from "../../../lib/api";
import { formatDate, truncate } from "../../../lib/format";

type ReportDetail = {
  report_id: string;
  repo: string;
  commit: string;
  created_at: string;
  summary: Record<string, number>;
  files: Array<{
    filepath: string;
    severity_counts: Record<string, number>;
    category_counts: Record<string, number>;
    rule_counts: Record<string, number>;
    findings: Array<{
      finding_id: string;
      severity: string;
      source: string;
      rule_id: string;
      category: string;
      start_line: number;
      end_line: number;
      confidence: number;
      message: string | null;
      excerpt: string;
    }>;
  }>;
};

export default function ReportDetailPage() {
  return (
    <Suspense fallback={<div className="card">Loading report...</div>}>
      <ReportDetailContent />
    </Suspense>
  );
}

function ReportDetailContent() {
  const params = useParams<{ reportId: string }>();
  const reportId = params?.reportId;
  const [detail, setDetail] = useState<ReportDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const searchParams = useSearchParams();
  const query = useMemo(() => {
    const severity = searchParams.get("severity") ?? "";
    return buildQuery({ severity });
  }, [searchParams]);

  useEffect(() => {
    if (!reportId) return;
    fetchJson<ReportDetail>(`/api/v1/dashboard/reports/${reportId}${query}`).then((result) => {
      setLoading(false);
      if (!result.ok || !result.data) {
        setError(result.error || "Failed to load report");
        return;
      }
      setDetail(result.data);
    });
  }, [reportId, query]);

  if (loading) {
    return <div className="card">Loading report...</div>;
  }

  if (error || !detail) {
    return (
      <div className="error">
        {error || "Report not found"}
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
    );
  }

  return (
    <div className="grid">
      <div className="card">
        <h3>Report {detail.report_id}</h3>
        <p style={{ color: "var(--muted)", marginTop: 4 }}>
          {detail.repo} • {detail.commit?.slice(0, 8) || "unknown"} •{" "}
          {formatDate(detail.created_at)}
        </p>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 12 }}>
          {Object.entries(detail.summary).map(([key, value]) => (
            <span key={key} className={`badge ${key}`}>
              {key}: {value}
            </span>
          ))}
        </div>
      </div>

      {detail.files.map((file) => (
        <details key={file.filepath} className="card">
          <summary>
            {file.filepath} • {file.findings.length} findings
          </summary>
          <div style={{ marginTop: 12 }}>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {Object.entries(file.severity_counts).map(([key, value]) => (
                <span key={key} className={`badge ${key}`}>
                  {key}: {value}
                </span>
              ))}
            </div>
            <div style={{ marginTop: 10, color: "var(--muted)", fontSize: 12 }}>
              Categories:{" "}
              {Object.entries(file.category_counts)
                .map(([key, value]) => `${key} (${value})`)
                .join(", ")}
            </div>
            <div style={{ marginTop: 4, color: "var(--muted)", fontSize: 12 }}>
              Rules:{" "}
              {Object.entries(file.rule_counts)
                .map(([key, value]) => `${key} (${value})`)
                .join(", ")}
            </div>

            <div className="grid" style={{ marginTop: 12 }}>
              {file.findings.map((finding) => (
                <div key={finding.finding_id} className="card">
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <strong>
                      [{finding.severity}] {finding.rule_id}
                    </strong>
                    <span className={`badge ${finding.severity}`}>{finding.source}</span>
                  </div>
                  <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 6 }}>
                    {finding.category} • lines {finding.start_line}-{finding.end_line} • confidence{" "}
                    {finding.confidence ?? 0}
                  </div>
                  {finding.message && (
                    <div style={{ marginTop: 8 }}>{truncate(finding.message, 200)}</div>
                  )}
                  {finding.excerpt && (
                    <pre style={{ marginTop: 8 }}>{truncate(finding.excerpt, 1200)}</pre>
                  )}
                </div>
              ))}
            </div>
          </div>
        </details>
      ))}
    </div>
  );
}
