import React from "react";

type Report = {
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
};

async function fetchReports(): Promise<Report[]> {
  const res = await fetch("http://localhost:8000/api/v1/reports?limit=20", { cache: "no-store" });
  if (!res.ok) return [];
  return res.json();
}

export default async function Page() {
  const reports = await fetchReports();

  return (
    <div style={{ maxWidth: 1000 }}>
      <h2 style={{ marginTop: 0 }}>Recent Reports</h2>
      {reports.length === 0 ? (
        <p style={{ color: "#666" }}>
          No reports yet. POST one to <code>/api/v1/reports</code> or wire CI to upload.
        </p>
      ) : (
        <div style={{ display: "grid", gap: 12 }}>
          {reports.map((r) => (
            <div key={r.id} style={{ border: "1px solid #eee", borderRadius: 10, padding: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                <div>
                  <div style={{ fontWeight: 600 }}>
                    {r.repo} • PR #{r.pr_number}
                  </div>
                  <div style={{ color: "#666", fontSize: 12 }}>
                    {new Date(r.created_at).toLocaleString()} • {r.commit_sha.slice(0, 8)}
                  </div>
                </div>
                <div style={{ textAlign: "right", fontSize: 12, color: "#333" }}>
                  <div>
                    Bandit: <b>{r.findings.bandit ?? 0}</b>
                  </div>
                  <div>
                    Semgrep: <b>{r.findings.semgrep ?? 0}</b>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <hr style={{ margin: "24px 0", border: "none", borderTop: "1px solid #eee" }} />
      <h3>Next</h3>
      <ul>
        <li>
          Wire the GitHub Action to POST <code>report.json</code> into the backend.
        </li>
        <li>Add patch suggestions + test validation.</li>
        <li>Add DL risk scoring service.</li>
      </ul>
    </div>
  );
}
