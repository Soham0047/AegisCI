import React from "react";
import Link from "next/link";

export default function Page() {
  return (
    <div className="grid grid-2">
      <div className="card">
        <h3>Reports</h3>
        <p>
          Review scan findings across repos with filters for repo, commit, severity, and timeframe.
        </p>
        <Link className="button" href="/reports">
          Open reports
        </Link>
      </div>
      <div className="card">
        <h3>Patches</h3>
        <p>
          Track patch attempts, validation outcomes, and the final diff selected by Patch Copilot.
        </p>
        <Link className="button secondary" href="/patches">
          Inspect patches
        </Link>
      </div>
      <div className="card">
        <h3>Gateway events</h3>
        <p>Audit tool-call decisions, redactions, and approval requirements.</p>
        <Link className="button" href="/gateway">
          View gateway log
        </Link>
      </div>
      <div className="card">
        <h3>Policy controls</h3>
        <p>Per-org and per-repo policy configs are available via the backend API.</p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <span className="badge">Org defaults</span>
          <span className="badge">Repo overrides</span>
          <span className="badge">Policy patches</span>
        </div>
      </div>
    </div>
  );
}
