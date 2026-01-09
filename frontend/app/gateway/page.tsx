"use client";

import React, { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";

import { API_BASE, buildQuery, fetchJson } from "../../lib/api";
import { formatDate } from "../../lib/format";

type GatewayEvent = {
  id: string;
  timestamp: string;
  tool: string;
  decision: string;
  reason: string;
  correlation_id: string;
  metadata?: Record<string, unknown>;
};

type GatewaySummary = {
  total: number;
  blocked: number;
  top_reasons: Array<[string, number]>;
  top_tools: Array<[string, number]>;
};

const decisions = ["", "allow", "deny", "mask", "require_approval"] as const;

export default function GatewayPage() {
  return (
    <Suspense fallback={<div className="card">Loading gateway events...</div>}>
      <GatewayPageContent />
    </Suspense>
  );
}

function GatewayPageContent() {
  const [events, setEvents] = useState<GatewayEvent[]>([]);
  const [summary, setSummary] = useState<GatewaySummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const searchParams = useSearchParams();
  const defaultFrom = useMemo(
    () => new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10),
    [],
  );

  const repo = searchParams.get("repo") ?? "";
  const decision = searchParams.get("decision") ?? "";
  const from = searchParams.get("from") ?? defaultFrom;
  const to = searchParams.get("to") ?? "";

  useEffect(() => {
    const query = buildQuery({ repo, decision, from, to });
    Promise.all([
      fetchJson<GatewayEvent[]>(`/api/v1/dashboard/gateway/events${query}`),
      fetchJson<GatewaySummary>(`/api/v1/dashboard/gateway/summary${query}`),
    ]).then(([eventsRes, summaryRes]) => {
      setLoading(false);
      if (!eventsRes.ok || !eventsRes.data) {
        setError(eventsRes.error || "Failed to load gateway events");
        return;
      }
      setEvents(eventsRes.data);
      if (summaryRes.ok && summaryRes.data) {
        setSummary(summaryRes.data);
      }
    });
  }, [repo, decision, from, to]);

  return (
    <div className="grid">
      <div className="card">
        <h3>Gateway events</h3>
        <p style={{ color: "var(--muted)", marginTop: 4 }}>
          Source: {API_BASE}/api/v1/dashboard/gateway/events
        </p>
        <form className="filters" method="get">
          <label>
            Repo
            <input name="repo" defaultValue={repo} placeholder="org/repo" />
          </label>
          <label>
            Decision
            <select name="decision" defaultValue={decision}>
              {decisions.map((value) => (
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

      {summary && (
        <div className="grid grid-2">
          <div className="card">
            <h3>Blocked calls</h3>
            <p style={{ fontSize: 32, margin: 0 }}>{summary.blocked}</p>
            <p style={{ color: "var(--muted)" }}>Out of {summary.total} events</p>
          </div>
          <div className="card">
            <h3>Top reasons</h3>
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {summary.top_reasons.map(([reason, count]) => (
                <li key={reason}>
                  {reason} ({count})
                </li>
              ))}
            </ul>
          </div>
          <div className="card">
            <h3>Top tools</h3>
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {summary.top_tools.map(([tool, count]) => (
                <li key={tool}>
                  {tool} ({count})
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

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
          <p>Loading gateway events...</p>
        ) : events.length === 0 ? (
          <p>No events found for the current filters.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Tool</th>
                <th>Decision</th>
                <th>Reason</th>
                <th>Correlation</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id}>
                  <td>{formatDate(event.timestamp)}</td>
                  <td>{event.tool}</td>
                  <td>{event.decision}</td>
                  <td>{event.reason}</td>
                  <td>{event.correlation_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
