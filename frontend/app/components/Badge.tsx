"use client";

import React from "react";

type BadgeVariant = "default" | "success" | "warning" | "danger" | "info";

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
}

export function Badge({ children, variant = "default" }: BadgeProps) {
  return (
    <span className={`badge badge-${variant}`}>
      {children}
      <style jsx>{`
        .badge {
          display: inline-flex;
          align-items: center;
          padding: 4px 10px;
          border-radius: 999px;
          font-size: 12px;
          font-weight: 600;
        }
        .badge-default {
          background: var(--bg-accent);
          color: var(--muted);
        }
        .badge-success {
          background: #d1fae5;
          color: #047857;
        }
        .badge-warning {
          background: #fef3c7;
          color: #b45309;
        }
        .badge-danger {
          background: #fee2e2;
          color: #b91c1c;
        }
        .badge-info {
          background: var(--accent-soft);
          color: var(--accent);
        }
      `}</style>
    </span>
  );
}

interface SeverityBadgeProps {
  severity: string;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const severityLower = severity.toLowerCase();
  let variant: BadgeVariant = "default";

  if (severityLower === "high" || severityLower === "critical" || severityLower === "error") {
    variant = "danger";
  } else if (severityLower === "medium" || severityLower === "warning") {
    variant = "warning";
  } else if (severityLower === "low" || severityLower === "info") {
    variant = "info";
  }

  return <Badge variant={variant}>{severity.toUpperCase()}</Badge>;
}

interface StatusBadgeProps {
  status: string;
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const statusLower = status.toLowerCase();
  let variant: BadgeVariant = "default";

  if (
    statusLower === "success" ||
    statusLower === "passed" ||
    statusLower === "allow" ||
    statusLower === "allowed"
  ) {
    variant = "success";
  } else if (
    statusLower === "failed" ||
    statusLower === "error" ||
    statusLower === "deny" ||
    statusLower === "denied"
  ) {
    variant = "danger";
  } else if (
    statusLower === "pending" ||
    statusLower === "running" ||
    statusLower === "in_progress"
  ) {
    variant = "warning";
  }

  return <Badge variant={variant}>{status}</Badge>;
}
