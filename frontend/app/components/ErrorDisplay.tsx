"use client";

import React from "react";

interface ErrorDisplayProps {
  title?: string;
  message: string;
  onRetry?: () => void;
  variant?: "error" | "warning" | "info";
}

export function ErrorDisplay({
  title = "Something went wrong",
  message,
  onRetry,
  variant = "error",
}: ErrorDisplayProps) {
  const variantStyles = {
    error: {
      borderColor: "var(--danger)",
      iconColor: "var(--danger)",
      icon: "⚠️",
    },
    warning: {
      borderColor: "var(--warning)",
      iconColor: "var(--warning)",
      icon: "⚡",
    },
    info: {
      borderColor: "var(--accent)",
      iconColor: "var(--accent)",
      icon: "ℹ️",
    },
  };

  const style = variantStyles[variant];

  return (
    <div className="error-card" style={{ borderColor: style.borderColor }}>
      <div className="error-icon">{style.icon}</div>
      <div className="error-content">
        <h4 className="error-title">{title}</h4>
        <p className="error-message">{message}</p>
        {onRetry && (
          <button className="button secondary" onClick={onRetry}>
            Try again
          </button>
        )}
      </div>
      <style jsx>{`
        .error-card {
          display: flex;
          gap: 16px;
          padding: 20px;
          background: var(--card);
          border: 2px solid;
          border-radius: 12px;
          align-items: flex-start;
        }
        .error-icon {
          font-size: 24px;
          flex-shrink: 0;
        }
        .error-content {
          flex: 1;
        }
        .error-title {
          margin: 0 0 8px;
          font-size: 16px;
          color: var(--ink);
        }
        .error-message {
          margin: 0 0 12px;
          font-size: 14px;
          color: var(--muted);
          line-height: 1.5;
        }
      `}</style>
    </div>
  );
}

interface EmptyStateProps {
  icon?: string;
  title: string;
  description: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export function EmptyState({ icon = "📭", title, description, action }: EmptyStateProps) {
  return (
    <div className="empty-state">
      <div className="empty-icon">{icon}</div>
      <h3 className="empty-title">{title}</h3>
      <p className="empty-description">{description}</p>
      {action && (
        <button className="button" onClick={action.onClick}>
          {action.label}
        </button>
      )}
      <style jsx>{`
        .empty-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 48px 24px;
          text-align: center;
        }
        .empty-icon {
          font-size: 48px;
          margin-bottom: 16px;
        }
        .empty-title {
          margin: 0 0 8px;
          font-size: 18px;
          color: var(--ink);
        }
        .empty-description {
          margin: 0 0 20px;
          font-size: 14px;
          color: var(--muted);
          max-width: 400px;
        }
      `}</style>
    </div>
  );
}
