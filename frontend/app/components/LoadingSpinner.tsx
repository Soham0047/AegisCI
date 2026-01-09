"use client";

import React from "react";

interface LoadingSpinnerProps {
  size?: "sm" | "md" | "lg";
  message?: string;
}

export function LoadingSpinner({ size = "md", message }: LoadingSpinnerProps) {
  const sizeClasses = {
    sm: "w-4 h-4",
    md: "w-8 h-8",
    lg: "w-12 h-12",
  };

  return (
    <div className="loading-container">
      <div className={`spinner ${sizeClasses[size]}`} />
      {message && <p className="loading-message">{message}</p>}
      <style jsx>{`
        .loading-container {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 12px;
          padding: 24px;
        }
        .spinner {
          border: 3px solid var(--border);
          border-top-color: var(--accent);
          border-radius: 50%;
          animation: spin 0.8s linear infinite;
        }
        .w-4 {
          width: 16px;
          height: 16px;
        }
        .w-8 {
          width: 32px;
          height: 32px;
        }
        .w-12 {
          width: 48px;
          height: 48px;
        }
        .loading-message {
          color: var(--muted);
          font-size: 14px;
          margin: 0;
        }
        @keyframes spin {
          to {
            transform: rotate(360deg);
          }
        }
      `}</style>
    </div>
  );
}

interface LoadingCardProps {
  message?: string;
}

export function LoadingCard({ message = "Loading..." }: LoadingCardProps) {
  return (
    <div className="card">
      <LoadingSpinner message={message} />
    </div>
  );
}
