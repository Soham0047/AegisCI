import React from "react";
import Link from "next/link";

import "./globals.css";

export const metadata = {
  title: "SecureDev Guardian",
  description: "Baseline dashboard",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <div className="topbar">
            <div className="brand">
              <h1>SecureDev Guardian</h1>
              <span>Reports, patches, and gateway policy telemetry</span>
            </div>
            <nav className="nav">
              <Link href="/">Overview</Link>
              <Link href="/reports">Reports</Link>
              <Link href="/patches">Patches</Link>
              <Link href="/gateway">Gateway</Link>
            </nav>
          </div>
          <main>{children}</main>
        </div>
      </body>
    </html>
  );
}
