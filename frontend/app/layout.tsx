import React from "react";

export const metadata = {
  title: "SecureDev Guardian",
  description: "Baseline dashboard",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "ui-sans-serif, system-ui", margin: 0 }}>
        <div style={{ padding: 24, borderBottom: "1px solid #eee" }}>
          <h1 style={{ margin: 0, fontSize: 20 }}>SecureDev Guardian</h1>
          <p style={{ margin: "6px 0 0", color: "#666" }}>Baseline dashboard</p>
        </div>
        <div style={{ padding: 24 }}>{children}</div>
      </body>
    </html>
  );
}
