import React from "react";

// The one way the app says "working on it". The word is the product's own —
// unsealing, never loading — and the line stays a single quiet mono row
// wherever it lands: a dialog list, a detail pane, or a StatusPanel's body.
export function Loading({ label = "unsealing…", className }: { label?: string; className?: string }) {
  return <p className={`text-sm text-muted-foreground font-mono py-3${className ? ` ${className}` : ""}`}>{label}</p>;
}
