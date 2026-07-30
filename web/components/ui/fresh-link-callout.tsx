import React from "react";
import { CopyButton } from "./copy-button";

// A link that exists exactly once. Its key rides in the URL fragment, so this
// screen is the only place the whole thing will ever be assembled — share
// links and vault invites both have to say that, and say it identically.
export function FreshLinkCallout({
  label,
  value,
  copyLabel,
}: {
  label: string;
  value: string;
  copyLabel: string;
}) {
  return (
    <div className="animate-pop mt-4 rounded-lg border border-accent-border bg-accent-subtle p-3">
      <p className="field-label field-label-accent mb-2">{label}</p>
      <div className="flex items-center gap-2">
        <code className="font-mono text-xs text-foreground break-all flex-1 select-all">{value}</code>
        <CopyButton value={value} label={copyLabel} />
      </div>
    </div>
  );
}
