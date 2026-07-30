import React from "react";
import { AlertIcon } from "../icons";

// ErrorBanner is the one shape a recoverable failure takes: the shake-
// animated danger block a form drops in beside its fields. Where the same
// message can fail twice running, give the element a `key` that changes per
// attempt — remounting is what replays an animation that would otherwise sit
// there unnoticed. `children` ride inside the message, for the rare failure
// that can offer a way out of itself.
//
// `tone="warning"` is the same block used to warn rather than to report: it
// is standing advice, not the answer to a click, so it neither shakes nor
// announces itself as an alert.
export function ErrorBanner({
  message,
  className,
  children,
  tone = "danger",
}: {
  message: string;
  className?: string;
  children?: React.ReactNode;
  tone?: "danger" | "warning";
}) {
  return (
    <div
      className={`flex items-start gap-2 text-sm rounded-md border px-3 py-2.5 leading-relaxed${
        tone === "danger" ? " animate-shake" : ""
      }${className ? ` ${className}` : ""}`}
      role={tone === "danger" ? "alert" : "note"}
      style={{
        background: `var(--${tone}-subtle)`,
        borderColor: `var(--${tone})`,
        color: `var(--${tone}-fg)`,
      }}
    >
      <AlertIcon className="h-4 w-4 mt-0.5 flex-shrink-0" />
      <span>
        {message}
        {children}
      </span>
    </div>
  );
}
