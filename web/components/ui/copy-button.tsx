import React, { useEffect, useRef, useState } from "react";
import { CheckIcon, CopyIcon } from "../icons";

// useCopy is the single clipboard path in the app: one place that touches
// navigator.clipboard, one confirmation window. Callers that render a secret
// use it to make the value itself clickable — copying is the common action,
// and revealing a password on screen just to select it is the worse habit to
// design for.
export function useCopy(): { copied: boolean; copy: (value: string | (() => string)) => Promise<void> } {
  const [copied, setCopied] = useState(false);
  const timer = useRef<number>(0);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const copy = async (value: string | (() => string)) => {
    // Resolved lazily so a decrypted secret is only touched at click time.
    const text = typeof value === "function" ? value() : value;
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(false), 1400);
    } catch {
      // Clipboard denied: nothing sensible to do silently.
    }
  };

  return { copied, copy };
}

// CopyButton writes a value to the clipboard with a brief confirmation
// flash.
export function CopyButton({
  value,
  label,
  className,
}: {
  value: string | (() => string);
  label?: string;
  className?: string;
}) {
  const { copied, copy } = useCopy();

  return (
    <button
      type="button"
      onClick={() => copy(value)}
      aria-label={label ?? "Copy"}
      title={label ?? "Copy"}
      className={
        className ??
        "p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
      }
    >
      {copied ? <CheckIcon className="h-4 w-4 text-success" /> : <CopyIcon className="h-4 w-4" />}
    </button>
  );
}
