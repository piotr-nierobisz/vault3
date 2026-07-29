import React from "react";

// StrengthMeter: an honest, simple estimate of Master Password strength.
// Character-class-aware entropy heuristic — indicative, not oracular; the
// server never sees the password to judge it.

export function estimateStrength(password: string): { bits: number; label: string; tone: string; fraction: number } {
  if (!password) return { bits: 0, label: "", tone: "var(--border)", fraction: 0 };
  let alphabet = 0;
  if (/[a-z]/.test(password)) alphabet += 26;
  if (/[A-Z]/.test(password)) alphabet += 26;
  if (/[0-9]/.test(password)) alphabet += 10;
  if (/[^a-zA-Z0-9]/.test(password)) alphabet += 24;
  const bits = Math.round(password.length * Math.log2(Math.max(alphabet, 2)));

  if (bits < 40) return { bits, label: "Too weak", tone: "var(--danger)", fraction: 0.25 };
  if (bits < 60) return { bits, label: "Getting there", tone: "var(--warning)", fraction: 0.5 };
  if (bits < 80) return { bits, label: "Strong", tone: "var(--success)", fraction: 0.75 };
  return { bits, label: "Excellent", tone: "var(--success)", fraction: 1 };
}

export function StrengthMeter({ password }: { password: string }) {
  const { bits, label, tone, fraction } = estimateStrength(password);
  if (!password) return null;
  return (
    <div className="pt-1.5">
      <div className="h-1 rounded-full bg-muted overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{ width: `${fraction * 100}%`, background: tone }}
        />
      </div>
      <p className="text-xs text-muted-foreground mt-1">
        {label} <span className="font-mono opacity-70">~{bits} bits</span>
      </p>
    </div>
  );
}
