import React from "react";
import { DERIVATION_STAGES, type DerivationStage } from "../../lib/crypto";

// DerivationProgress is what the user watches while their keys are derived.
//
// The wait is real and deliberate — Argon2id over PBKDF2 costs roughly a
// second on a desktop and several on a phone, because that is the cost an
// attacker also has to pay per guess. A password manager that appears to hang
// for three seconds on the unlock screen reads as broken, and the honest fix
// is not to make the KDF faster but to say what it is doing.
//
// The bar is stage-driven, not time-driven: it advances when the derivation
// actually reaches the next step, and eases forward within a step so it never
// looks stalled. Two rules keep it truthful — it never reaches 100% until the
// work is genuinely finished, and the easing decelerates rather than
// completing on a guessed schedule, so a slow device shows a bar still moving
// rather than a full bar and nothing happening.

// Weights are rough shares of total wall-clock at the default costs, which is
// all the bar needs to move at a believable rate. "hardening" dominates.
const STAGE_COPY: Record<DerivationStage, { label: string; weight: number }> = {
  preparing: { label: "Getting your account settings", weight: 0.02 },
  stretching: { label: "Working on your Master Password", weight: 0.38 },
  hardening: { label: "Adding the slow part attackers hate", weight: 0.55 },
  finishing: { label: "Building your vault keys", weight: 0.05 },
};

function stageStart(stage: DerivationStage): number {
  let total = 0;
  for (const s of DERIVATION_STAGES) {
    if (s === stage) break;
    total += STAGE_COPY[s].weight;
  }
  return total;
}

export function DerivationProgress({ stage, className }: { stage: DerivationStage | null; className?: string }) {
  const [eased, setEased] = React.useState(0);

  React.useEffect(() => {
    if (!stage) {
      setEased(0);
      return;
    }
    const start = stageStart(stage);
    const span = STAGE_COPY[stage].weight;
    const startedAt = performance.now();
    let frame = 0;

    const tick = () => {
      // 1 - e^-t approaches the end of the stage's span without arriving, so
      // an over-running stage keeps creeping instead of sitting at a number
      // that claims the step is done.
      const elapsed = (performance.now() - startedAt) / 1000;
      setEased(start + span * (1 - Math.exp(-elapsed * 1.6)));
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [stage]);

  if (!stage) return null;
  const percent = Math.min(99, Math.round(eased * 100));

  return (
    <div
      className={`flex flex-col gap-2${className ? ` ${className}` : ""}`}
      role="status"
      aria-live="polite"
      aria-label={STAGE_COPY[stage].label}
    >
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-sm" style={{ color: "var(--foreground)" }}>
          {STAGE_COPY[stage].label}…
        </span>
        <span className="text-xs tabular-nums" style={{ color: "var(--muted-foreground)" }}>
          {percent}%
        </span>
      </div>

      <div
        className="h-1.5 w-full rounded-full overflow-hidden"
        style={{ background: "var(--muted)" }}
        role="progressbar"
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div
          className="h-full rounded-full"
          style={{
            width: `${percent}%`,
            background: "var(--gradient-brand)",
            transition: "width 120ms linear",
          }}
        />
      </div>

      <p className="text-xs leading-relaxed" style={{ color: "var(--muted-foreground)" }}>
        This runs on your device and is slow on purpose — it is the same cost an attacker would pay for every guess.
      </p>
    </div>
  );
}
