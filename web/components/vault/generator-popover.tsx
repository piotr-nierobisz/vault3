import React, { useEffect, useState } from "react";
import { CheckIcon, RefreshIcon } from "../icons";
import { Checkbox } from "../ui/checkbox";
import { useCopy } from "../ui/copy-button";
import { CHARACTER_CLASS_ORDER, CHARACTER_CLASS_STYLE, SecretText } from "../ui/secret-text";
import {
  DEFAULT_GENERATOR,
  enabledClasses,
  entropyBits,
  generatePassword,
  type CharacterClass,
  type GeneratorOptions,
} from "../../lib/generator";

// The password generator, embedded in the item form. Regenerates on every
// option change so what you see is always what you'd insert — rendered by the
// same SecretText the rest of the app displays passwords with, so a candidate
// looks identical to the item it becomes.

// Slider: the .slider token style plus the fill percentage it can't compute
// itself, with the live value read out beside it.
function Slider({
  label,
  min,
  max,
  value,
  onChange,
}: {
  label: string;
  min: number;
  max: number;
  value: number;
  onChange: (value: number) => void;
}) {
  const id = `gen-${label.toLowerCase()}`;
  const pct = `${((value - min) / (max - min)) * 100}%`;
  return (
    <div className="flex items-center gap-3.5 text-xs text-muted-foreground">
      <label htmlFor={id} className="font-semibold tracking-widest uppercase">
        {label}
      </label>
      <input
        id={id}
        type="range"
        className="slider flex-1"
        min={min}
        max={max}
        value={value}
        onChange={(e) => onChange(parseInt(e.target.value, 10))}
        style={{ "--slider-pct": pct } as React.CSSProperties}
      />
      <span className="font-mono text-sm text-foreground w-6 text-right tabular-nums">{value}</span>
    </div>
  );
}

export function GeneratorPanel({ onUse }: { onUse: (password: string) => void }) {
  const [options, setOptions] = useState<GeneratorOptions>(DEFAULT_GENERATOR);
  const [candidate, setCandidate] = useState(() => generatePassword(DEFAULT_GENERATOR));
  const { copied, copy } = useCopy();

  useEffect(() => {
    setCandidate(generatePassword(options));
  }, [options]);

  const bits = entropyBits(options);
  const tone = bits < 50 ? "var(--warning)" : "var(--success)";
  // The last enabled class can't be unchecked — a password drawn from an
  // empty alphabet is not a thing, and a disabled box explains itself better
  // than a silent no-op would.
  const active = enabledClasses(options);
  const isOnlyActive = (name: CharacterClass) => active.length === 1 && active[0] === name;

  return (
    <div className="rounded-lg border border-border bg-muted p-4 space-y-3.5 animate-pop">
      <div className="flex items-center gap-2">
        {/* Click the candidate to copy it — the same gesture as every other
            secret in the app. */}
        <button
          type="button"
          onClick={() => copy(candidate)}
          title="Copy this password"
          className="flex-1 text-left cursor-pointer rounded-sm min-w-0"
        >
          <SecretText value={candidate} className="text-sm break-all leading-snug" />
        </button>
        {copied && <span className="text-xs font-semibold flex-shrink-0" style={{ color: "var(--success)" }}>Copied</span>}
        <button
          type="button"
          aria-label="Regenerate"
          onClick={() => setCandidate(generatePassword(options))}
          className="p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-card transition-colors flex-shrink-0"
        >
          <RefreshIcon className="h-4 w-4" />
        </button>
      </div>

      <div className="h-1 rounded-full overflow-hidden" style={{ background: "var(--border)" }}>
        <div className="h-full transition-all duration-300" style={{ width: `${Math.min(100, (bits / 128) * 100)}%`, background: tone }} />
      </div>
      <p className="text-xs text-muted-foreground font-mono">~{bits} bits</p>

      <div className="flex items-center gap-2 text-xs">
        {(["characters", "passphrase"] as const).map((mode) => (
          <button
            key={mode}
            type="button"
            onClick={() => setOptions((o) => ({ ...o, mode }))}
            className={`px-2.5 py-1.5 rounded-md transition-colors ${
              options.mode === mode ? "bg-accent-subtle text-accent font-semibold" : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {mode === "characters" ? "Characters" : "Passphrase"}
          </button>
        ))}
      </div>

      {options.mode === "characters" ? (
        <div className="space-y-2.5">
          <Slider
            label="Length"
            min={8}
            max={64}
            value={options.length}
            onChange={(length) => setOptions((o) => ({ ...o, length }))}
          />
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2.5 text-xs">
            {CHARACTER_CLASS_ORDER.map((name) => {
              const style = CHARACTER_CLASS_STYLE[name];
              const last = isOnlyActive(name);
              return (
                <Checkbox
                  key={name}
                  checked={options[name]}
                  disabled={last}
                  title={last ? "A password needs at least one character class" : undefined}
                  tint={style.tint}
                  tintSubtle={style.tintSubtle}
                  onChange={(next) => setOptions((o) => ({ ...o, [name]: next }))}
                  label={
                    <span style={{ color: options[name] ? style.tint : "var(--muted-foreground)" }}>{style.label}</span>
                  }
                />
              );
            })}
          </div>
        </div>
      ) : (
        <Slider
          label="Words"
          min={3}
          max={10}
          value={options.words}
          onChange={(words) => setOptions((o) => ({ ...o, words }))}
        />
      )}

      <button type="button" onClick={() => onUse(candidate)} className="btn btn-primary w-full text-sm h-9">
        <CheckIcon className="h-4 w-4" /> Use this password
      </button>
    </div>
  );
}
