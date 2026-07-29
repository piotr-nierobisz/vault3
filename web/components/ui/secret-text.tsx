import React from "react";
import { classify, type CharacterClass } from "../../lib/generator";

// SecretText is the one way a secret is rendered as readable text anywhere in
// the app. Every character is tinted by the class it belongs to, so a
// password reads the same in the generator that produced it, in the item that
// stores it, and on a share page that received it — and transcribing one by
// eye stops depending on spotting an l against a 1.
//
// The class split itself comes from lib/generator's `classify`, so the
// toggles that decide what a password may contain and the colours that show
// what it does contain can never drift apart.

// The single tint table. `label` names the class in the generator's toggles;
// `tint` colours both that toggle and every character it produced. Letters
// stay foreground-neutral: they are the bulk of any password, and colouring
// them too would leave nothing for the eye to pick out.
export const CHARACTER_CLASS_STYLE: Record<CharacterClass, { label: string; tint: string; tintSubtle: string }> = {
  letters: { label: "Letters", tint: "var(--foreground)", tintSubtle: "var(--muted)" },
  digits: { label: "Numbers", tint: "var(--accent-2)", tintSubtle: "var(--accent-2-subtle)" },
  symbols: { label: "Characters", tint: "var(--accent-3)", tintSubtle: "var(--accent-3-subtle)" },
};

export const CHARACTER_CLASS_ORDER: CharacterClass[] = ["letters", "digits", "symbols"];

export function SecretText({ value, className }: { value: string; className?: string }) {
  return (
    <span className={`font-mono ${className ?? ""}`}>
      {value.split("").map((char, i) => (
        <span key={i} style={{ color: CHARACTER_CLASS_STYLE[classify(char)].tint }}>
          {char}
        </span>
      ))}
    </span>
  );
}
