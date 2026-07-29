import React from "react";
import { CheckIcon } from "../icons";

// The checkbox primitive, in two shapes:
//
//   CheckboxBox — just the control, for call sites that already own their
//                 <label> and its layout (nesting labels would be invalid).
//   Checkbox    — the control plus its label, for the common inline case.
//
// `tint` themes the box to whatever it toggles (pass a token, e.g.
// "var(--accent-2)"); omit it for the brand accent. The tick always paints in
// --background, so it stays legible on any tint in both themes.

type BoxProps = {
  checked: boolean;
  onChange: (checked: boolean) => void;
  tint?: string;
  tintSubtle?: string;
  disabled?: boolean;
  className?: string;
};

export function CheckboxBox({ checked, onChange, tint, tintSubtle, disabled, className }: BoxProps) {
  const style = tint
    ? ({ "--check-tint": tint, "--check-tint-subtle": tintSubtle ?? tint } as React.CSSProperties)
    : undefined;

  return (
    <span className={`checkbox-wrap ${className ?? ""}`}>
      <input
        type="checkbox"
        className="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        style={style}
      />
      <CheckIcon className="checkbox-tick" />
    </span>
  );
}

export function Checkbox({
  label,
  title,
  className,
  ...box
}: BoxProps & { label: React.ReactNode; title?: string }) {
  return (
    <label
      title={title}
      className={`inline-flex items-center gap-2 select-none ${box.disabled ? "cursor-not-allowed opacity-60" : "cursor-pointer"} ${className ?? ""}`}
    >
      <CheckboxBox {...box} />
      {label}
    </label>
  );
}
