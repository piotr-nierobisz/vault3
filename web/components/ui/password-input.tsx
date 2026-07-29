import React, { useState } from "react";
import { EyeIcon, EyeOffIcon } from "../icons";

// PasswordInput: the shared secret-entry field with a reveal toggle.
// Secrets render in monospace (data-secret hooks the theme.css rule).
export function PasswordInput({
  id,
  name,
  value,
  onChange,
  onBlur,
  placeholder,
  autoComplete,
  disabled,
  autoFocus,
}: {
  id: string;
  name: string;
  value: string;
  onChange: (value: string) => void;
  onBlur?: (e: React.FocusEvent) => void;
  placeholder?: string;
  autoComplete?: string;
  disabled?: boolean;
  autoFocus?: boolean;
}) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="relative">
      <input
        id={id}
        name={name}
        data-secret
        type={visible ? "text" : "password"}
        autoComplete={autoComplete ?? "off"}
        placeholder={placeholder ?? "••••••••••••"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onBlur={onBlur}
        disabled={disabled}
        autoFocus={autoFocus}
        className="input pr-10"
      />
      <button
        type="button"
        tabIndex={-1}
        onClick={() => setVisible((v) => !v)}
        aria-label={visible ? "Hide" : "Show"}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
      >
        {visible ? <EyeOffIcon className="h-4 w-4" /> : <EyeIcon className="h-4 w-4" />}
      </button>
    </div>
  );
}
