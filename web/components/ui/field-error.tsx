import React from "react";

// FieldError renders a form field's validation message only once the field
// has been touched, keeping untouched forms quiet.
export function FieldError({
  touched,
  error,
  className,
}: {
  touched?: boolean;
  error?: string;
  className?: string;
}) {
  if (!touched || !error) return null;
  return <p className={className ?? "text-xs text-danger pt-1"}>{error}</p>;
}
