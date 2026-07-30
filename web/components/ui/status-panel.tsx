import React from "react";
import { VaultMark } from "../icons";

// The shape every "hold on", "nothing here" and "that didn't work" page takes:
// a centred mark, a heading, one line, and whatever the visitor can do next.
// Surface, padding, mark size and entrance animation are settled here, once,
// because these panels are written far apart from each other and had drifted
// into four paddings and three entrances saying the same thing.
//
// A glyph (`icon`) sits in a tinted well; the brand mark (`mark`) stands on
// its own and breathes while something is still `pulse`-ing. Everything is
// optional: an empty state that wants only a line of copy passes only `body`.
export function StatusPanel({
  icon,
  tone = "accent",
  mark,
  pulse,
  title,
  as: Heading = "h1",
  body,
  children,
}: {
  icon?: React.ReactNode;
  tone?: "accent" | "danger";
  mark?: boolean;
  pulse?: boolean;
  title?: React.ReactNode;
  as?: "h1" | "h2";
  body?: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <div className="panel p-10 text-center animate-unseal">
      {icon && (
        <span className={`icon-tile icon-tile-lg mb-5${tone === "danger" ? " icon-tile-danger" : ""}`} aria-hidden="true">
          {icon}
        </span>
      )}
      {mark && <VaultMark className={`h-11 w-11 text-accent mx-auto mb-5${pulse ? " mark-pulse" : ""}`} />}
      {title && <Heading className="text-2xl font-bold tracking-tight mb-2">{title}</Heading>}
      {body && <div className="text-sm text-muted-foreground leading-relaxed max-w-sm mx-auto">{body}</div>}
      {children && <div className="mt-6">{children}</div>}
    </div>
  );
}
