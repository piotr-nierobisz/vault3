import React from "react";

// The Cloudflare Turnstile widget: the bot check on sign-in and registration,
// and the only third-party code Vault3 loads anywhere. It renders on /login
// and /join and on no other page — the CSP allowance that admits it is scoped
// to exactly those two documents in internal/runtime/middleware.go, so /app,
// where a vault is unlocked, still admits code from this origin alone.
//
// api.js is injected as a plain <script> rather than imported: it is not an ES
// module, BunGo resolves URL imports at build time (which would inline a copy
// that goes stale and defeats the point of a hosted challenge), and the
// challenge is only solvable when the script is served from Cloudflare's own
// origin.
//
// Tokens are single-use and lapse after five minutes, so a widget is worth
// exactly one submission:
//   - a submission the server refused → the parent changes this component's
//     `key`, which tears the widget down and mints a fresh challenge;
//   - a form left open past the token's life → expired-callback resets in
//     place, so the page the user comes back to is still submittable.
//
// Failure is closed on this side too: no token, no submit. The parent disables
// its button on an empty token, and the note below says why when the script
// itself could not load — an ad blocker is the usual cause, and a dead button
// with no explanation is the worst version of that.

declare global {
  interface Window {
    turnstile?: {
      render: (el: HTMLElement, opts: Record<string, unknown>) => string;
      reset: (id?: string) => void;
      remove: (id: string) => void;
    };
  }
}

const SCRIPT_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

// One load per document, shared by every mount. The promise is cleared on
// failure so a later mount (or a remount after a refused submit) retries
// rather than inheriting a rejection from a connection that has since come
// back.
let scriptPromise: Promise<void> | null = null;

function loadTurnstile(): Promise<void> {
  if (window.turnstile) return Promise.resolve();
  if (!scriptPromise) {
    scriptPromise = new Promise<void>((resolve, reject) => {
      const script = document.createElement("script");
      script.src = SCRIPT_URL;
      script.async = true;
      script.defer = true;
      script.onload = () => resolve();
      script.onerror = () => {
        scriptPromise = null;
        reject(new Error("turnstile script failed to load"));
      };
      document.head.appendChild(script);
    });
  }
  return scriptPromise;
}

export function Turnstile({
  siteKey,
  onToken,
  className,
}: {
  siteKey: string;
  onToken: (token: string) => void;
  className?: string;
}) {
  const host = React.useRef<HTMLDivElement | null>(null);
  const [failed, setFailed] = React.useState(false);

  // The callback is a fresh closure on every parent render; holding it in a
  // ref keeps the effect keyed on the site key alone, so a keystroke in the
  // form beside the widget cannot tear the challenge down mid-solve.
  const emit = React.useRef(onToken);
  emit.current = onToken;

  React.useEffect(() => {
    let widgetID: string | undefined;
    let cancelled = false;

    const render = () => {
      if (cancelled || !host.current || !window.turnstile) return;
      widgetID = window.turnstile.render(host.current, {
        sitekey: siteKey,
        // One theme, dark — same rule as the rest of the app.
        theme: "dark",
        callback: (token: string) => emit.current(token),
        "expired-callback": () => {
          emit.current("");
          window.turnstile?.reset(widgetID);
        },
        "error-callback": () => emit.current(""),
      });
    };

    // render() is called straight off the script's own load event. Do NOT
    // route it through turnstile.ready(): that helper exists for callers who
    // may run before api.js has, and calling it afterwards makes api.js warn
    // and throw — which the catch below then reports as a widget that never
    // loaded. The catch covers both real failures the user has to be told
    // about, since either one leaves them with no token and a dead button.
    loadTurnstile()
      .then(render)
      .catch(() => {
        if (cancelled) return;
        setFailed(true);
        emit.current("");
      });

    return () => {
      cancelled = true;
      if (widgetID) window.turnstile?.remove(widgetID);
    };
  }, [siteKey]);

  return (
    <div className={className}>
      <div ref={host} />
      {failed && (
        <p className="text-xs text-muted-foreground">
          The human check could not load. If you use a content blocker, allow challenges.cloudflare.com and reload.
        </p>
      )}
    </div>
  );
}
