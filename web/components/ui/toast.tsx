import React, { createContext, useCallback, useContext, useRef, useState } from "react";

// Minimal toast system: useToasts() from any component below <ToastProvider>.
// Kinds map to the semantic tokens.

export type ToastKind = "success" | "error" | "info";
type Toast = { id: number; kind: ToastKind; message: string };

const ToastContext = createContext<(kind: ToastKind, message: string) => void>(() => {});

export function useToasts() {
  return useContext(ToastContext);
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextID = useRef(1);

  const push = useCallback((kind: ToastKind, message: string) => {
    const id = nextID.current++;
    setToasts((t) => [...t, { id, kind, message }]);
    window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3600);
  }, []);

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="fixed bottom-5 right-5 z-[80] flex flex-col gap-2 items-end" aria-live="polite">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className="animate-pop card px-4 py-3 text-sm shadow-lg flex items-center gap-2.5 max-w-xs"
          >
            <span
              className="w-2 h-2 rounded-full flex-shrink-0"
              style={{
                background:
                  toast.kind === "success" ? "var(--success)" : toast.kind === "error" ? "var(--danger)" : "var(--accent)",
              }}
            />
            <span className="text-foreground">{toast.message}</span>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
