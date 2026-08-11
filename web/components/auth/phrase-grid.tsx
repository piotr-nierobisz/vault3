import React from "react";
import { CopyButton } from "../ui/copy-button";

// PhraseGrid renders a Secret Phrase as a numbered 3×3 word grid — the way
// it appears in the Emergency Kit, so what users save matches what they see.
export function PhraseGrid({ phrase, withCopy }: { phrase: string; withCopy?: boolean }) {
  const words = phrase.split(" ").filter(Boolean);
  return (
    <div>
      <div className="grid grid-cols-3 gap-2.5">
        {words.map((word, i) => (
          <div
            key={`${i}-${word}`}
            className="rounded-lg border border-border bg-muted px-3 py-2.5 font-mono text-sm text-foreground animate-rise"
            style={{ animationDelay: `${i * 45}ms` }}
          >
            <span className="text-muted-foreground text-xs mr-1.5 select-none">{i + 1}.</span>
            {word}
          </div>
        ))}
      </div>
      {withCopy && (
        <div className="flex justify-end mt-2">
          <CopyButton
            value={phrase}
            label="Copy Secret Phrase"
            className="text-xs text-muted-foreground hover:text-foreground inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full hover:bg-muted transition-colors"
          />
        </div>
      )}
    </div>
  );
}
