import type { CipherEnvelope } from "../lib/crypto";

// Server payload for POST /api/v1/share/open — ciphertext only; the URL
// fragment's share key opens it all client-side.
export type ShareOpenResponse = {
  wrappedItemKey: CipherEnvelope;
  overview: CipherEnvelope;
  details: CipherEnvelope;
  expiresAt: string;
};
