export type JoinPageData = {
  PageTitle: string;
  RegistrationOpen: boolean;
  // Public half of the Turnstile pair; the secret half never leaves the
  // server. Cloudflare's always-pass test key outside production.
  TurnstileSiteKey: string;
  KdfCosts: {
    kdfIterations: number;
    argon2MemoryKiB: number;
    argon2Time: number;
    argon2Lanes: number;
  };
};

export type RegisterResponse = {
  redirectTo?: string;
  message?: string;
  field?: string;
};

export type JoinStep = "account" | "phrase" | "sealing" | "done";
