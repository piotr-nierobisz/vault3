export type JoinPageData = {
  PageTitle: string;
  RegistrationOpen: boolean;
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
