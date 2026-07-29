export type JoinPageData = {
  PageTitle: string;
  RegistrationOpen: boolean;
  KdfIterations: number;
};

export type RegisterResponse = {
  redirectTo?: string;
  message?: string;
  field?: string;
};

export type JoinStep = "account" | "phrase" | "sealing" | "done";
