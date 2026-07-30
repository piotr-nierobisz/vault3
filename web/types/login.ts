export type LoginPageData = {
  PageTitle: string;
};

export type AuthParamsResponse = {
  kdfSalt: string;
  kdfIterations: number;
  argon2MemoryKiB: number;
  argon2Time: number;
  argon2Lanes: number;
};

export type LoginResponse = {
  redirectTo?: string;
  message?: string;
  twoFactorRequired?: boolean;
  emailNotVerified?: boolean;
};

export type LoginStep = "credentials" | "twofactor";

export type LoginState =
  | { kind: "idle" }
  | { kind: "deriving" }
  | { kind: "submitting" }
  | { kind: "error"; message: string; unverified?: boolean }
  | { kind: "success" };
