export type RecoverPageData = {
  PageTitle: string;
  Token: string;
  KdfIterations: number;
};

export type RecoverResponse = {
  redirectTo?: string;
  message?: string;
};
