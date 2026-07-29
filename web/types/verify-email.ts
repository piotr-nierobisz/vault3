export type VerifyEmailPageData = {
  PageTitle: string;
  Token: string;
};

export type VerifyResponse = {
  verified?: boolean;
  message?: string;
};
