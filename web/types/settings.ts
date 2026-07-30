import type { KeysetDto } from "./vault";

export type SessionRow = {
  id: string;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
  lastSeenAt: string;
  current: boolean;
};

export type NotificationPrefs = {
  emailEnabled: boolean;
  securityAlerts: boolean;
  productUpdates: boolean;
};

export type SettingsPageData = {
  PageTitle: string;
  Viewer: { User: { email: string; displayName?: string } } | null;
  Sessions: SessionRow[];
  Prefs: NotificationPrefs;
  TwoFactorEnabled: boolean;
  EmailVerified: boolean;
  KdfCosts: {
    kdfIterations: number;
    argon2MemoryKiB: number;
    argon2Time: number;
    argon2Lanes: number;
  };
  Keyset: KeysetDto | null;
  Revision: number;
};

export type TwoFactorSetupResponse = {
  secret: string;
  otpauthUrl: string;
  qrDataUri: string;
};
