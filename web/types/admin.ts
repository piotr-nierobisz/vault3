// Server payload shapes for the management console (mirror
// internal/models/admin.go and the /api/v1/admin/* responses).
//
// Everything here is metadata: counts, account state, timestamps. There is no
// item, envelope or key shape in this file and there cannot be a meaningful
// one — the server holds no key to open any of them, so the console has
// nothing to render even if an endpoint shipped ciphertext.

export type PlatformStats = {
  users: number;
  activeUsers: number;
  suspendedUsers: number;
  verifiedUsers: number;
  twoFactorUsers: number;
  adminUsers: number;
  usersLast7Days: number;
  usersLast30Days: number;
  vaults: number;
  sharedVaults: number;
  items: number;
  trashedItems: number;
  activeSessions: number;
  activeShareLinks: number;
  pendingInvites: number;
  openInquiries: number;
};

export type PlatformSetting = {
  key: string;
  value: string;
  kind: string;
  updatedAt: string;
};

export type AdminUserRow = {
  id: string;
  email: string;
  displayName?: string;
  isActive: boolean;
  emailVerified: boolean;
  twoFactor: boolean;
  isAdmin: boolean;
  vaultCount: number;
  itemCount: number;
  sessionCount: number;
  lastLoginAt?: string;
  archivedAt?: string;
  archivedReason?: string;
  createdAt: string;
};

export type AdminAuditRow = {
  id: string;
  userId?: string;
  email?: string;
  action: string;
  entityType?: string;
  entityId?: string;
  ipAddress?: string;
  userAgent?: string;
  detail?: string;
  createdAt: string;
};

export type ContactInquiry = {
  id: string;
  name: string;
  email: string;
  message: string;
  ipAddress?: string;
  userAgent?: string;
  handledAt?: string;
  createdAt: string;
};

export type AdminOverview = {
  stats: PlatformStats;
  settings: PlatformSetting[];
};

export type AdminUsersResponse = { users: AdminUserRow[]; total: number; page: number };
export type AdminAuditResponse = { entries: AdminAuditRow[]; page: number };
export type AdminInquiriesResponse = { inquiries: ContactInquiry[]; total: number; page: number };

export type AdminPageData = {
  PageTitle: string;
  Stats: PlatformStats;
  Settings: PlatformSetting[];
  PageSize: number;
  SelfID: string;
};
