import type { CipherEnvelope } from "../lib/crypto";
import type { KeysetDto, KeysetVaultDto } from "./vault";

export type InvitePageData = {
  PageTitle: string;
  Viewer: { User: { email: string } } | null;
  Keyset?: KeysetDto | null;
};

// Server payload for POST /api/v1/vaults/invites/preview.
export type InvitePreviewResponse = {
  vaultId: string;
  wrappedVaultKey: CipherEnvelope;
  encName: CipherEnvelope;
  inviterEmail: string;
  memberCount: number;
  alreadyMember: boolean;
  expiresAt: string;
};

// Server payload for POST /api/v1/vaults/invites/accept.
export type InviteAcceptResponse = {
  vault: KeysetVaultDto;
  revision: number;
};
