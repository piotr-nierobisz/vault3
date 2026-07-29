import type { CipherEnvelope, ItemDetails, ItemOverview } from "../lib/crypto";

// Server payload shapes (mirror internal/view: Keyset, ItemRow).

export type KeysetVaultDto = {
  id: string;
  kind: string;
  role: string;
  wrapAlgo: string;
  wrappedKey: CipherEnvelope;
  encName: CipherEnvelope;
  memberCount: number;
};

export type KeysetDto = {
  kdfSalt: string;
  kdfIterations: number;
  algo: string;
  publicKey: unknown;
  encPrivateKey: CipherEnvelope;
  vaults: KeysetVaultDto[];
};

export type ItemRowDto = {
  id: string;
  vaultId: string;
  wrappedItemKey: CipherEnvelope;
  overview: CipherEnvelope;
  details: CipherEnvelope;
  trashed: boolean;
  trashedAt?: string;
  createdAt: string;
  updatedAt: string;
};

export type CategoryDto = {
  code: string;
  label: string;
  icon: string;
};

export type VaultPageData = {
  PageTitle: string;
  Keyset: KeysetDto | null;
  Items: ItemRowDto[];
  Categories: CategoryDto[];
  Revision: number;
  Viewer: { User: { email: string } } | null;
};

export type ItemsResponse = {
  items: ItemRowDto[];
  revision: number;
};

// A vault with its client-side decrypted name (opened from encName with the
// vault key; "Sealed vault" when the key is unavailable).
export type NamedVault = {
  dto: KeysetVaultDto;
  name: string;
};

export type VaultsResponse = {
  vaults: KeysetVaultDto[];
  revision: number;
};

export type VaultWriteResponse = {
  vault: KeysetVaultDto;
  revision: number;
};

export type ShareLinkDto = {
  id: string;
  itemId: string;
  expiresAt: string;
  revoked: boolean;
  revokedAt?: string;
  viewCount: number;
  createdAt: string;
};

export type ShareCreateResponse = {
  link: ShareLinkDto;
  token: string;
};

export type VaultMemberDto = {
  userId: string;
  email: string;
  displayName: string;
  role: string;
  joinedAt: string;
};

export type VaultInviteDto = {
  id: string;
  vaultId: string;
  expiresAt: string;
  createdAt: string;
};

export type VaultMembersResponse = {
  members: VaultMemberDto[];
  invites: VaultInviteDto[];
  role: string;
};

export type InviteCreateResponse = {
  invite: VaultInviteDto;
  token: string;
};

export type ItemWriteResponse = {
  item: ItemRowDto;
  revision: number;
};

// Client-side decrypted shape: the row plus its opened overview and the
// unwrapped per-item key (details open lazily with it).
export type DecryptedItem = {
  row: ItemRowDto;
  overview: ItemOverview;
  itemKey: Uint8Array;
};

export type VaultFilter =
  | { kind: "all" }
  | { kind: "favorites" }
  | { kind: "category"; code: string }
  | { kind: "trash" };

export type { ItemOverview, ItemDetails };

// Per-category field templates for the item form and detail pane. `secret`
// fields are masked/blurred and copied without reveal; a `totp` field holds a
// one-time-code seed, which the detail pane renders as a live rotating code
// (computed in the browser — see lib/totp.ts).
export type FieldSpec = {
  key: string;
  label: string;
  secret?: boolean;
  generator?: boolean;
  totp?: boolean;
  placeholder?: string;
  hint?: string;
};

export const CATEGORY_FIELDS: Record<string, FieldSpec[]> = {
  login: [
    { key: "username", label: "Username / email", placeholder: "you@example.com" },
    { key: "password", label: "Password", secret: true, generator: true },
    {
      key: "totp",
      label: "One-time code",
      totp: true,
      placeholder: "Setup key, or paste an otpauth:// link",
      hint: "Sealed with the rest of this item — codes are computed on your device, never by the server. Storing it here means this vault holds both factors for that account.",
    },
  ],
  secure_note: [],
  card: [
    { key: "cardholder", label: "Cardholder name", placeholder: "NORA SANDOVAL" },
    { key: "number", label: "Card number", secret: true, placeholder: "4242 4242 4242 4242" },
    { key: "expiry", label: "Expiry", placeholder: "12/28" },
    { key: "cvv", label: "CVV", secret: true, placeholder: "123" },
  ],
  identity: [
    { key: "fullName", label: "Full name", placeholder: "Nora Sandoval" },
    { key: "email", label: "Email", placeholder: "you@example.com" },
    { key: "phone", label: "Phone", placeholder: "+44 7700 900000" },
    { key: "address", label: "Address", placeholder: "12 Example Street, London" },
  ],
};
