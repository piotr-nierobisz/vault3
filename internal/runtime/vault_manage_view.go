package runtime

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"vault3/internal/config"
	"vault3/internal/crypto"
	"vault3/internal/database"
	"vault3/internal/models"
	"vault3/internal/view"

	bungo "github.com/piotr-nierobisz/BunGo"
	"go.uber.org/zap"
)

// Vault management: create/rename/delete, the members panel, and invite
// links. An invite is the share-link pattern applied to a vault key: the
// owner's browser mints a random invite key, seals the vault key under it,
// and the server stores only the token hash and that wrap. Accepting opens
// the vault key with the fragment secret and re-wraps it under the
// acceptor's own key-encryption key, so every stored vault wrap stays
// uniform ('muk') and Master Password rotation is unchanged.

// VaultsAPI handles GET /api/v1/vaults: the refetch endpoint for the vault
// list (the change signal drives it, like /items).
func (r *Runtime) VaultsAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	vaults, vaultsErr := database.SelectUserVaults(req.Context, r.GetDb(), &r.Builder, user.ID)
	if vaultsErr != nil {
		return bungo.APIResponse{}, vaultsErr
	}
	revision, revisionErr := database.SelectUserRevision(req.Context, r.GetDb(), &r.Builder, user.ID)
	if revisionErr != nil {
		return bungo.APIResponse{}, revisionErr
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body: map[string]any{
			"vaults":   view.NewKeysetVaults(vaults),
			"revision": revision,
		},
	}, nil
}

// CreateVaultAPI handles POST /api/v1/vaults/create: a new vault whose key
// and encrypted name were minted client-side.
func (r *Runtime) CreateVaultAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		EncName    json.RawMessage `json:"encName"`
		WrappedKey json.RawMessage `json:"wrappedKey"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	if envErr := models.ValidateCipherEnvelope(payload.EncName, config.MaxVaultNameBytes); envErr != nil {
		return apiError(400, "Malformed vault name envelope."), nil
	}
	if envErr := models.ValidateCipherEnvelope(payload.WrappedKey, config.MaxWrappedKeyBytes); envErr != nil {
		return apiError(400, "Malformed vault key envelope."), nil
	}

	count, countErr := database.CountUserVaults(req.Context, r.GetDb(), &r.Builder, user.ID)
	if countErr != nil {
		return bungo.APIResponse{}, countErr
	}
	if count >= config.MaxVaultsPerUser {
		return apiError(422, "You've reached the vault limit for this account."), nil
	}

	vault := &models.Vault{
		ID:          newUUID(),
		OwnerUserID: user.ID,
		Kind:        "personal",
		EncName:     payload.EncName,
	}
	access := &models.VaultAccess{
		ID:         newUUID(),
		VaultID:    vault.ID,
		UserID:     user.ID,
		Role:       "owner",
		WrapAlgo:   "muk",
		WrappedKey: payload.WrappedKey,
	}
	var revision int64
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		if insertErr := database.InsertVault(req.Context, txRt.GetDb(), &txRt.Builder, vault); insertErr != nil {
			return insertErr
		}
		if accessErr := database.InsertVaultAccess(req.Context, txRt.GetDb(), &txRt.Builder, access); accessErr != nil {
			return accessErr
		}
		var bumpErr error
		revision, bumpErr = SignalUserChanged(req.Context, txRt, user.ID)
		return bumpErr
	})
	if transactionErr != nil {
		return bungo.APIResponse{}, transactionErr
	}

	r.PublishChange(req, user.ID, revision)
	r.audit(req, user.ID, "vault_created", "vault", vault.ID, "")
	return bungo.APIResponse{
		StatusCode: 200,
		Body: map[string]any{
			"vault": view.KeysetVault{
				ID:          vault.ID,
				Kind:        vault.Kind,
				Role:        access.Role,
				WrapAlgo:    access.WrapAlgo,
				WrappedKey:  access.WrappedKey,
				EncName:     vault.EncName,
				MemberCount: 1,
			},
			"revision": revision,
		},
	}, nil
}

// RenameVaultAPI handles POST /api/v1/vaults/rename: replaces the encrypted
// name (sealed under the vault key, so every member still reads it).
func (r *Runtime) RenameVaultAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		VaultID string          `json:"vaultId"`
		EncName json.RawMessage `json:"encName"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	access, accessErr := r.requireVaultAccess(req, user.ID, payload.VaultID)
	if accessErr != nil {
		return apiError(404, "Vault not found."), nil
	}
	if access.Role != "owner" {
		return apiError(403, "Only the vault owner can rename it."), nil
	}
	if envErr := models.ValidateCipherEnvelope(payload.EncName, config.MaxVaultNameBytes); envErr != nil {
		return apiError(400, "Malformed vault name envelope."), nil
	}

	var revisions map[string]int64
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		if updateErr := database.UpdateVaultEncName(req.Context, txRt.GetDb(), &txRt.Builder,
			payload.VaultID, payload.EncName); updateErr != nil {
			return updateErr
		}
		var signalErr error
		revisions, signalErr = SignalVaultChanged(req.Context, txRt, payload.VaultID)
		return signalErr
	})
	if transactionErr != nil {
		return bungo.APIResponse{}, transactionErr
	}

	r.PublishChanges(req, revisions)
	r.audit(req, user.ID, "vault_renamed", "vault", payload.VaultID, "")
	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"ok": true, "revision": revisions[user.ID]},
	}, nil
}

// DeleteVaultAPI handles POST /api/v1/vaults/delete: owner-only, forbidden
// on the account's last vault, permanent (items cascade).
func (r *Runtime) DeleteVaultAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		VaultID string `json:"vaultId"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	access, accessErr := r.requireVaultAccess(req, user.ID, payload.VaultID)
	if accessErr != nil {
		return apiError(404, "Vault not found."), nil
	}
	if access.Role != "owner" {
		return apiError(403, "Only the vault owner can delete it."), nil
	}
	count, countErr := database.CountUserVaults(req.Context, r.GetDb(), &r.Builder, user.ID)
	if countErr != nil {
		return bungo.APIResponse{}, countErr
	}
	if count <= 1 {
		return apiError(422, "You can't delete your only vault."), nil
	}

	// Capture the audience before the delete removes the access rows.
	memberIDs, memberErr := database.SelectVaultUserIDs(req.Context, r.GetDb(), &r.Builder, payload.VaultID)
	if memberErr != nil {
		return bungo.APIResponse{}, memberErr
	}

	var revisions map[string]int64
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		if deleteErr := database.DeleteVault(req.Context, txRt.GetDb(), &txRt.Builder, payload.VaultID); deleteErr != nil {
			return deleteErr
		}
		var signalErr error
		revisions, signalErr = signalUsersChanged(req.Context, txRt, memberIDs)
		return signalErr
	})
	if transactionErr != nil {
		return bungo.APIResponse{}, transactionErr
	}

	r.PublishChanges(req, revisions)
	r.audit(req, user.ID, "vault_deleted", "vault", payload.VaultID, "")
	for _, memberID := range memberIDs {
		if memberID == user.ID {
			continue
		}
		if notifyErr := r.Notify(req.Context, &VaultAccessEnded{MemberUserID: memberID, Reason: "deleted"}); notifyErr != nil {
			r.Log.Warn("vault delete: member notification failed", zap.Error(notifyErr))
		}
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"ok": true, "revision": revisions[user.ID]},
	}, nil
}

// VaultMembersAPI handles GET /api/v1/vaults/members?vaultId=…: everyone
// with access sees the member list; pending invites are owner-only.
func (r *Runtime) VaultMembersAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	vaultID := strings.TrimSpace(req.Params["vaultId"])
	access, accessErr := r.requireVaultAccess(req, user.ID, vaultID)
	if accessErr != nil {
		return apiError(404, "Vault not found."), nil
	}

	members, membersErr := database.SelectVaultMembers(req.Context, r.GetDb(), &r.Builder, r.Cipher, vaultID)
	if membersErr != nil {
		return bungo.APIResponse{}, membersErr
	}
	body := map[string]any{
		"members": members,
		"role":    access.Role,
		"invites": []view.VaultInviteRow{},
	}
	if access.Role == "owner" {
		invites, invitesErr := database.SelectVaultInvites(req.Context, r.GetDb(), &r.Builder, vaultID)
		if invitesErr != nil {
			return bungo.APIResponse{}, invitesErr
		}
		body["invites"] = view.NewVaultInviteRows(invites)
	}
	return bungo.APIResponse{StatusCode: 200, Body: body}, nil
}

// CreateVaultInviteAPI handles POST /api/v1/vaults/invites/create: mints a
// single-use invite whose token is returned exactly once.
func (r *Runtime) CreateVaultInviteAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		VaultID         string          `json:"vaultId"`
		WrappedVaultKey json.RawMessage `json:"wrappedVaultKey"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	access, accessErr := r.requireVaultAccess(req, user.ID, payload.VaultID)
	if accessErr != nil {
		return apiError(404, "Vault not found."), nil
	}
	if access.Role != "owner" {
		return apiError(403, "Only the vault owner can invite people."), nil
	}
	if envErr := models.ValidateCipherEnvelope(payload.WrappedVaultKey, config.MaxWrappedKeyBytes); envErr != nil {
		return apiError(400, "Malformed invite key envelope."), nil
	}

	memberCount, memberErr := database.CountVaultMembers(req.Context, r.GetDb(), &r.Builder, payload.VaultID)
	if memberErr != nil {
		return bungo.APIResponse{}, memberErr
	}
	if memberCount >= config.MaxMembersPerVault {
		return apiError(422, "This vault has reached its member limit."), nil
	}
	pending, pendingErr := database.CountActiveVaultInvites(req.Context, r.GetDb(), &r.Builder, payload.VaultID)
	if pendingErr != nil {
		return bungo.APIResponse{}, pendingErr
	}
	if pending >= config.MaxActiveInvitesPerVault {
		return apiError(422, "This vault has too many pending invites. Revoke one first."), nil
	}

	token, tokenHash, tokenErr := crypto.NewToken()
	if tokenErr != nil {
		return bungo.APIResponse{}, tokenErr
	}
	invite := &models.VaultInvite{
		ID:              newUUID(),
		VaultID:         payload.VaultID,
		CreatedByUserID: user.ID,
		TokenHash:       tokenHash,
		WrappedVaultKey: payload.WrappedVaultKey,
		Role:            "member",
		ExpiresAt:       time.Now().Add(config.VaultInviteTTL),
		// Set for the immediate response; the DB default is authoritative.
		CreatedAt: time.Now(),
	}
	if insertErr := database.InsertVaultInvite(req.Context, r.GetDb(), &r.Builder, invite); insertErr != nil {
		return bungo.APIResponse{}, insertErr
	}

	r.audit(req, user.ID, "vault_invite_created", "vault_invite", invite.ID, "")
	return bungo.APIResponse{
		StatusCode: 200,
		Body: map[string]any{
			"invite": view.NewVaultInviteRow(invite),
			"token":  token,
		},
	}, nil
}

// RevokeVaultInviteAPI handles POST /api/v1/vaults/invites/revoke {id}.
func (r *Runtime) RevokeVaultInviteAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		ID string `json:"id"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	invite, inviteErr := database.SelectVaultInviteByID(req.Context, r.GetDb(), &r.Builder, payload.ID)
	if inviteErr != nil {
		if !errors.Is(inviteErr, sql.ErrNoRows) {
			r.Log.Error("invite lookup failed", zap.Error(inviteErr))
		}
		return apiError(404, "Invite not found."), nil
	}
	access, accessErr := r.requireVaultAccess(req, user.ID, invite.VaultID)
	if accessErr != nil {
		return apiError(404, "Invite not found."), nil
	}
	if access.Role != "owner" {
		return apiError(403, "Only the vault owner can revoke invites."), nil
	}
	if revokeErr := database.RevokeVaultInvite(req.Context, r.GetDb(), &r.Builder, invite.ID); revokeErr != nil {
		return bungo.APIResponse{}, revokeErr
	}
	r.audit(req, user.ID, "vault_invite_revoked", "vault_invite", invite.ID, "")
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"ok": true}}, nil
}

// InvitePreviewAPI handles POST /api/v1/vaults/invites/preview {token}: what
// the accept page shows before the user commits. Everything returned is
// ciphertext or already visible to the inviter (their email).
func (r *Runtime) InvitePreviewAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		Token string `json:"token"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	if payload.Token == "" {
		return apiError(400, "Missing invite token."), nil
	}

	invite, inviteErr := database.SelectLiveVaultInviteByTokenHash(req.Context, r.GetDb(), &r.Builder, crypto.HashToken(payload.Token))
	if inviteErr != nil {
		if !errors.Is(inviteErr, sql.ErrNoRows) {
			r.Log.Error("invite preview lookup failed", zap.Error(inviteErr))
		}
		return apiError(404, "This invite is invalid, expired or revoked."), nil
	}
	vault, vaultErr := database.SelectVaultByID(req.Context, r.GetDb(), &r.Builder, invite.VaultID)
	if vaultErr != nil {
		return bungo.APIResponse{}, vaultErr
	}
	members, membersErr := database.SelectVaultMembers(req.Context, r.GetDb(), &r.Builder, r.Cipher, invite.VaultID)
	if membersErr != nil {
		return bungo.APIResponse{}, membersErr
	}
	inviterEmail := ""
	alreadyMember := false
	for _, m := range members {
		if m.Role == "owner" {
			inviterEmail = m.Email
		}
		if m.UserID == user.ID {
			alreadyMember = true
		}
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body: map[string]any{
			"vaultId":         invite.VaultID,
			"wrappedVaultKey": invite.WrappedVaultKey,
			"encName":         vault.EncName,
			"inviterEmail":    inviterEmail,
			"memberCount":     len(members),
			"alreadyMember":   alreadyMember,
			"expiresAt":       invite.ExpiresAt,
		},
	}, nil
}

// AcceptVaultInviteAPI handles POST /api/v1/vaults/invites/accept {token,
// wrappedKey}: claims the single-use invite and grants membership with the
// vault key re-wrapped under the acceptor's own key-encryption key.
func (r *Runtime) AcceptVaultInviteAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		Token      string          `json:"token"`
		WrappedKey json.RawMessage `json:"wrappedKey"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	if payload.Token == "" {
		return apiError(400, "Missing invite token."), nil
	}
	if envErr := models.ValidateCipherEnvelope(payload.WrappedKey, config.MaxWrappedKeyBytes); envErr != nil {
		return apiError(400, "Malformed vault key envelope."), nil
	}

	// Pre-checks outside the transaction; the unique access constraint and
	// the atomic claim are the real guards.
	tokenHash := crypto.HashToken(payload.Token)
	pending, pendingErr := database.SelectLiveVaultInviteByTokenHash(req.Context, r.GetDb(), &r.Builder, tokenHash)
	if pendingErr != nil {
		if !errors.Is(pendingErr, sql.ErrNoRows) {
			r.Log.Error("invite accept lookup failed", zap.Error(pendingErr))
		}
		return apiError(404, "This invite is invalid, expired or revoked."), nil
	}
	if _, existsErr := database.SelectVaultAccess(req.Context, r.GetDb(), &r.Builder, user.ID, pending.VaultID); existsErr == nil {
		return apiError(409, "You already have access to this vault."), nil
	}
	vaultCount, vaultCountErr := database.CountUserVaults(req.Context, r.GetDb(), &r.Builder, user.ID)
	if vaultCountErr != nil {
		return bungo.APIResponse{}, vaultCountErr
	}
	if vaultCount >= config.MaxVaultsPerUser {
		return apiError(422, "You've reached the vault limit for this account."), nil
	}
	memberCount, memberCountErr := database.CountVaultMembers(req.Context, r.GetDb(), &r.Builder, pending.VaultID)
	if memberCountErr != nil {
		return bungo.APIResponse{}, memberCountErr
	}
	if memberCount >= config.MaxMembersPerVault {
		return apiError(422, "This vault has reached its member limit."), nil
	}

	access := &models.VaultAccess{
		ID:         newUUID(),
		VaultID:    pending.VaultID,
		UserID:     user.ID,
		Role:       "member",
		WrapAlgo:   "muk",
		WrappedKey: payload.WrappedKey,
	}
	var revisions map[string]int64
	var claimed *models.VaultInvite
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		var claimErr error
		claimed, claimErr = database.ClaimVaultInvite(req.Context, txRt.GetDb(), &txRt.Builder, tokenHash, user.ID)
		if claimErr != nil {
			return claimErr
		}
		if accessErr := database.InsertVaultAccess(req.Context, txRt.GetDb(), &txRt.Builder, access); accessErr != nil {
			return accessErr
		}
		if kindErr := database.UpdateVaultKind(req.Context, txRt.GetDb(), &txRt.Builder, claimed.VaultID, "shared"); kindErr != nil {
			return kindErr
		}
		var signalErr error
		revisions, signalErr = SignalVaultChanged(req.Context, txRt, claimed.VaultID)
		return signalErr
	})
	if transactionErr != nil {
		if errors.Is(transactionErr, sql.ErrNoRows) {
			return apiError(404, "This invite is invalid, expired or revoked."), nil
		}
		return bungo.APIResponse{}, transactionErr
	}

	r.PublishChanges(req, revisions)
	r.audit(req, user.ID, "vault_invite_accepted", "vault_invite", claimed.ID, "")
	if notifyErr := r.Notify(req.Context, &VaultMemberJoined{OwnerUserID: claimed.CreatedByUserID, MemberEmail: user.Email}); notifyErr != nil {
		r.Log.Warn("invite accept: owner notification failed", zap.Error(notifyErr))
	}

	vault, vaultErr := database.SelectVaultByID(req.Context, r.GetDb(), &r.Builder, claimed.VaultID)
	if vaultErr != nil {
		return bungo.APIResponse{}, vaultErr
	}
	newCount, newCountErr := database.CountVaultMembers(req.Context, r.GetDb(), &r.Builder, claimed.VaultID)
	if newCountErr != nil {
		return bungo.APIResponse{}, newCountErr
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body: map[string]any{
			"vault": view.KeysetVault{
				ID:          vault.ID,
				Kind:        vault.Kind,
				Role:        access.Role,
				WrapAlgo:    access.WrapAlgo,
				WrappedKey:  access.WrappedKey,
				EncName:     vault.EncName,
				MemberCount: newCount,
			},
			"revision": revisions[user.ID],
		},
	}, nil
}

// RemoveVaultMemberAPI handles POST /api/v1/vaults/members/remove {vaultId,
// userId}: the owner removes a member, or a member removes themselves
// (leaves). The owner cannot be removed — delete the vault instead.
func (r *Runtime) RemoveVaultMemberAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		VaultID string `json:"vaultId"`
		UserID  string `json:"userId"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	access, accessErr := r.requireVaultAccess(req, user.ID, payload.VaultID)
	if accessErr != nil {
		return apiError(404, "Vault not found."), nil
	}
	leaving := payload.UserID == user.ID
	if !leaving && access.Role != "owner" {
		return apiError(403, "Only the vault owner can remove members."), nil
	}
	target, targetErr := database.SelectVaultAccess(req.Context, r.GetDb(), &r.Builder, payload.UserID, payload.VaultID)
	if targetErr != nil {
		return apiError(404, "That person doesn't have access to this vault."), nil
	}
	if target.Role == "owner" {
		return apiError(422, "The owner can't be removed. Delete the vault instead."), nil
	}

	// Capture the audience (including the leaver) before the delete.
	memberIDs, memberErr := database.SelectVaultUserIDs(req.Context, r.GetDb(), &r.Builder, payload.VaultID)
	if memberErr != nil {
		return bungo.APIResponse{}, memberErr
	}

	var revisions map[string]int64
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		if deleteErr := database.DeleteVaultAccess(req.Context, txRt.GetDb(), &txRt.Builder, payload.VaultID, payload.UserID); deleteErr != nil {
			return deleteErr
		}
		remaining, remainingErr := database.CountVaultMembers(req.Context, txRt.GetDb(), &txRt.Builder, payload.VaultID)
		if remainingErr != nil {
			return remainingErr
		}
		if remaining <= 1 {
			if kindErr := database.UpdateVaultKind(req.Context, txRt.GetDb(), &txRt.Builder, payload.VaultID, "personal"); kindErr != nil {
				return kindErr
			}
		}
		var signalErr error
		revisions, signalErr = signalUsersChanged(req.Context, txRt, memberIDs)
		return signalErr
	})
	if transactionErr != nil {
		return bungo.APIResponse{}, transactionErr
	}

	r.PublishChanges(req, revisions)
	if leaving {
		r.audit(req, user.ID, "vault_left", "vault", payload.VaultID, "")
		ownerID := ""
		if vault, vaultErr := database.SelectVaultByID(req.Context, r.GetDb(), &r.Builder, payload.VaultID); vaultErr == nil {
			ownerID = vault.OwnerUserID
		}
		if ownerID != "" {
			if notifyErr := r.Notify(req.Context, &VaultMemberLeft{OwnerUserID: ownerID, MemberEmail: user.Email}); notifyErr != nil {
				r.Log.Warn("vault leave: owner notification failed", zap.Error(notifyErr))
			}
		}
	} else {
		r.audit(req, user.ID, "vault_member_removed", "vault", payload.VaultID, "")
		if notifyErr := r.Notify(req.Context, &VaultAccessEnded{MemberUserID: payload.UserID, Reason: "removed"}); notifyErr != nil {
			r.Log.Warn("member removal: notification failed", zap.Error(notifyErr))
		}
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"ok": true, "revision": revisions[user.ID]},
	}, nil
}

// InvitePage renders the invite accept shell at /app/invite. optional_auth:
// signed-out visitors get a sign-in prompt (the layer must not 401 a link
// people open from a message), signed-in ones get their keyset to unlock
// and accept with.
func (r *Runtime) InvitePage(req *bungo.Request) (map[string]any, error) {
	viewer := r.Viewer(req)
	data := r.PageData(map[string]any{
		"PageTitle": "Vault invitation | Vault3",
		"Viewer":    viewer,
		"NoIndex":   true,
	})
	if user := CurrentUser(req); user != nil {
		data["Keyset"] = view.NewKeyset(user)
	}
	return data, nil
}
