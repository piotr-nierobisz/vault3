package runtime

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"vault3/internal/config"
	"vault3/internal/crypto"
	"vault3/internal/database"
	"vault3/internal/models"
	"vault3/internal/view"

	bungo "github.com/piotr-nierobisz/BunGo"
	"go.uber.org/zap"
)

// Share links expose ONE item through a URL whose fragment carries the
// decryption secret. The browser mints a random share key, re-wraps the
// item's per-item key under it, and sends only that wrap; the server stores
// a SHA-256 token hash beside it and, on redemption, returns ciphertext the
// fragment key alone can open. The server can revoke and expire links but
// never read what they share.

// SharePage renders the public share viewer shell; share.tsx reads the
// fragment and does everything else.
func (r *Runtime) SharePage(_ *bungo.Request) (map[string]any, error) {
	return r.PageData(map[string]any{
		"PageTitle":       "A sealed item was shared with you | Vault3",
		"PageDescription": "View an item shared securely from a Vault3 vault. The decryption key never reaches our servers.",
		"NoIndex":         true,
	}), nil
}

// CreateShareLinkAPI handles POST /api/v1/shares/create: owner-only, capped,
// clamped expiry, token returned exactly once.
func (r *Runtime) CreateShareLinkAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		ItemID         string          `json:"itemId"`
		WrappedItemKey json.RawMessage `json:"wrappedItemKey"`
		ExpiresInHours int             `json:"expiresInHours"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	item, access, itemErr := r.loadAuthorisedItem(req, user.ID, payload.ItemID)
	if itemErr != nil {
		return apiError(404, "Item not found."), nil
	}
	if access.Role != "owner" {
		return apiError(403, "Only the vault owner can share items."), nil
	}
	if item.DeletedAt != nil {
		return apiError(422, "Items in the trash can't be shared."), nil
	}
	if envErr := models.ValidateCipherEnvelope(payload.WrappedItemKey, config.MaxWrappedKeyBytes); envErr != nil {
		return apiError(400, "Malformed share key envelope."), nil
	}

	active, countErr := database.CountActiveItemShareLinks(req.Context, r.GetDb(), &r.Builder, item.ID)
	if countErr != nil {
		return bungo.APIResponse{}, countErr
	}
	if active >= config.MaxActiveShareLinksPerItem {
		return apiError(422, "This item has reached its share link limit. Revoke one first."), nil
	}

	hours := payload.ExpiresInHours
	if hours <= 0 {
		hours = config.ShareLinkDefaultTTLHours
	}
	if hours > config.ShareLinkMaxTTLHours {
		hours = config.ShareLinkMaxTTLHours
	}

	token, tokenHash, tokenErr := crypto.NewToken()
	if tokenErr != nil {
		return bungo.APIResponse{}, tokenErr
	}
	link := &models.ShareLink{
		ID:              newUUID(),
		ItemID:          item.ID,
		CreatedByUserID: user.ID,
		TokenHash:       tokenHash,
		WrappedItemKey:  payload.WrappedItemKey,
		ExpiresAt:       time.Now().Add(time.Duration(hours) * time.Hour),
		// Set for the immediate response; the DB default is authoritative.
		CreatedAt: time.Now(),
	}
	if insertErr := database.InsertShareLink(req.Context, r.GetDb(), &r.Builder, link); insertErr != nil {
		return bungo.APIResponse{}, insertErr
	}

	r.audit(req, user.ID, "share_created", "share_link", link.ID, "")
	return bungo.APIResponse{
		StatusCode: 200,
		Body: map[string]any{
			"link":  view.NewShareLinkRow(link),
			"token": token,
		},
	}, nil
}

// ItemShareLinksAPI handles GET /api/v1/shares?itemId=…: the owner's link
// list for the share dialog.
func (r *Runtime) ItemShareLinksAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	_, access, itemErr := r.loadAuthorisedItem(req, user.ID, req.Params["itemId"])
	if itemErr != nil {
		return apiError(404, "Item not found."), nil
	}
	if access.Role != "owner" {
		return apiError(403, "Only the vault owner can manage share links."), nil
	}
	links, linksErr := database.SelectItemShareLinks(req.Context, r.GetDb(), &r.Builder, req.Params["itemId"])
	if linksErr != nil {
		return bungo.APIResponse{}, linksErr
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"links": view.NewShareLinkRows(links)},
	}, nil
}

// RevokeShareLinkAPI handles POST /api/v1/shares/revoke {id}.
func (r *Runtime) RevokeShareLinkAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		ID string `json:"id"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	link, linkErr := database.SelectShareLinkByID(req.Context, r.GetDb(), &r.Builder, payload.ID)
	if linkErr != nil {
		if !errors.Is(linkErr, sql.ErrNoRows) {
			r.Log.Error("share link lookup failed", zap.Error(linkErr))
		}
		return apiError(404, "Share link not found."), nil
	}
	_, access, itemErr := r.loadAuthorisedItem(req, user.ID, link.ItemID)
	if itemErr != nil {
		return apiError(404, "Share link not found."), nil
	}
	if access.Role != "owner" {
		return apiError(403, "Only the vault owner can manage share links."), nil
	}
	if revokeErr := database.RevokeShareLink(req.Context, r.GetDb(), &r.Builder, link.ID); revokeErr != nil {
		return bungo.APIResponse{}, revokeErr
	}
	r.audit(req, user.ID, "share_revoked", "share_link", link.ID, "")
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"ok": true}}, nil
}

// OpenShareAPI handles POST /api/v1/share/open {token} — the one public
// sharing endpoint (throttled by the middleware). It returns ciphertext
// only: the wrapped item key plus the item's live blobs. Missing, revoked,
// expired and trashed all collapse into the same 404.
func (r *Runtime) OpenShareAPI(req *bungo.Request) (bungo.APIResponse, error) {
	var payload struct {
		Token string `json:"token"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	if payload.Token == "" {
		return apiError(400, "Missing share token."), nil
	}

	link, redeemErr := database.RedeemShareLink(req.Context, r.GetDb(), &r.Builder, crypto.HashToken(payload.Token))
	if redeemErr != nil {
		if !errors.Is(redeemErr, sql.ErrNoRows) {
			r.Log.Error("share redemption failed", zap.Error(redeemErr))
		}
		return apiError(404, "This share link is invalid, expired or revoked."), nil
	}
	item, itemErr := database.SelectItemByID(req.Context, r.GetDb(), &r.Builder, link.ItemID)
	if itemErr != nil {
		if !errors.Is(itemErr, sql.ErrNoRows) {
			r.Log.Error("shared item lookup failed", zap.Error(itemErr))
		}
		return apiError(404, "This share link is invalid, expired or revoked."), nil
	}
	if item.DeletedAt != nil {
		return apiError(404, "This share link is invalid, expired or revoked."), nil
	}

	r.audit(req, "", "share_opened", "share_link", link.ID, "")
	return bungo.APIResponse{
		StatusCode: 200,
		Body: map[string]any{
			"wrappedItemKey": link.WrappedItemKey,
			"overview":       item.Overview,
			"details":        item.Details,
			"expiresAt":      link.ExpiresAt,
		},
	}, nil
}
