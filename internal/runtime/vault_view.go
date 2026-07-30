package runtime

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"vault3/internal/config"
	"vault3/internal/database"
	"vault3/internal/models"
	"vault3/internal/view"

	sq "github.com/Masterminds/squirrel"
	bungo "github.com/piotr-nierobisz/BunGo"
	"go.uber.org/zap"
)

// /app: the vault itself. The page ships the keyset (all ciphertext) and the
// item rows for the user's first vault; the browser derives keys, unwraps,
// and renders. Every item mutation authorises through vault access, bumps
// the user's sync revision inside the same transaction, and publishes the
// change signal after commit so other devices refresh.

// AppVaultPage renders the vault shell with everything one unlock needs.
func (r *Runtime) AppVaultPage(req *bungo.Request) (map[string]any, error) {
	user := CurrentUser(req)
	viewer := r.Viewer(req)

	data := r.PageData(map[string]any{
		"PageTitle":  "Your vault | Vault3",
		"Viewer":     viewer,
		"ActiveNav":  "vault",
		"NoIndex":    true,
		"Keyset":     view.NewKeyset(user),
		"Items":      []view.ItemRow{},
		"Categories": r.Lookups.CategoryOptions(),
		"Revision":   user.Revision,
	})

	if len(user.Vaults) > 0 {
		items, itemsErr := database.SelectVaultItems(req.Context, r.GetDb(), &r.Builder, user.Vaults[0].Vault.ID)
		if itemsErr != nil {
			return nil, itemsErr
		}
		data["Items"] = view.NewItemRows(items)
	}
	return data, nil
}

// ItemsAPI handles GET /api/v1/items?vaultId=…: the refetch endpoint the
// change signal drives. Returns every row (ciphertext) plus the current
// revision so the client can stamp its cache.
func (r *Runtime) ItemsAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	vaultID := strings.TrimSpace(req.Params["vaultId"])
	if vaultID == "" {
		if len(user.Vaults) == 0 {
			return apiError(404, "No vault on this account."), nil
		}
		vaultID = user.Vaults[0].Vault.ID
	}
	if _, deny := r.requireVaultAccess(req, user.ID, vaultID); deny != nil {
		return *deny, nil
	}

	items, itemsErr := database.SelectVaultItems(req.Context, r.GetDb(), &r.Builder, vaultID)
	if itemsErr != nil {
		return bungo.APIResponse{}, itemsErr
	}
	revision, revisionErr := database.SelectUserRevision(req.Context, r.GetDb(), &r.Builder, user.ID)
	if revisionErr != nil {
		return bungo.APIResponse{}, revisionErr
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body: map[string]any{
			"items":    view.NewItemRows(items),
			"revision": revision,
		},
	}, nil
}

type itemWritePayload struct {
	ID             string          `json:"id"`
	VaultID        string          `json:"vaultId"`
	WrappedItemKey json.RawMessage `json:"wrappedItemKey"`
	Overview       json.RawMessage `json:"overview"`
	Details        json.RawMessage `json:"details"`
}

// CreateItemAPI handles POST /api/v1/items/create.
func (r *Runtime) CreateItemAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	payload, deny := decodeBody[itemWritePayload](req)
	if deny != nil {
		return *deny, nil
	}
	if payload.VaultID == "" {
		return apiError(400, "vaultId is required."), nil
	}
	if _, deny := r.requireVaultOwner(req, user.ID, payload.VaultID, memberReadOnlyMessage); deny != nil {
		return *deny, nil
	}
	if envErr := validateItemEnvelopes(payload); envErr != nil {
		return apiError(400, envErr.Error()), nil
	}

	count, countErr := database.CountVaultItems(req.Context, r.GetDb(), &r.Builder, payload.VaultID)
	if countErr != nil {
		return bungo.APIResponse{}, countErr
	}
	if count >= config.MaxItemsPerVault {
		return apiError(422, "This vault has reached its item limit."), nil
	}

	item := &models.Item{
		ID:             newUUID(),
		VaultID:        payload.VaultID,
		WrappedItemKey: payload.WrappedItemKey,
		Overview:       payload.Overview,
		Details:        payload.Details,
	}
	revisions, commitErr := r.commitVaultChange(req, user.ID, payload.VaultID, "item_created", "item", item.ID,
		func(txRt *Runtime) error {
			return database.InsertItem(req.Context, txRt.GetDb(), &txRt.Builder, item)
		})
	if commitErr != nil {
		return bungo.APIResponse{}, commitErr
	}
	revision := revisions[user.ID]

	stored, loadErr := database.SelectItemByID(req.Context, r.GetDb(), &r.Builder, item.ID)
	if loadErr != nil {
		return bungo.APIResponse{}, loadErr
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"item": view.NewItemRow(stored), "revision": revision},
	}, nil
}

// UpdateItemAPI handles POST /api/v1/items/update: replaces both blobs
// (re-sealed client-side under the item's existing key).
func (r *Runtime) UpdateItemAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	payload, deny := decodeBody[itemWritePayload](req)
	if deny != nil {
		return *deny, nil
	}
	item, _, deny := r.requireItemOwner(req, user.ID, payload.ID, memberReadOnlyMessage)
	if deny != nil {
		return *deny, nil
	}
	if envErr := validateItemEnvelopes(payload); envErr != nil {
		return apiError(400, envErr.Error()), nil
	}

	revisions, commitErr := r.commitVaultChange(req, user.ID, item.VaultID, "item_updated", "item", item.ID,
		func(txRt *Runtime) error {
			return database.UpdateItemBlobs(req.Context, txRt.GetDb(), &txRt.Builder,
				item.ID, payload.Overview, payload.Details)
		})
	if commitErr != nil {
		return bungo.APIResponse{}, commitErr
	}
	revision := revisions[user.ID]

	stored, loadErr := database.SelectItemByID(req.Context, r.GetDb(), &r.Builder, item.ID)
	if loadErr != nil {
		return bungo.APIResponse{}, loadErr
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"item": view.NewItemRow(stored), "revision": revision},
	}, nil
}

// TrashItemAPI, RestoreItemAPI and DeleteItemAPI share one shape: authorise,
// flip, bump, signal.
func (r *Runtime) TrashItemAPI(req *bungo.Request) (bungo.APIResponse, error) {
	return r.itemLifecycleAPI(req, "item_trashed", database.TrashItem)
}

func (r *Runtime) RestoreItemAPI(req *bungo.Request) (bungo.APIResponse, error) {
	return r.itemLifecycleAPI(req, "item_restored", database.RestoreItem)
}

func (r *Runtime) DeleteItemAPI(req *bungo.Request) (bungo.APIResponse, error) {
	return r.itemLifecycleAPI(req, "item_deleted", database.DeleteItem)
}

// itemLifecycleFn is the shared shape of the single-item mutations in
// internal/database (trash / restore / permanent delete).
type itemLifecycleFn func(ctx context.Context, db database.DbTx, builder *sq.StatementBuilderType, itemID string) error

func (r *Runtime) itemLifecycleAPI(req *bungo.Request, action string, mutate itemLifecycleFn) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	payload, deny := decodeBody[idPayload](req)
	if deny != nil {
		return *deny, nil
	}
	item, _, deny := r.requireItemOwner(req, user.ID, payload.ID, memberReadOnlyMessage)
	if deny != nil {
		return *deny, nil
	}

	revisions, commitErr := r.commitVaultChange(req, user.ID, item.VaultID, action, "item", item.ID,
		func(txRt *Runtime) error {
			return mutate(req.Context, txRt.GetDb(), &txRt.Builder, item.ID)
		})
	if commitErr != nil {
		return bungo.APIResponse{}, commitErr
	}

	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"ok": true, "revision": revisions[user.ID]},
	}, nil
}

// --- Authorisation ---------------------------------------------------------
//
// Every vault and item handler authorises through one of the four helpers
// below, and none of them re-implements the check inline. They return either
// the loaded row(s) or a ready-to-return denial, so a handler reads:
//
//	access, deny := r.requireVaultOwner(req, user.ID, vaultID, "…")
//	if deny != nil {
//	    return *deny, nil
//	}
//
// Two properties are deliberately built in rather than left to each caller:
//
//   - "Does not exist" and "is not yours" collapse into the same 404. A
//     distinguishable response would turn any id into an existence oracle.
//   - The role requirement is in the function name. Members hold read access
//     to a shared vault, so the owner check is the only thing standing between
//     a member and someone else's data; a handler that wants it must say so,
//     and one that forgets is visible as `requireVaultAccess` in review rather
//     than as a missing line.

const (
	vaultNotFoundMessage = "Vault not found."
	itemNotFoundMessage  = "Item not found."
	// memberReadOnlyMessage is the 403 for every item mutation: members read a
	// shared vault, owners write it.
	memberReadOnlyMessage = "Members can view this vault but not change it."
)

// requireVaultAccess resolves the caller's access row for a vault. Any role
// passes: use it for reads that every member is entitled to.
func (r *Runtime) requireVaultAccess(req *bungo.Request, userID, vaultID string) (*models.VaultAccess, *bungo.APIResponse) {
	access, accessErr := database.SelectVaultAccess(req.Context, r.GetDb(), &r.Builder, userID, vaultID)
	if accessErr != nil {
		if !errors.Is(accessErr, sql.ErrNoRows) {
			r.Log.Error("vault access lookup failed", zap.Error(accessErr))
		}
		deny := apiError(404, vaultNotFoundMessage)
		return nil, &deny
	}
	return access, nil
}

// requireVaultOwner is requireVaultAccess plus the owner check, denying with
// ownerOnly (403) when the caller holds access but only as a member.
func (r *Runtime) requireVaultOwner(req *bungo.Request, userID, vaultID, ownerOnly string) (*models.VaultAccess, *bungo.APIResponse) {
	access, deny := r.requireVaultAccess(req, userID, vaultID)
	if deny != nil {
		return nil, deny
	}
	if access.Role != models.RoleOwner {
		forbidden := apiError(403, ownerOnly)
		return nil, &forbidden
	}
	return access, nil
}

// requireItemAccess loads an item and the caller's access to its vault. A
// missing item, a foreign item and a blank id are one 404.
func (r *Runtime) requireItemAccess(req *bungo.Request, userID, itemID string) (*models.Item, *models.VaultAccess, *bungo.APIResponse) {
	notFound := apiError(404, itemNotFoundMessage)
	if strings.TrimSpace(itemID) == "" {
		return nil, nil, &notFound
	}
	item, itemErr := database.SelectItemByID(req.Context, r.GetDb(), &r.Builder, itemID)
	if itemErr != nil {
		if !errors.Is(itemErr, sql.ErrNoRows) {
			r.Log.Error("item lookup failed", zap.Error(itemErr))
		}
		return nil, nil, &notFound
	}
	// Deliberately not requireVaultAccess: its 404 names the vault, which
	// would let an item id be probed by the wording of the refusal.
	access, accessErr := database.SelectVaultAccess(req.Context, r.GetDb(), &r.Builder, userID, item.VaultID)
	if accessErr != nil {
		if !errors.Is(accessErr, sql.ErrNoRows) {
			r.Log.Error("vault access lookup failed", zap.Error(accessErr))
		}
		return nil, nil, &notFound
	}
	return item, access, nil
}

// requireItemOwner is requireItemAccess plus the owner check.
func (r *Runtime) requireItemOwner(req *bungo.Request, userID, itemID, ownerOnly string) (*models.Item, *models.VaultAccess, *bungo.APIResponse) {
	item, access, deny := r.requireItemAccess(req, userID, itemID)
	if deny != nil {
		return nil, nil, deny
	}
	if access.Role != models.RoleOwner {
		forbidden := apiError(403, ownerOnly)
		return nil, nil, &forbidden
	}
	return item, access, nil
}

// validateItemEnvelopes structurally checks an item write's three envelopes.
func validateItemEnvelopes(payload *itemWritePayload) error {
	if len(payload.WrappedItemKey) > 0 {
		if envErr := models.ValidateCipherEnvelope(payload.WrappedItemKey, config.MaxWrappedKeyBytes); envErr != nil {
			return fmt.Errorf("malformed item key envelope: %w", envErr)
		}
	}
	if envErr := models.ValidateCipherEnvelope(payload.Overview, config.MaxItemOverviewBytes); envErr != nil {
		return fmt.Errorf("malformed overview envelope: %w", envErr)
	}
	if envErr := models.ValidateCipherEnvelope(payload.Details, config.MaxItemDetailsBytes); envErr != nil {
		return fmt.Errorf("malformed details envelope: %w", envErr)
	}
	return nil
}
