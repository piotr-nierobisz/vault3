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
	if _, accessErr := r.requireVaultAccess(req, user.ID, vaultID); accessErr != nil {
		return apiError(404, "Vault not found."), nil
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
	var payload itemWritePayload
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	if payload.VaultID == "" {
		return apiError(400, "vaultId is required."), nil
	}
	access, accessErr := r.requireVaultAccess(req, user.ID, payload.VaultID)
	if accessErr != nil {
		return apiError(404, "Vault not found."), nil
	}
	if access.Role != "owner" {
		return apiError(403, "Members can view this vault but not change it."), nil
	}
	if envErr := validateItemEnvelopes(&payload); envErr != nil {
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
	var revisions map[string]int64
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		if insertErr := database.InsertItem(req.Context, txRt.GetDb(), &txRt.Builder, item); insertErr != nil {
			return insertErr
		}
		var signalErr error
		revisions, signalErr = SignalVaultChanged(req.Context, txRt, payload.VaultID)
		return signalErr
	})
	if transactionErr != nil {
		return bungo.APIResponse{}, transactionErr
	}
	revision := revisions[user.ID]

	r.PublishChanges(req, revisions)
	r.audit(req, user.ID, "item_created", "item", item.ID, "")

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
	var payload itemWritePayload
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	item, access, itemErr := r.loadAuthorisedItem(req, user.ID, payload.ID)
	if itemErr != nil {
		return apiError(404, "Item not found."), nil
	}
	if access.Role != "owner" {
		return apiError(403, "Members can view this vault but not change it."), nil
	}
	if envErr := validateItemEnvelopes(&payload); envErr != nil {
		return apiError(400, envErr.Error()), nil
	}

	var revisions map[string]int64
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		if updateErr := database.UpdateItemBlobs(req.Context, txRt.GetDb(), &txRt.Builder,
			item.ID, payload.Overview, payload.Details); updateErr != nil {
			return updateErr
		}
		var signalErr error
		revisions, signalErr = SignalVaultChanged(req.Context, txRt, item.VaultID)
		return signalErr
	})
	if transactionErr != nil {
		return bungo.APIResponse{}, transactionErr
	}
	revision := revisions[user.ID]

	r.PublishChanges(req, revisions)
	r.audit(req, user.ID, "item_updated", "item", item.ID, "")

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
	var payload struct {
		ID string `json:"id"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	item, access, itemErr := r.loadAuthorisedItem(req, user.ID, payload.ID)
	if itemErr != nil {
		return apiError(404, "Item not found."), nil
	}
	if access.Role != "owner" {
		return apiError(403, "Members can view this vault but not change it."), nil
	}

	var revisions map[string]int64
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		if mutateErr := mutate(req.Context, txRt.GetDb(), &txRt.Builder, item.ID); mutateErr != nil {
			return mutateErr
		}
		var signalErr error
		revisions, signalErr = SignalVaultChanged(req.Context, txRt, item.VaultID)
		return signalErr
	})
	if transactionErr != nil {
		return bungo.APIResponse{}, transactionErr
	}
	revision := revisions[user.ID]

	r.PublishChanges(req, revisions)
	r.audit(req, user.ID, action, "item", item.ID, "")

	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"ok": true, "revision": revision},
	}, nil
}

// requireVaultAccess loads the access row binding the user to the vault.
func (r *Runtime) requireVaultAccess(req *bungo.Request, userID, vaultID string) (*models.VaultAccess, error) {
	access, accessErr := database.SelectVaultAccess(req.Context, r.GetDb(), &r.Builder, userID, vaultID)
	if accessErr != nil {
		if !errors.Is(accessErr, sql.ErrNoRows) {
			r.Log.Error("vault access lookup failed", zap.Error(accessErr))
		}
		return nil, accessErr
	}
	return access, nil
}

// loadAuthorisedItem loads an item and verifies the user can access its
// vault, collapsing "missing" and "not yours" into one error so responses
// never reveal foreign item ids exist. The access row rides along so callers
// can gate mutations on its role.
func (r *Runtime) loadAuthorisedItem(req *bungo.Request, userID, itemID string) (*models.Item, *models.VaultAccess, error) {
	if strings.TrimSpace(itemID) == "" {
		return nil, nil, sql.ErrNoRows
	}
	item, itemErr := database.SelectItemByID(req.Context, r.GetDb(), &r.Builder, itemID)
	if itemErr != nil {
		if !errors.Is(itemErr, sql.ErrNoRows) {
			r.Log.Error("item lookup failed", zap.Error(itemErr))
		}
		return nil, nil, itemErr
	}
	access, accessErr := r.requireVaultAccess(req, userID, item.VaultID)
	if accessErr != nil {
		return nil, nil, accessErr
	}
	return item, access, nil
}

// validateItemEnvelopes structurally checks an item write's three envelopes.
func validateItemEnvelopes(payload *itemWritePayload) error {
	if len(payload.WrappedItemKey) > 0 {
		if envErr := models.ValidateCipherEnvelope(payload.WrappedItemKey, 1024); envErr != nil {
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
