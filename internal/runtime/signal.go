package runtime

import (
	"context"

	"vault3/internal/database"

	bungo "github.com/piotr-nierobisz/BunGo"
	"go.uber.org/zap"
)

// Change signals: when one signed-in client mutates anything about the user
// (an item, the profile, a session), every OTHER connected client should
// refresh. The pieces:
//
//   - vault3_user.Revision — a monotonic counter bumped in the SAME
//     transaction as each mutation (database.BumpUserRevision), so a rolled
//     back change never signals anyone and a delivered signal always has
//     committed data to fetch.
//   - ChangeSignalPath — a BunGo WebSocket route. Each connection subscribes
//     to its own user's topic and receives {revision, origin} frames; BunGo
//     owns the upgrade, keepalive and teardown, so nothing here touches
//     net/http.
//   - X-Vault3-Client — a per-tab id the client sends with mutations and
//     matches against event origins, so the tab that made the change skips
//     the redundant refetch while every other tab refreshes.
//
// The hub is process-local, which is correct for the single-web-container
// deployment. If the web tier ever scales horizontally, put a Postgres
// LISTEN/NOTIFY (or Redis) broadcaster in front of the hub's Publish call —
// no caller changes.

// ChangeSignal is one published change event.
type ChangeSignal struct {
	Revision int64  `json:"revision"`
	Origin   string `json:"origin,omitempty"`
}

// ClientIDHeader carries the per-tab client id on mutating requests, echoed
// back as the event origin.
const ClientIDHeader = "X-Vault3-Client"

// ChangeSignalPath is the WebSocket route clients subscribe to. web/lib/sync.ts
// dials the same path.
const ChangeSignalPath = "/ws/changes"

// signalMaxFrameBytes caps inbound frames. Clients never send anything on this
// socket, so the limit only has to leave room for a control frame.
const signalMaxFrameBytes = 1024

// signalTopic is the hub topic carrying one user's signals.
func signalTopic(userID string) string {
	return "user:" + userID
}

// ChangeSignalRoute is the WebSocket route definition main.go registers. It
// carries require_auth rather than resolving the session itself, so the rules
// admitting a listener cannot drift from the ones guarding every other
// authenticated route — the layer runs before the upgrade, so an unauthorized
// client gets a plain 401 and never opens a socket.
//
// Cross-site WebSocket hijacking is the attack this must not be open to:
// browsers attach the session cookie to a cross-origin ws:// handshake and no
// CORS preflight stands in the way. BunGo's default origin policy (same host,
// absent Origin allowed for non-browser clients) is exactly the check that
// closes it, and is deliberately left unoverridden here.
func (r *Runtime) ChangeSignalRoute() bungo.WebSocketRoute {
	return bungo.WebSocketRoute{
		Path:           ChangeSignalPath,
		SecurityLayer:  []string{"require_auth"},
		MaxMessageSize: signalMaxFrameBytes,
		OnConnect:      r.subscribeToChanges,
	}
}

// subscribeToChanges runs once per accepted connection: it joins the connection
// to its user's topic and sends the current revision, so a client that
// reconnects after a dropped socket can tell whether it missed a change while
// away.
func (r *Runtime) subscribeToChanges(conn *bungo.WebSocketConn) {
	req := conn.Request()
	user := CurrentUser(req)
	if user == nil || r.Signals == nil {
		// require_auth makes this unreachable; closing beats a silent socket.
		_ = conn.Close()
		return
	}

	r.Signals.Subscribe(conn, signalTopic(user.ID))

	revision, revisionErr := database.SelectUserRevision(req.Context, r.GetDb(), &r.Builder, user.ID)
	if revisionErr != nil {
		r.Log.Warn("change signal: initial revision lookup failed", zap.Error(revisionErr))
		return
	}
	if sendErr := conn.SendJSON(ChangeSignal{Revision: revision}); sendErr != nil {
		r.Log.Warn("change signal: initial send failed", zap.Error(sendErr))
	}
}

// SignalUserChanged bumps the user's revision and returns the new value.
//
// It must run INSIDE the mutation's transaction, and its result must not be
// published until that transaction commits. Handlers therefore do not call
// this directly — commitUserChange owns the sequencing. Reach for it only when
// building another commit helper.
func SignalUserChanged(ctx context.Context, txRt *Runtime, userID string) (int64, error) {
	return database.BumpUserRevision(ctx, txRt.GetDb(), &txRt.Builder, userID)
}

// SignalVaultChanged bumps the revision of EVERY user with access to a vault,
// because a mutation in a shared vault must reach every member's devices, not
// just the actor's. Same rules as SignalUserChanged: inside the transaction,
// published only after commit, and driven by commitVaultChange rather than by
// handlers directly.
func SignalVaultChanged(ctx context.Context, txRt *Runtime, vaultID string) (map[string]int64, error) {
	userIDs, idsErr := database.SelectVaultUserIDs(ctx, txRt.GetDb(), &txRt.Builder, vaultID)
	if idsErr != nil {
		return nil, idsErr
	}
	return signalUsersChanged(ctx, txRt, userIDs)
}

// signalUsersChanged bumps a known set of users (used when the audience must
// be captured before the mutation removes rows, e.g. deleting a vault).
func signalUsersChanged(ctx context.Context, txRt *Runtime, userIDs []string) (map[string]int64, error) {
	revisions := make(map[string]int64, len(userIDs))
	for _, userID := range userIDs {
		revision, bumpErr := database.BumpUserRevision(ctx, txRt.GetDb(), &txRt.Builder, userID)
		if bumpErr != nil {
			return nil, bumpErr
		}
		revisions[userID] = revision
	}
	return revisions, nil
}

// --- Commit pipeline --------------------------------------------------------
//
// Nearly every mutation in the app has the same shape: change something, bump
// the affected users' revisions in the SAME transaction, then — once it has
// actually committed — publish the change signal and append an audit row.
//
// The ordering is not stylistic. Bumping inside the transaction is what makes
// a rolled-back change unable to signal anyone; publishing only after commit
// is what stops a client being told to refetch data that was never written.
// Spelled out at each call site, those are two invariants a handler can get
// wrong silently. The three helpers below own them instead, so a handler
// supplies only the mutation and cannot sequence it incorrectly.
//
// Pick by audience:
//
//	commitUserChange     — only the acting user sees it (profile, credentials)
//	commitVaultChange    — everyone with access, resolved after the mutation
//	commitAudienceChange — audience captured BEFORE the mutation, for changes
//	                       that remove the very access rows identifying it

// commitUserChange applies a mutation affecting one user and returns their new
// revision.
func (r *Runtime) commitUserChange(
	req *bungo.Request,
	userID, action, entityType, entityID string,
	mutate func(txRt *Runtime) error,
) (int64, error) {
	var revision int64
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		if mutateErr := mutate(txRt); mutateErr != nil {
			return mutateErr
		}
		var bumpErr error
		revision, bumpErr = SignalUserChanged(req.Context, txRt, userID)
		return bumpErr
	})
	if transactionErr != nil {
		return 0, transactionErr
	}
	r.PublishChange(req, userID, revision)
	r.audit(req, userID, action, entityType, entityID, "")
	return revision, nil
}

// commitVaultChange applies a mutation to a vault and signals every user who
// can reach it. The audience is resolved after the mutation runs, so a member
// added by it is included and one removed by it is not.
func (r *Runtime) commitVaultChange(
	req *bungo.Request,
	actorUserID, vaultID, action, entityType, entityID string,
	mutate func(txRt *Runtime) error,
) (map[string]int64, error) {
	var revisions map[string]int64
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		if mutateErr := mutate(txRt); mutateErr != nil {
			return mutateErr
		}
		var signalErr error
		revisions, signalErr = SignalVaultChanged(req.Context, txRt, vaultID)
		return signalErr
	})
	if transactionErr != nil {
		return nil, transactionErr
	}
	r.PublishChanges(req, revisions)
	r.audit(req, actorUserID, action, entityType, entityID, "")
	return revisions, nil
}

// commitAudienceChange applies a mutation and signals a caller-supplied set of
// users. Use it when the mutation destroys the access rows that identify the
// audience — deleting a vault, removing a member — so the list must be
// captured before the change and cannot be derived after it.
func (r *Runtime) commitAudienceChange(
	req *bungo.Request,
	actorUserID string,
	audience []string,
	action, entityType, entityID string,
	mutate func(txRt *Runtime) error,
) (map[string]int64, error) {
	var revisions map[string]int64
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		if mutateErr := mutate(txRt); mutateErr != nil {
			return mutateErr
		}
		var signalErr error
		revisions, signalErr = signalUsersChanged(req.Context, txRt, audience)
		return signalErr
	})
	if transactionErr != nil {
		return nil, transactionErr
	}
	r.PublishChanges(req, revisions)
	r.audit(req, actorUserID, action, entityType, entityID, "")
	return revisions, nil
}

// PublishChanges fans out a set of committed per-user revisions. Call only
// after the transaction that bumped them commits.
func (r *Runtime) PublishChanges(req *bungo.Request, revisions map[string]int64) {
	for userID, revision := range revisions {
		r.PublishChange(req, userID, revision)
	}
}

// PublishChange fans out a committed revision to the user's connected clients,
// tagging the originating client (from the request's X-Vault3-Client header) so
// it can skip its own echo. Call only after the transaction that bumped the
// revision commits.
func (r *Runtime) PublishChange(req *bungo.Request, userID string, revision int64) {
	if r.Signals == nil {
		return
	}
	publishErr := r.Signals.PublishJSON(signalTopic(userID), ChangeSignal{
		Revision: revision,
		Origin:   req.Headers[ClientIDHeader],
	})
	if publishErr != nil {
		r.Log.Warn("change signal: publish failed", zap.String("user_id", userID), zap.Error(publishErr))
	}
}
