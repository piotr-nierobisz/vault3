package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

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
//   - SignalHub — an in-process registry of subscriber channels per user.
//   - /events — a Server-Sent Events endpoint (native net/http, mounted by
//     main.go next to the BunGo mux, because BunGo responses cannot stream)
//     that pushes {revision, origin} events.
//   - X-Vault3-Client — a per-tab id the client sends with mutations and
//     matches against event origins, so the tab that made the change skips
//     the redundant refetch while every other tab refreshes.
//
// The hub is process-local, which is correct for the single-web-container
// deployment. If the web tier ever scales horizontally, put a Postgres
// LISTEN/NOTIFY (or Redis) broadcaster behind the same Publish/Subscribe
// surface — no caller changes.

// ChangeSignal is one published change event.
type ChangeSignal struct {
	Revision int64  `json:"revision"`
	Origin   string `json:"origin,omitempty"`
}

// ClientIDHeader carries the per-tab client id on mutating requests, echoed
// back as the event origin.
const ClientIDHeader = "X-Vault3-Client"

// SignalHub fans ChangeSignals out to each user's subscribers.
type SignalHub struct {
	mu   sync.Mutex
	subs map[string]map[chan ChangeSignal]struct{}
}

func NewSignalHub() *SignalHub {
	return &SignalHub{subs: make(map[string]map[chan ChangeSignal]struct{})}
}

// Subscribe registers a listener for one user's signals. The returned cancel
// function must be called when the listener goes away; the channel is
// buffered so a slow consumer drops intermediate signals rather than
// blocking publishers (the newest revision is all a client needs).
func (h *SignalHub) Subscribe(userID string) (<-chan ChangeSignal, func()) {
	ch := make(chan ChangeSignal, 8)
	h.mu.Lock()
	if h.subs[userID] == nil {
		h.subs[userID] = make(map[chan ChangeSignal]struct{})
	}
	h.subs[userID][ch] = struct{}{}
	h.mu.Unlock()

	cancel := func() {
		h.mu.Lock()
		if set, ok := h.subs[userID]; ok {
			delete(set, ch)
			if len(set) == 0 {
				delete(h.subs, userID)
			}
		}
		h.mu.Unlock()
	}
	return ch, cancel
}

// Publish delivers a signal to every subscriber of the user. Non-blocking:
// a full buffer means that subscriber is behind and will catch up from the
// next signal (or the heartbeat revision check).
func (h *SignalHub) Publish(userID string, signal ChangeSignal) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[userID] {
		select {
		case ch <- signal:
		default:
		}
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

// PublishChange fans out a committed revision, tagging the originating
// client (from the request's X-Vault3-Client header) so it can skip its own
// echo. Call only after the transaction that bumped the revision commits.
func (r *Runtime) PublishChange(req *bungo.Request, userID string, revision int64) {
	if r.Signals == nil {
		return
	}
	r.Signals.Publish(userID, ChangeSignal{
		Revision: revision,
		Origin:   req.Headers[ClientIDHeader],
	})
}

// EventsHandler is the SSE endpoint, mounted at /events by main.go on the
// native mux (outside BunGo, which cannot stream). It authenticates exactly
// like require_auth — session cookie, live user — then holds the connection
// open, pushing one "change" event per published signal and a comment
// heartbeat to defeat idle proxies. The initial event carries the current
// revision so a reconnecting client can detect anything it missed.
func (r *Runtime) EventsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, httpReq *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Reuse the bungo-shaped session resolution so the auth rules can
		// never drift from require_auth.
		breq := &bungo.Request{
			Context:  httpReq.Context(),
			Headers:  map[string]string{"Cookie": httpReq.Header.Get("Cookie")},
			Internal: map[string]any{},
		}
		session, user := r.resolveSession(breq)
		if user == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)

		signals, cancel := r.Signals.Subscribe(user.ID)
		defer cancel()

		writeEvent := func(signal ChangeSignal) bool {
			payload, marshalErr := json.Marshal(signal)
			if marshalErr != nil {
				return false
			}
			if _, writeErr := fmt.Fprintf(w, "event: change\ndata: %s\n\n", payload); writeErr != nil {
				return false
			}
			flusher.Flush()
			return true
		}

		// Opening event: the current revision, so the client can compare
		// against what it last saw and refetch if it missed anything while
		// disconnected.
		revision, revisionErr := database.SelectUserRevision(httpReq.Context(), r.GetDb(), &r.Builder, user.ID)
		if revisionErr != nil {
			r.Log.Warn("events: initial revision lookup failed", zap.Error(revisionErr))
		} else if !writeEvent(ChangeSignal{Revision: revision}) {
			return
		}

		heartbeat := time.NewTicker(25 * time.Second)
		defer heartbeat.Stop()

		r.Log.Debug("events: client connected", zap.String("user_id", user.ID), zap.String("session_id", session.ID))
		for {
			select {
			case <-httpReq.Context().Done():
				return
			case signal := <-signals:
				if !writeEvent(signal) {
					return
				}
			case <-heartbeat.C:
				if _, writeErr := fmt.Fprint(w, ": ping\n\n"); writeErr != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}
