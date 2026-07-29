// Package jobs is the background job scheduler: a standalone process
// (cmd/scheduler) that reuses the same Runtime as the web server to run
// expiry-driven housekeeping the request path cannot. Each job is
// idempotent, so a missed or repeated run only ever costs a little extra
// work.
package jobs

import (
	"context"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"vault3/internal/runtime"

	"go.uber.org/zap"
)

// job is one scheduled unit of work: a named function run once on startup
// and then on a fixed interval until the scheduler shuts down.
type job struct {
	name     string
	interval time.Duration
	run      func(ctx context.Context, rt *runtime.Runtime) error
}

// Run starts the scheduler and blocks until the process receives SIGINT or
// SIGTERM, then cancels the jobs and returns once they have drained. Each
// job runs once immediately (so a fresh deploy catches up on anything
// missed) and then on its own interval. Jobs run in their own goroutines and
// are safe to overlap: they use the pooled connection or WithTransaction
// (which copies the runtime rather than mutating the shared one). Never
// stash per-run state on the shared *Runtime.
func Run(rt *runtime.Runtime) {
	jobs := []job{
		{name: "purge_expired_sessions", interval: time.Hour, run: PurgeExpiredSessions},
		{name: "purge_trashed_items", interval: 24 * time.Hour, run: PurgeTrashedItems},
		{name: "clear_expired_auth_tokens", interval: 24 * time.Hour, run: ClearExpiredAuthTokens},
		{name: "purge_lapsed_sharing", interval: 24 * time.Hour, run: PurgeLapsedSharing},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rt.Log.Info("scheduler started", zap.Int("jobs", len(jobs)))

	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			runLoop(ctx, rt, j)
		}(j)
	}

	<-ctx.Done()
	rt.Log.Info("scheduler stopping; draining in-flight jobs")
	wg.Wait()
	rt.Log.Info("scheduler stopped")
}

// runLoop runs a job once immediately, then on every tick until shutdown.
func runLoop(ctx context.Context, rt *runtime.Runtime, j job) {
	runOnce(ctx, rt, j)
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runOnce(ctx, rt, j)
		}
	}
}

// runOnce executes one pass of a job, timing and logging the outcome at the
// boundary. It skips a pass that would begin during shutdown.
func runOnce(ctx context.Context, rt *runtime.Runtime, j job) {
	if ctx.Err() != nil {
		return
	}
	start := time.Now()
	if err := j.run(ctx, rt); err != nil {
		rt.Log.Error("scheduled job failed", zap.String("job", j.name), zap.Error(err))
		return
	}
	rt.Log.Info("scheduled job completed", zap.String("job", j.name), zap.Duration("took", time.Since(start)))
}
