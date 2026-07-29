package jobs

import (
	"context"
	"time"

	"vault3/internal/config"
	"vault3/internal/database"
	"vault3/internal/runtime"

	"go.uber.org/zap"
)

// PurgeExpiredSessions removes session rows past their expiry. The delete's
// WHERE clause is the claim, so overlapping runs are harmless.
func PurgeExpiredSessions(ctx context.Context, rt *runtime.Runtime) error {
	purged, purgeErr := database.DeleteExpiredSessions(ctx, rt.GetDb(), &rt.Builder)
	if purgeErr != nil {
		return purgeErr
	}
	if purged > 0 {
		rt.Log.Info("expired sessions purged", zap.Int64("count", purged))
	}
	return nil
}

// PurgeTrashedItems permanently deletes items whose trash retention has
// lapsed. Users are told trash empties itself after the retention window;
// this is the job that honours it.
func PurgeTrashedItems(ctx context.Context, rt *runtime.Runtime) error {
	cutoff := time.Now().Add(-config.TrashRetention)
	purged, purgeErr := database.PurgeTrashedItems(ctx, rt.GetDb(), &rt.Builder, cutoff)
	if purgeErr != nil {
		return purgeErr
	}
	if purged > 0 {
		rt.Log.Info("trashed items purged", zap.Int64("count", purged))
	}
	return nil
}

// PurgeLapsedSharing deletes share links and vault invites whose expiry,
// revocation or acceptance is older than the grace window, so dead sharing
// rows (and their wrapped keys) do not linger.
func PurgeLapsedSharing(ctx context.Context, rt *runtime.Runtime) error {
	cutoff := time.Now().Add(-config.SharingPurgeGrace)
	links, linksErr := database.PurgeLapsedShareLinks(ctx, rt.GetDb(), &rt.Builder, cutoff)
	if linksErr != nil {
		return linksErr
	}
	invites, invitesErr := database.PurgeLapsedVaultInvites(ctx, rt.GetDb(), &rt.Builder, cutoff)
	if invitesErr != nil {
		return invitesErr
	}
	if links > 0 || invites > 0 {
		rt.Log.Info("lapsed sharing purged", zap.Int64("share_links", links), zap.Int64("invites", invites))
	}
	return nil
}

// ClearExpiredAuthTokens nulls lapsed verification and account-reset token
// hashes so stale credentials do not linger.
func ClearExpiredAuthTokens(ctx context.Context, rt *runtime.Runtime) error {
	cleared, clearErr := database.ClearExpiredAuthTokens(ctx, rt.GetDb(), &rt.Builder)
	if clearErr != nil {
		return clearErr
	}
	if cleared > 0 {
		rt.Log.Info("expired auth tokens cleared", zap.Int64("rows", cleared))
	}
	return nil
}
