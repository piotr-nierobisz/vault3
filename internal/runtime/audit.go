package runtime

import (
	"vault3/internal/database"
	"vault3/internal/models"

	bungo "github.com/piotr-nierobisz/BunGo"
	"go.uber.org/zap"
)

// audit appends one row to the security trail, capturing the request's IP
// and user agent. Log-and-continue by design: the trail must never take down
// the action it records. Item content never appears here — the server never
// has it; detail is a short contextual string (encrypted at rest).
func (r *Runtime) audit(req *bungo.Request, userID, action, entityType, entityID, detail string) {
	entry := &models.AuditLog{
		ID:         newUUID(),
		UserID:     userID,
		Action:     action,
		EntityType: entityType,
		EntityID:   entityID,
		IPAddress:  ClientIP(req),
		UserAgent:  req.Headers["User-Agent"],
		Detail:     detail,
	}
	if insertErr := database.InsertAuditLog(req.Context, r.GetDb(), &r.Builder, r.Cipher, entry); insertErr != nil {
		r.Log.Error("audit: insert failed", zap.String("action", action), zap.Error(insertErr))
	}
}
