package runtime

import (
	"strings"

	"vault3/internal/config"
	"vault3/internal/database"
	"vault3/internal/models"

	bungo "github.com/piotr-nierobisz/BunGo"
	"go.uber.org/zap"
)

type contactPayload struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Message string `json:"message"`
}

// ContactSubmitAPI persists a contact form submission. It is public and
// unauthenticated, so flood protection is the production reverse proxy's job
// (see middleware.go) — nothing here rate-limits.
func (r *Runtime) ContactSubmitAPI(req *bungo.Request) (bungo.APIResponse, error) {
	payload, deny := decodeBody[contactPayload](req)
	if deny != nil {
		return *deny, nil
	}

	name := strings.TrimSpace(payload.Name)
	email := strings.TrimSpace(payload.Email)
	message := strings.TrimSpace(payload.Message)
	if name == "" || email == "" || message == "" {
		return apiError(400, "Name, email and message are required"), nil
	}
	if len(name) > config.MaxContactNameChars || len(message) > config.MaxContactMessageChars || !emailPattern.MatchString(strings.ToLower(email)) {
		return apiError(400, "Please check the form and try again"), nil
	}

	inquiry := &models.ContactInquiry{
		ID:        newUUID(),
		Name:      name,
		Email:     email,
		Message:   message,
		IPAddress: ClientIP(req),
		UserAgent: req.Headers["User-Agent"],
	}

	if insertErr := database.InsertContactInquiry(req.Context, r.GetDb(), &r.Builder, r.Cipher, inquiry); insertErr != nil {
		r.Log.Error("contact inquiry insert failed", zap.Error(insertErr))
		return apiError(500, "We couldn't save your message. Please try again shortly."), nil
	}

	r.Log.Info("contact inquiry received", zap.String("email", email))
	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]string{"message": "Thanks — we'll get back to you soon."},
	}, nil
}
