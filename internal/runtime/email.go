package runtime

import (
	"context"
	"fmt"

	"vault3/internal/config"
	"vault3/internal/integrations"

	"go.uber.org/zap"
)

// Email delivery. Every outbound email names a template by its short name
// (e.g. "NEW_DEVICE_LOGIN"), resolved to a subject + HTML body in
// email_templates.go and rendered server-side — Mailgun only transports, and
// the client that talks to it lives in internal/integrations/mailgun.go.
// frontendUrl, supportEmail, firstName and email are injected into every
// render, with caller-supplied keys winning.
//
// Two gates sit in front of every send:
//   - the email_sending_enabled platform setting (admin-controlled): off
//     replaces the send with an info log naming template, trigger and
//     recipient, so local dev sees exactly what would have gone out;
//   - the Mailgun credentials themselves (see config.MailgunAPIKeyEnv and
//     friends), which are OPTIONAL config: while any is empty the send
//     degrades to a warn log. They are deliberately absent from
//     REQUIRED_ENV_VARS so a dev stack boots with the keys blank; fill them
//     in once the vault3.com domain is verified.
//
// Both gates are policy, which is why they are here and not in the client:
// integrations/ knows how to send an email, not whether this deployment
// should.

// SendTemplateEmail sends one templated email. template is the short
// template name; trigger is the notification kind (or other cause) recorded
// in logs. Returns an error only for a real delivery failure; a disabled
// toggle, missing credentials, or an unknown template name is handled here
// (logged and skipped) so callers never branch on configuration.
func (r *Runtime) SendTemplateEmail(ctx context.Context, toEmail, toName, template, trigger string, data map[string]any) error {
	if toEmail == "" {
		return fmt.Errorf("send email %s: recipient has no email address", template)
	}

	if !r.EmailSendingEnabled(ctx) {
		r.Log.Info("email sending disabled; skipping email",
			zap.String("template", template),
			zap.String("trigger", trigger),
			zap.String("to", toEmail),
		)
		return nil
	}

	if !r.Integrations.Mailgun.Configured() {
		r.Log.Warn("mailgun not configured; skipping email",
			zap.String("template", template),
			zap.String("trigger", trigger),
			zap.String("to", toEmail),
		)
		return nil
	}

	merged := map[string]any{
		"frontendUrl":  config.SITE_URL,
		"supportEmail": r.Config.MustString("SUPPORT_EMAIL_STRING"),
		"firstName":    toName,
		"email":        toEmail,
	}
	for key, value := range data {
		merged[key] = value
	}

	subject, htmlBody, renderErr := renderEmailTemplate(template, merged)
	if renderErr != nil {
		r.Log.Error("email template render failed; skipping email",
			zap.String("template", template),
			zap.String("trigger", trigger),
			zap.Error(renderErr),
		)
		return nil
	}

	if sendErr := r.Integrations.Mailgun.Send(ctx, integrations.Email{
		ToEmail: toEmail,
		ToName:  toName,
		Subject: subject,
		HTML:    htmlBody,
	}); sendErr != nil {
		return fmt.Errorf("send email %s: %w", template, sendErr)
	}

	r.Log.Info("email sent",
		zap.String("template", template),
		zap.String("trigger", trigger),
		zap.String("to", toEmail),
	)
	return nil
}
