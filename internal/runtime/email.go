package runtime

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vault3/internal/config"

	"go.uber.org/zap"
)

// Email delivery via the Mailgun messages API. Every outbound email names a
// template by its short name (e.g. "NEW_DEVICE_LOGIN"), resolved to a
// subject + HTML body in email_templates.go and rendered server-side —
// Mailgun only transports. frontendUrl, supportEmail, firstName and email
// are injected into every render, with caller-supplied keys winning.
//
// Two gates sit in front of every send:
//   - the email_sending_enabled platform setting (admin-controlled): off
//     replaces the send with an info log naming template, trigger and
//     recipient, so local dev sees exactly what would have gone out;
//   - the Mailgun credentials themselves (MAILGUN_API_KEY_STRING,
//     MAILGUN_DOMAIN_STRING, MAILGUN_FROM_EMAIL_STRING), which are OPTIONAL
//     config: while any is empty the send degrades to a warn log. They are
//     deliberately absent from REQUIRED_ENV_VARS so a dev stack boots with
//     the keys blank; fill them in once the vault3.com domain is verified.

const mailgunAPIBase = "https://api.eu.mailgun.net/v3"

var mailgunHTTPClient = &http.Client{Timeout: 15 * time.Second}

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

	apiKey, hasKey := r.Config.LookupString("MAILGUN_API_KEY_STRING")
	domain, hasDomain := r.Config.LookupString("MAILGUN_DOMAIN_STRING")
	fromEmail, hasFrom := r.Config.LookupString("MAILGUN_FROM_EMAIL_STRING")
	if !hasKey || !hasDomain || !hasFrom {
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

	form := url.Values{}
	form.Set("from", fmt.Sprintf("%s <%s>", config.SITE_NAME, fromEmail))
	form.Set("to", strings.TrimSpace(toName+" <"+toEmail+">"))
	form.Set("subject", subject)
	form.Set("html", htmlBody)

	endpoint := fmt.Sprintf("%s/%s/messages", mailgunAPIBase, domain)
	httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if reqErr != nil {
		return fmt.Errorf("send email %s: build request: %w", template, reqErr)
	}
	httpReq.SetBasicAuth("api", apiKey)
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, doErr := mailgunHTTPClient.Do(httpReq)
	if doErr != nil {
		return fmt.Errorf("send email %s: %w", template, doErr)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("send email %s: Mailgun responded %d", template, resp.StatusCode)
	}

	r.Log.Info("email sent",
		zap.String("template", template),
		zap.String("trigger", trigger),
		zap.String("to", toEmail),
	)
	return nil
}
