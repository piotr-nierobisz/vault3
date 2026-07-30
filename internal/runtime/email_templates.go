package runtime

import (
	"bytes"
	"fmt"
	"html/template"
)

// Email templates, rendered server-side and handed to Mailgun as finished
// HTML. Each entry is a subject template plus a body fragment injected into
// the shared shell. Data keys available to every template: frontendUrl,
// supportEmail, firstName, email, plus whatever the triggering event adds
// (see notify.go).
//
// Copy rules match the product: precise, calm, no hype. Every security email
// says what happened, when, and what to do if it wasn't you.

type emailTemplate struct {
	Subject string
	Body    string
}

var emailTemplates = map[string]emailTemplate{
	"WELCOME": {
		Subject: "Welcome to Vault3",
		Body: `
			<h1>Your vault is ready{{if .firstName}}, {{.firstName}}{{end}}.</h1>
			<p>Everything you save is locked on your device before it reaches us. Your Master Password and Secret Phrase never leave your browser, so you are the only person who can open your vault.</p>
			<p><strong>Keep your Emergency Kit safe.</strong> It holds your Secret Phrase, and together with your Master Password it is the only way in. Nobody can let you back in without them — us included.</p>
			<p><a class="btn" href="{{.frontendUrl}}/app">Open your vault</a></p>`,
	},
	"EMAIL_VERIFICATION": {
		Subject: "Confirm your email address",
		Body: `
			<h1>Confirm your email.</h1>
			<p>Use the link below to confirm {{.email}} as the address on your Vault3 account. The link is valid for 24 hours and can be used once.</p>
			<p><a class="btn" href="{{.verifyUrl}}">Confirm email address</a></p>
			<p class="muted">If you didn't create a Vault3 account, you can ignore this email.</p>`,
	},
	"NEW_DEVICE_LOGIN": {
		Subject: "New sign-in to your Vault3 account",
		Body: `
			<h1>New sign-in detected.</h1>
			<p>Your Vault3 account was just opened from a device or network we haven't seen before.</p>
			<p class="detail">{{.loginDetail}}</p>
			<p>If this was you, there's nothing to do. If it wasn't, sign in, change your Master Password, and sign that device out under Settings → Security.</p>
			<p><a class="btn" href="{{.frontendUrl}}/app/settings">Review sessions</a></p>`,
	},
	"PASSWORD_CHANGED": {
		Subject: "Your Master Password was changed",
		Body: `
			<h1>Master Password changed.</h1>
			<p>The Master Password on your Vault3 account was just changed, and every other device was signed out.</p>
			<p>If this was you, there's nothing else to do. If it wasn't, then whoever did it holds both of your secrets — email <a href="mailto:{{.supportEmail}}">{{.supportEmail}}</a> straight away.</p>`,
	},
	"TWO_FACTOR_ENABLED": {
		Subject: "Two-factor authentication enabled",
		Body: `
			<h1>Two-factor authentication is on.</h1>
			<p>From now on, signing in to your Vault3 account also needs a code from your authenticator app.</p>
			<p class="muted">If you didn't enable this, contact <a href="mailto:{{.supportEmail}}">{{.supportEmail}}</a> right away.</p>`,
	},
	"TWO_FACTOR_DISABLED": {
		Subject: "Two-factor authentication disabled",
		Body: `
			<h1>Two-factor authentication is off.</h1>
			<p>Two-factor authentication was just removed from your Vault3 account. Sign-ins now require only your email, Master Password and Secret Phrase.</p>
			<p class="muted">If you didn't disable this, sign in and re-enable it from Settings → Security, then change your Master Password.</p>`,
	},
}

// emailShell is the shared HTML wrapper: dark, minimal, brand-consistent,
// safe for the lowest common denominator of email clients (inline styles,
// single column).
const emailShell = `<!doctype html>
<html>
<body style="margin:0;padding:0;background:#0a0a10;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a10;padding:32px 16px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;">
<tr><td style="padding:0 8px 24px 8px;">
	<span style="font-size:22px;font-weight:800;letter-spacing:-0.02em;color:#f4f2ff;">vault<span style="color:#8b7cf6;">3</span></span>
</td></tr>
<tr><td style="background:#131320;border:1px solid #232338;border-radius:14px;padding:32px;">
	<div style="color:#c7c4de;font-size:15px;line-height:1.65;">{{.__body}}</div>
</td></tr>
<tr><td style="padding:24px 8px;color:#5d5a78;font-size:12px;line-height:1.6;">
	Nothing from your vault ever appears in an email from us — we have no way to read it.<br>
	Questions? <a href="mailto:{{.supportEmail}}" style="color:#8b7cf6;">{{.supportEmail}}</a>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>`

// renderEmailTemplate resolves a short template name and renders subject and
// full HTML body with the merged data map. Unknown names error (the caller
// logs and skips — a typo'd template must not panic a request).
func renderEmailTemplate(name string, data map[string]any) (subject string, htmlBody string, err error) {
	entry, ok := emailTemplates[name]
	if !ok {
		return "", "", fmt.Errorf("unknown email template %q", name)
	}

	styledBody := `<style>
		h1 { color:#f4f2ff; font-size:20px; margin:0 0 16px 0; letter-spacing:-0.01em; }
		p { margin:0 0 16px 0; }
		a { color:#8b7cf6; }
		.btn { display:inline-block; background:#6d5ce6; color:#ffffff !important; text-decoration:none; font-weight:600; padding:12px 22px; border-radius:9px; }
		.muted { color:#5d5a78; font-size:13px; }
		.detail { background:#0a0a10; border:1px solid #232338; border-radius:9px; padding:12px 16px; font-family:ui-monospace,Menlo,monospace; font-size:13px; color:#a5a1c8; }
	</style>` + entry.Body

	bodyTmpl, bodyErr := template.New(name).Parse(styledBody)
	if bodyErr != nil {
		return "", "", fmt.Errorf("parse body template %s: %w", name, bodyErr)
	}
	var bodyBuf bytes.Buffer
	if execErr := bodyTmpl.Execute(&bodyBuf, data); execErr != nil {
		return "", "", fmt.Errorf("render body template %s: %w", name, execErr)
	}

	shellData := map[string]any{
		"__body":       template.HTML(bodyBuf.String()),
		"supportEmail": data["supportEmail"],
	}
	shellTmpl, shellErr := template.New("shell").Parse(emailShell)
	if shellErr != nil {
		return "", "", fmt.Errorf("parse email shell: %w", shellErr)
	}
	var out bytes.Buffer
	if execErr := shellTmpl.Execute(&out, shellData); execErr != nil {
		return "", "", fmt.Errorf("render email shell: %w", execErr)
	}

	subjTmpl, subjErr := template.New(name + "-subject").Parse(entry.Subject)
	if subjErr != nil {
		return "", "", fmt.Errorf("parse subject template %s: %w", name, subjErr)
	}
	var subjBuf bytes.Buffer
	if execErr := subjTmpl.Execute(&subjBuf, data); execErr != nil {
		return "", "", fmt.Errorf("render subject template %s: %w", name, execErr)
	}

	return subjBuf.String(), out.String(), nil
}
