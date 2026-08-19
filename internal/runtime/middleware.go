package runtime

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"vault3/internal/config"
	"vault3/internal/integrations"

	bungo "github.com/piotr-nierobisz/BunGo"
)

// What is left of the hand-rolled transport layer, and why.
//
// BunGo v0.5.x absorbed most of what used to live here: security headers are
// now srv.SetResponseHeaders (see SecurityHeaders below, applied in
// cmd/vault3/main.go), and cross-origin rejection is now ApiRoute.CheckOrigin
// (SameOriginWrite below, attached to every state-changing route by the api()
// helpers). Both are stated once and enforced by the framework on every
// response and every route, rather than by a wrapper that a future listener
// could be assembled without.
//
// WrapHandler survives for the one job the framework genuinely cannot do:
// bungo.Request carries headers, not the connection, so a handler has no way
// to see the socket address. The dev stack has no reverse proxy to synthesise
// forwarding headers, so they are synthesised here, before BunGo translates
// the request.
//
// Rate limiting is still deliberately NOT here, and the arrival of 429-capable
// security layers does not change the reasoning. An in-process fixed-window
// counter keyed on the socket address is the wrong layer: behind the TLS
// reverse proxy that terminates production traffic every request arrives from
// the proxy's address, so one bucket would throttle the whole platform at
// once. Per-IP throttling of the auth endpoints belongs to the proxy, which
// sees the real client address and survives an app restart.

// hostHeader carries the connection's Host through to bungo.Request, which has
// no field for it. WrapHandler overwrites it unconditionally on every request,
// so a client cannot forge one to talk its way past SameOriginWrite.
const hostHeader = "X-Vault3-Host"

// WrapHandler applies the pre-translation request fixups to the compiled BunGo
// handler. It sets no response headers and rejects nothing — those moved into
// BunGo itself.
func (r *Runtime) WrapHandler(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Socket-derived client IP for handlers. Only set when no proxy header
		// is present, so a real X-Forwarded-For from the production edge wins.
		ip := socketIP(req)
		if req.Header.Get("X-Forwarded-For") == "" && req.Header.Get("X-Real-Ip") == "" && ip != "" {
			req.Header.Set("X-Real-Ip", ip)
		}

		// net/http promotes Host out of the header map, so it would otherwise
		// be invisible to a bungo.Request. Set, never Add: whatever the client
		// sent under this name is discarded.
		req.Header.Set(hostHeader, req.Host)

		// The login and join documents — and only those two — are served the
		// CSP that admits the Turnstile widget. See turnstilePages.
		if turnstilePages[req.URL.Path] {
			inner.ServeHTTP(&cspWriter{ResponseWriter: w, policy: contentSecurityPolicy(true)}, req)
			return
		}

		inner.ServeHTTP(w, req)
	})
}

// turnstilePages are the only paths whose responses carry the widened policy.
// Both are anonPage GET routes, so nothing here needs to survive a WebSocket
// upgrade or a streaming response.
var turnstilePages = map[string]bool{
	config.LoginPath: true,
	config.JoinPath:  true,
}

// cspWriter rewrites Content-Security-Policy on the way out.
//
// BunGo applies srv.SetResponseHeaders in a wrapper INSIDE CreateHandler, so a
// header set before inner.ServeHTTP is overwritten and one set afterwards
// arrives too late. Swapping the value at the moment the response commits is
// what is left, and it is a small price for keeping a third-party script host
// off every other page in the app — /app above all, where a vault is unlocked
// and every item's plaintext is in memory.
//
// PageRoute has no per-response header hook; if BunGo ever grows one, this
// belongs there instead.
type cspWriter struct {
	http.ResponseWriter
	policy  string
	applied bool
}

func (c *cspWriter) apply() {
	if c.applied {
		return
	}
	c.applied = true
	c.Header().Set("Content-Security-Policy", c.policy)
}

func (c *cspWriter) WriteHeader(status int) {
	c.apply()
	c.ResponseWriter.WriteHeader(status)
}

// Write covers the handler that never calls WriteHeader: net/http would
// commit an implicit 200 on the underlying writer and the swap would be lost.
func (c *cspWriter) Write(b []byte) (int, error) {
	c.apply()
	return c.ResponseWriter.Write(b)
}

// SecurityHeaders returns the transport-security headers BunGo emits on every
// response — pages, APIs, static files and the WebSocket handshake alike —
// via srv.SetResponseHeaders in cmd/vault3/main.go.
//
// The CSP allows inline script/style because BunGo injects __BUNGO_DATA__ (and,
// outside production, the compiled view bundles) as inline <script> tags; the
// meaningful protections here are the connect/frame/object restrictions and
// base-uri/form-action pinning.
//
// Note there is no CDN in any directive, and there must not be one. Every
// dependency (React, Tailwind) is compiled in or self-hosted, and remote
// imports are resolved at build time, so nothing is fetched from a third party
// at runtime. Whitelisting a public package host would hand any future
// injection foothold both a script source and an exfiltration channel for the
// unlocked keys — for this product that is the whole ballgame.
//
// The single exception is Cloudflare Turnstile, and the shape of the exception
// is the argument for it: the allowance exists only in the variant policy
// contentSecurityPolicy(true) builds, only on the two pre-vault documents in
// turnstilePages, only for script-src and frame-src, and never on /app. It is
// a real cost — Cloudflare becomes a trusted script origin on the page where
// the encryption key is derived — accepted for a bot check on the two
// endpoints anyone can call without an account. Nothing else may follow it in
// here without the same accounting.
//
// connect-src 'self' covers the change-signal WebSocket: CSP resolves a ws://
// or wss:// URL against the document's origin, so a same-origin socket needs
// no separate ws: allowance and adding one would only widen the directive.
//
// 'wasm-unsafe-eval' is the one keyword that has been added deliberately, for
// the Argon2id key-derivation module (web/lib/argon2.ts). Its name invites
// misreading: it does not permit eval(), new Function(), or any JavaScript
// text-to-code path. It permits exactly one thing — compiling WebAssembly —
// and it exists as a separate keyword precisely so a page can do that without
// the far broader 'unsafe-eval'. The module it admits is same-origin, pinned
// by digest, and reproducible from source in this repository.
//
// worker-src is stated rather than left to fall back through child-src and
// script-src, because what those fall back to is 'unsafe-inline', and a
// reader checking whether an injected inline script could spawn a worker
// should not have to reason through a fallback chain to find out.
func (r *Runtime) SecurityHeaders() map[string]string {
	headers := map[string]string{
		"Content-Security-Policy": contentSecurityPolicy(false),
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Permissions-Policy":      "camera=(), microphone=(), geolocation=()",
	}
	if r.Config.MustBool("PRODUCTION_BOOL") {
		headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
	}
	return headers
}

// contentSecurityPolicy states the app's one policy, in the two forms it is
// served in. Stating both here rather than editing a string per page is the
// point: the login and join pages differ from every other page by exactly the
// two directives Turnstile requires and nothing else, and that has to stay
// readable as a difference.
//
// What the widget needs, and why it needs no more: script-src for api.js,
// which must come from Cloudflare's origin to be solvable, and frame-src for
// the challenge iframe it plants. connect-src stays 'self' — the iframe makes
// its own requests from its own origin, where this page's policy does not
// reach, so widening it would open an exfiltration channel and buy the widget
// nothing. style-src already permits the inline styles it injects.
//
// frame-src is stated rather than left to fall through default-src for the
// same reason worker-src is: a reader checking what this page may embed
// should find the answer in the directive, not in a fallback chain.
func contentSecurityPolicy(turnstile bool) string {
	scriptSrc := "'self' 'unsafe-inline' 'wasm-unsafe-eval'"
	frameSrc := "'self'"
	if turnstile {
		scriptSrc += " " + integrations.TurnstileOrigin
		frameSrc += " " + integrations.TurnstileOrigin
	}
	return "default-src 'self'; script-src " + scriptSrc + "; " +
		"worker-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; " +
		"connect-src 'self'; frame-src " + frameSrc + "; " +
		"frame-ancestors 'none'; object-src 'none'; " +
		"base-uri 'self'; form-action 'self'"
}

// SameOriginWrite is the ApiRoute.CheckOrigin hook the api() helpers attach to
// every state-changing route: it reports whether the request may proceed, and
// BunGo answers 403 Forbidden before any security layer runs when it does not.
//
// CSRF needs a browser to attach the session cookie ambiently, and browsers
// label such requests: Sec-Fetch-Site on every modern engine, and an Origin
// header on any method other than GET/HEAD. Checking those is equivalent
// protection to a synchroniser token without the token plumbing, and it
// composes with the cookie's SameSite=Lax rather than relying on it alone.
//
// A request carrying neither header did not come from a browser, so it has no
// ambient credentials to abuse and is not a CSRF vector; those pass, which
// also keeps curl usable against a dev server.
//
// Only registrations for state-changing methods get this hook, so there is no
// method check here — GET routes never reach it.
func (r *Runtime) SameOriginWrite(req *bungo.Request) bool {
	// "none" means the user initiated it directly (bookmark, typed URL);
	// "same-origin" is our own page. Anything else is another site.
	if site := req.Headers["Sec-Fetch-Site"]; site != "" {
		return site == "same-origin" || site == "none"
	}

	// Compare hosts rather than full origins: the scheme a TLS-terminating
	// proxy forwards need not match the one the browser used.
	if origin := req.Headers["Origin"]; origin != "" {
		parsed, parseErr := url.Parse(origin)
		if parseErr != nil {
			return false
		}
		return strings.EqualFold(parsed.Host, req.Headers[hostHeader])
	}

	return true
}

func socketIP(req *http.Request) string {
	host, _, splitErr := net.SplitHostPort(req.RemoteAddr)
	if splitErr != nil {
		return strings.TrimSpace(req.RemoteAddr)
	}
	return host
}
