package runtime

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// HTTP middleware wrapped around the BunGo handler by main.go (via
// engine.CreateHandler — public framework API, no framework changes). BunGo
// itself offers no response-header or request-rejection hooks, so a password
// manager's transport hygiene lives here:
//
//   - security headers (CSP, frame denial, referrer policy, HSTS in prod)
//   - cross-origin rejection for state-changing requests (defence in depth
//     behind the session cookie's SameSite=Lax)
//   - X-Real-Ip injection from the socket address, so ClientIP works in dev
//     where no reverse proxy sets forwarding headers
//
// Rate limiting is deliberately NOT here. An in-process fixed-window counter
// keyed on the socket address is the wrong layer for it: behind the TLS
// reverse proxy that terminates production traffic every request arrives from
// the proxy's address, so one bucket would throttle the whole platform at
// once. Per-IP throttling of the auth endpoints belongs to the proxy, which
// sees the real client address and survives an app restart.

// WrapHandler applies the middleware stack to the compiled BunGo handler.
func (r *Runtime) WrapHandler(inner http.Handler) http.Handler {
	production := r.Config.MustBool("PRODUCTION_BOOL")

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Socket-derived client IP for handlers. Only set when no proxy
		// header is present, so a real X-Forwarded-For from the production
		// edge wins.
		ip := socketIP(req)
		if req.Header.Get("X-Forwarded-For") == "" && req.Header.Get("X-Real-Ip") == "" && ip != "" {
			req.Header.Set("X-Real-Ip", ip)
		}

		securityHeaders(w, production)

		if isCrossOriginWrite(req) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Cross-origin request refused."}`))
			return
		}

		inner.ServeHTTP(w, req)
	})
}

// securityHeaders sets the transport-security response headers on every
// response. The CSP allows inline script/style because BunGo injects the
// compiled view bundles and __BUNGO_DATA__ as inline <script> tags; the
// meaningful protections here are the connect/frame/object restrictions and
// base-uri/form-action pinning.
//
// Note there is no CDN in any directive. Every dependency (React, Tailwind)
// is compiled in or self-hosted, and remote imports are resolved at build
// time, so nothing is fetched from a third party at runtime. Whitelisting a
// public package host would hand any future injection foothold both a
// script source and an exfiltration channel for the unlocked keys — for this
// product that is the whole ballgame, so the allowance stays absent until a
// dependency genuinely needs it.
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
func securityHeaders(w http.ResponseWriter, production bool) {
	h := w.Header()
	h.Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; "+
			"worker-src 'self'; "+
			"style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; "+
			"connect-src 'self'; frame-ancestors 'none'; object-src 'none'; "+
			"base-uri 'self'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if production {
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
}

// isCrossOriginWrite reports whether a state-changing request originated from
// another site. CSRF needs a browser to attach the session cookie ambiently,
// and browsers label such requests: Sec-Fetch-Site on every modern engine,
// and an Origin header on any method other than GET/HEAD. Checking those is
// equivalent protection to a synchroniser token without the token plumbing,
// and it composes with the cookie's SameSite=Lax rather than relying on it
// alone.
//
// A request carrying neither header did not come from a browser, so it has no
// ambient credentials to abuse and is not a CSRF vector; those pass, which
// also keeps curl usable against a dev server.
func isCrossOriginWrite(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}

	// "none" means the user initiated it directly (bookmark, typed URL);
	// "same-origin" is our own page. Anything else is another site.
	if site := req.Header.Get("Sec-Fetch-Site"); site != "" {
		return site != "same-origin" && site != "none"
	}

	// Compare hosts rather than full origins: the scheme a TLS-terminating
	// proxy forwards need not match the one the browser used.
	if origin := req.Header.Get("Origin"); origin != "" {
		parsed, parseErr := url.Parse(origin)
		return parseErr != nil || !strings.EqualFold(parsed.Host, req.Host)
	}

	return false
}

func socketIP(req *http.Request) string {
	host, _, splitErr := net.SplitHostPort(req.RemoteAddr)
	if splitErr != nil {
		return strings.TrimSpace(req.RemoteAddr)
	}
	return host
}
