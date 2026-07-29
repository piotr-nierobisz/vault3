package runtime

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTP middleware wrapped around the BunGo handler by main.go (via
// engine.CreateHandler — public framework API, no framework changes). BunGo
// itself offers no response-header or throttling hooks, so a password
// manager's transport hygiene lives here:
//
//   - security headers (CSP, frame denial, referrer policy, HSTS in prod)
//   - per-IP throttling of the authentication endpoints (proper 429s, which
//     a bungo security layer cannot produce — layers only yield 401)
//   - X-Real-Ip injection from the socket address, so ClientIP works in dev
//     where no reverse proxy sets forwarding headers

// authThrottlePaths are the unauthenticated endpoints worth brute-forcing;
// they share one strict per-IP bucket.
var authThrottlePaths = map[string]bool{
	"/api/v1/auth/params":              true,
	"/api/v1/auth/login":               true,
	"/api/v1/auth/register":            true,
	"/api/v1/auth/verify-email":        true,
	"/api/v1/auth/resend-verification": true,
	"/api/v1/auth/recover/request":     true,
	"/api/v1/auth/recover/confirm":     true,
	"/api/v1/contact":                  true,
	// Share redemption is public and token-guessable in principle; the same
	// bucket blunts brute force (tokens are 256-bit random regardless).
	"/api/v1/share/open": true,
}

// WrapHandler applies the middleware stack to the compiled BunGo handler.
func (r *Runtime) WrapHandler(inner http.Handler) http.Handler {
	production := r.Config.MustBool("PRODUCTION_BOOL")
	limiter := newIPRateLimiter(20, time.Minute)

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Socket-derived client IP for handlers and the limiter. Only set
		// when no proxy header is present, so a real X-Forwarded-For from
		// the production edge wins.
		ip := socketIP(req)
		if req.Header.Get("X-Forwarded-For") == "" && req.Header.Get("X-Real-Ip") == "" && ip != "" {
			req.Header.Set("X-Real-Ip", ip)
		}

		securityHeaders(w, production)

		if req.Method == http.MethodPost && authThrottlePaths[req.URL.Path] {
			if !limiter.allow(ip) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"message":"Too many attempts. Please wait a minute and try again."}`))
				return
			}
		}

		inner.ServeHTTP(w, req)
	})
}

// securityHeaders sets the transport-security response headers on every
// response. The CSP allows inline script/style because BunGo injects the
// compiled view bundles and __BUNGO_DATA__ as inline <script> tags; the
// meaningful protections here are the connect/frame/object restrictions and
// base-uri/form-action pinning.
func securityHeaders(w http.ResponseWriter, production bool) {
	h := w.Header()
	h.Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline' https://esm.sh; "+
			"style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; "+
			"connect-src 'self' https://esm.sh; frame-ancestors 'none'; object-src 'none'; "+
			"base-uri 'self'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if production {
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
}

func socketIP(req *http.Request) string {
	host, _, splitErr := net.SplitHostPort(req.RemoteAddr)
	if splitErr != nil {
		return strings.TrimSpace(req.RemoteAddr)
	}
	return host
}

// ipRateLimiter is a fixed-window per-IP counter: cheap, allocation-light,
// and honest about its purpose (blunting online brute force, not shaping
// traffic). Windows reset wholesale, which is fine at this granularity.
type ipRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	windowAt time.Time
	counts   map[string]int
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		limit:    limit,
		window:   window,
		windowAt: time.Now(),
		counts:   make(map[string]int),
	}
}

func (l *ipRateLimiter) allow(ip string) bool {
	if ip == "" {
		ip = "unknown"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.windowAt) >= l.window {
		l.windowAt = now
		l.counts = make(map[string]int)
	}
	l.counts[ip]++
	return l.counts[ip] <= l.limit
}
