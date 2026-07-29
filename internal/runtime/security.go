package runtime

import (
	"strings"

	bungo "github.com/piotr-nierobisz/BunGo"
)

// ClientIP extracts the originating IP from common proxy headers, falling
// back to an empty string when none is present. The dev stack has no proxy,
// so WrapHandler injects X-Real-Ip from the socket address before requests
// reach BunGo. Exported so handlers in sibling packages share one definition.
func ClientIP(req *bungo.Request) string {
	if xff := req.Headers["X-Forwarded-For"]; xff != "" {
		if comma := strings.IndexByte(xff, ','); comma >= 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	return req.Headers["X-Real-Ip"]
}
