package runtime

import bungo "github.com/piotr-nierobisz/BunGo"

// apiError builds a JSON error response in the standard {"message": …} shape
// every API handler returns. Centralised here so handlers express failures
// as apiError(400, "…") rather than re-declaring the bungo.APIResponse
// literal.
func apiError(status int, message string) bungo.APIResponse {
	return bungo.APIResponse{
		StatusCode: status,
		Body:       map[string]string{"message": message},
	}
}

// apiFieldError is apiError plus a "field" hint naming the offending form
// field, so multi-step clients (the /join wizard) can route the user back to
// the step that owns the field instead of showing a generic banner.
func apiFieldError(status int, message, field string) bungo.APIResponse {
	return bungo.APIResponse{
		StatusCode: status,
		Body:       map[string]string{"message": message, "field": field},
	}
}
