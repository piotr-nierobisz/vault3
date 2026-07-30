package runtime

import (
	"encoding/json"

	bungo "github.com/piotr-nierobisz/BunGo"
)

// decodeBody unmarshals a request body into T, returning either the payload
// or a ready-to-return 400. It pairs with the require* authorisation helpers:
// a handler opens with the same shape for both, and is left holding only its
// own logic.
//
//	payload, deny := decodeBody[idPayload](req)
//	if deny != nil {
//	    return *deny, nil
//	}
//
// The malformed-body response is stated once here rather than at each of the
// ~28 entry points, so every endpoint refuses unparseable input identically —
// which also means an attacker probing the API learns nothing from the
// wording of one endpoint that it could not learn from another.
func decodeBody[T any](req *bungo.Request) (*T, *bungo.APIResponse) {
	var payload T
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		deny := apiError(400, "Invalid request body")
		return nil, &deny
	}
	return &payload, nil
}

// The single-field request bodies that recur across handlers. Naming them
// keeps decodeBody's type argument readable and stops four handlers from each
// declaring their own {"id"} struct.
type (
	idPayload struct {
		ID string `json:"id"`
	}
	tokenPayload struct {
		Token string `json:"token"`
	}
	emailPayload struct {
		Email string `json:"email"`
	}
	codePayload struct {
		Code string `json:"code"`
	}
)

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
