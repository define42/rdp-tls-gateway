// Package contextkey defines typed context keys used across the gateway.
package contextkey

import "context"

type contextKey string

const authUserKey contextKey = "authUser"

// WithAuthUser stores the authenticated username in the context.
func WithAuthUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, authUserKey, user)
}

// AuthUserFromContext retrieves the authenticated username from the context.
func AuthUserFromContext(ctx context.Context) (string, bool) {
	user, ok := ctx.Value(authUserKey).(string)
	if !ok || user == "" {
		return "", false
	}
	return user, true
}
