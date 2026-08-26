package auth

import "context"

// WithUser attaches an authenticated user to a request context.
func WithUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, userKey{}, user)
}

// UserFrom returns the authenticated user, or "" when the request did not pass
// through Require.
//
// Handlers use it to attribute administrative audit entries: §6.1 asks the log
// to record who changed what, so every mutation names its actor.
func UserFrom(ctx context.Context) string {
	user, _ := ctx.Value(userKey{}).(string)
	return user
}
