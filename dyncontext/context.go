package dyncontext

import "context"

type cbdcContextKey string

const (
	ContexKeyUser             = cbdcContextKey("user")
	ContextKeyIgnoreOwnership = cbdcContextKey("ignore_ownership")
)

func NewContext(parent context.Context, user string, ignoreOwnership bool) context.Context {
	ctx := parent
	ctx = context.WithValue(ctx, ContexKeyUser, user)
	ctx = context.WithValue(ctx, ContextKeyIgnoreOwnership, ignoreOwnership)
	return ctx
}

func ContextUser(ctx context.Context) string {
	if user, ok := ctx.Value(ContexKeyUser).(string); ok {
		return user
	}
	return ""
}

func ContextIgnoreOwnership(ctx context.Context) bool {
	if ignore, ok := ctx.Value(ContextKeyIgnoreOwnership).(bool); ok {
		return ignore
	}
	return false
}
