// Package peercred identifies local TCP callers without trusting HTTP headers.
package peercred

import (
	"context"
	"net"
)

type contextKey struct{}

// ConnContext resolves the peer once, before HTTP or TLS processing begins.
func ConnContext(ctx context.Context, conn net.Conn) context.Context {
	if uid := lookupUID(conn); uid != nil {
		return context.WithValue(ctx, contextKey{}, *uid)
	}
	return ctx
}

// UID returns the UID determined at accept, or nil when it is unknown.
func UID(ctx context.Context) *uint32 {
	if uid, ok := ctx.Value(contextKey{}).(uint32); ok {
		return &uid
	}
	return nil
}
