//go:build !linux

package peercred

import "net"

func lookupUID(net.Conn) *uint32 { return nil }
