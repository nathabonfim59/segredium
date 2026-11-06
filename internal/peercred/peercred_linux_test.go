package peercred

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestProcSocketMatch(t *testing.T) {
	for _, tc := range []struct{ name, local, remote, peer, server string }{
		{"ipv4", "0100007F:C123", "0100007F:01BB", "127.0.0.1:49443", "127.0.0.1:443"},
		{"ipv6", "00000000000000000000000001000000:C123", "00000000000000000000000001000000:01BB", "[::1]:49443", "[::1]:443"},
		{"mapped", "0000000000000000FFFF00000100007F:C123", "0000000000000000FFFF00000100007F:01BB", "127.0.0.1:49443", "127.0.0.1:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer, server := netip.MustParseAddrPort(tc.peer), netip.MustParseAddrPort(tc.server)
			row := "  1: " + tc.local + " " + tc.remote + " 01 00000000:00000000 00:00000000 00000000 1001 0 1234"
			uid := findUID(strings.NewReader("header\nmalformed\n"+row), peer, server)
			if uid == nil || *uid != 1001 {
				t.Fatalf("UID = %v", uid)
			}
			if uid := findUID(strings.NewReader(row), server, peer); uid != nil {
				t.Fatalf("matched server side: %v", uid)
			}
			closed := strings.Replace(row, " 01 ", " 06 ", 1)
			if uid := findUID(strings.NewReader(closed), peer, server); uid != nil {
				t.Fatalf("matched closed socket: %v", uid)
			}
		})
	}
}

func TestLoopbackConnection(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			addr := "127.0.0.1:0"
			if network == "tcp6" {
				addr = "[::1]:0"
			}
			listener, err := net.Listen(network, addr)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.Dial(network, listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			uid := UID(ConnContext(context.Background(), server))
			if uid == nil || *uid != uint32(os.Getuid()) {
				t.Fatalf("peer UID = %v, want %d", uid, os.Getuid())
			}
		})
	}
}

func TestUnknownConnection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if uid := UID(ConnContext(context.Background(), a)); uid != nil {
		t.Fatalf("non-TCP UID: %v", uid)
	}
}
