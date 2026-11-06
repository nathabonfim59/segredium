package peercred

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

func lookupUID(conn net.Conn) *uint32 {
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || !remote.IP.IsLoopback() {
		return nil
	}
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	// Linux may place an IPv4-mapped dual-stack socket in tcp6.
	paths := [2]string{"/proc/net/tcp", "/proc/net/tcp6"}
	if remote.IP.To4() == nil {
		paths[0], paths[1] = paths[1], paths[0]
	}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		uid := findUID(f, remote.AddrPort(), local.AddrPort())
		f.Close()
		if uid != nil {
			return uid
		}
	}
	return nil
}

func findUID(r io.Reader, peer, server netip.AddrPort) *uint32 {
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	server = netip.AddrPortFrom(server.Addr().Unmap(), server.Port())
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Closed/orphaned sockets can report UID 0, so only trust an established peer.
		if len(fields) < 8 || fields[3] != "01" {
			continue
		}
		// Match the client's socket, whose endpoints are reversed from the accepted one.
		if procAddr(fields[1]) != peer || procAddr(fields[2]) != server {
			continue
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err == nil {
			value := uint32(uid)
			return &value
		}
	}
	return nil
}

func procAddr(value string) netip.AddrPort {
	addr, port, ok := strings.Cut(value, ":")
	if !ok {
		return netip.AddrPort{}
	}
	b, err := hex.DecodeString(addr)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.AddrPort{}
	}
	// /proc prints each native-endian 32-bit word as hexadecimal.
	for i := 0; i < len(b); i += 4 {
		word := binary.BigEndian.Uint32(b[i : i+4])
		binary.NativeEndian.PutUint32(b[i:i+4], word)
	}
	ip, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.AddrPort{}
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(p))
}
