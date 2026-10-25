package internal

import (
	"fmt"
	"net"
)

// isSelf reports whether upstream would reach the listener on this host.
func isSelf(listen, upstream *net.UDPAddr) (bool, error) {
	if listen.Port != upstream.Port {
		return false, nil
	}
	if len(listen.IP) == 0 || listen.IP.IsUnspecified() { // empty host (":53") has a nil IP
		if upstream.IP.IsLoopback() || upstream.IP.IsUnspecified() {
			return true, nil
		}
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return false, fmt.Errorf("list interface addresses: %w", err)
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(upstream.IP) {
				return true, nil
			}
		}
		return false, nil
	}
	if upstream.IP.IsUnspecified() {
		return listen.IP.IsLoopback(), nil
	}
	return listen.IP.Equal(upstream.IP), nil
}
