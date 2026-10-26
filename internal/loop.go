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
	if wildcard(listen.IP) {
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

// wildcard reports whether ip is unset or unspecified (":53" has a nil IP).
func wildcard(ip net.IP) bool { return len(ip) == 0 || ip.IsUnspecified() }

// exposedAddr reports whether listen could be reachable from outside a home network.
func exposedAddr(listen *net.UDPAddr) bool {
	ip := listen.IP
	return wildcard(ip) || !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}
