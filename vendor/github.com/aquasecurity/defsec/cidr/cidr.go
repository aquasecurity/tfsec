package cidr

import (
	"fmt"
	"net"
	"strings"
)

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivate(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPublic returns true if a provided IP is outside of the designated public ranges, or
// true if either of the min/max addresses of a provided CIDR are outside of these ranges.
func IsPublic(cidr string) bool {

	// some providers use wildcards etc. instead of "0.0.0.0/0" :/
	if cidr == "*" || cidr == "internet" || cidr == "any" {
		return true
	}

	// providers also allow "ranges" instead of cidrs :/
	if strings.Contains(cidr, "-") {
		parts := strings.Split(cidr, "-")
		if len(parts) != 2 {
			return false
		}
		if !isPrivate(net.IP(strings.TrimSpace(parts[0]))) {
			return true
		}
		if !isPrivate(net.IP(strings.TrimSpace(parts[1]))) {
			return true
		}
		return false
	}

	if !strings.Contains(cidr, "/") {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return false
		}
		return !isPrivate(ip)
	}

	start, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	if !isPrivate(start) {
		return true
	}

	end := highestAddress(network)
	return !isPrivate(end)
}

func highestAddress(network *net.IPNet) net.IP {
	raw := make([]byte, len(network.IP))
	copy(raw, network.IP)
	ones, bits := network.Mask.Size()
	flip := bits - ones
	for i := 0; i < flip; i++ {
		index := len(raw) - 1
		index -= (i / 8)
		raw[index] = raw[index] ^ (1 << (i % 8))
	}
	return net.IP(raw)
}
