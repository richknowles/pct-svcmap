package scanner

import (
	"net"
	"strings"
)

// DetectDomains returns hostnames for a guest: the Proxmox-configured name
// plus any reverse-DNS names resolved from its IPs.
// Failures from net.LookupAddr are silently skipped.
func DetectDomains(name string, ips []string) []string {
	seen := map[string]bool{}
	var domains []string

	add := func(s string) {
		s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
		if s != "" && !seen[s] {
			seen[s] = true
			domains = append(domains, s)
		}
	}

	add(name)

	for _, ip := range ips {
		names, err := net.LookupAddr(ip)
		if err != nil {
			continue
		}
		for _, n := range names {
			add(n)
		}
	}

	return domains
}
