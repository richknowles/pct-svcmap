package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/richknowles/pct-svcmap/proxmox"
)

// NmapMode controls the intensity of the nmap scan.
type NmapMode string

const (
	NmapQuick   NmapMode = "quick"
	NmapDefault NmapMode = "default"
	NmapFull    NmapMode = "full"
)

// RunNmapScan executes nmap against a list of IPs from the Proxmox host.
// nmap must be installed on the Proxmox node itself.
func RunNmapScan(ips []string, mode NmapMode, cfg proxmox.ExecConfig) ([]Service, error) {
	if len(ips) == 0 {
		return nil, nil
	}
	args := buildNmapArgs(mode, ips)
	data, err := proxmox.RunCommand(cfg, "nmap", args...)
	if err != nil {
		return nil, fmt.Errorf("nmap: %w", err)
	}
	return parseNmapGrepable(data), nil
}

func buildNmapArgs(mode NmapMode, ips []string) []string {
	var args []string
	switch mode {
	case NmapQuick:
		args = append(args, "-T4", "-F")
	case NmapFull:
		args = append(args, "-T4", "-p-")
	default:
		args = append(args, "-T4", "--top-ports", "1000")
	}
	args = append(args, "-oG", "-")
	return append(args, ips...)
}

var nmapPortRegexp = regexp.MustCompile(`(\d+)/open/(tcp|udp)//([^/]*)`)

// parseNmapGrepable extracts open ports from nmap -oG (grepable) output.
func parseNmapGrepable(data []byte) []Service {
	var svcs []Service
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "Host:") {
			continue
		}
		parts := strings.Fields(line)
		bindAddr := ""
		if len(parts) >= 2 {
			bindAddr = parts[1]
		}
		for _, m := range nmapPortRegexp.FindAllStringSubmatch(line, -1) {
			port, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			proc := strings.TrimSpace(m[3])
			svcs = append(svcs, Service{
				Protocol:    m[2],
				Port:        port,
				BindAddr:    bindAddr,
				ProcessName: proc,
			})
		}
	}
	return svcs
}

// mergeNmapServices merges nmap results into an existing service list.
// Existing entries take precedence; new nmap-only entries get risky-flagged
// without the bind-address restriction (reachable from network = exposed).
func mergeNmapServices(existing, nmapSvcs []Service) []Service {
	seen := map[string]bool{}
	for _, s := range existing {
		seen[fmt.Sprintf("%s:%d", s.Protocol, s.Port)] = true
	}
	result := append([]Service{}, existing...)
	for _, s := range nmapSvcs {
		key := fmt.Sprintf("%s:%d", s.Protocol, s.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, flagNmapRisky(s))
	}
	return result
}
