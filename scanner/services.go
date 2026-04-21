package scanner

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/rightontron/pct-svcmap/proxmox"
)

var ssUsersRegexp = regexp.MustCompile(`\("([^"]+)",pid=(\d+)`)

// DetectServices runs the ss → lsof → /proc/net/tcp fallback chain.
func DetectServices(guest proxmox.Guest, client *proxmox.NodeClient) ([]Service, DetectionMethod, error) {
	// Try ss first
	data, err := execInGuest(guest, client, "ss", "-Htupln")
	if err == nil {
		svcs, parseErr := parseSSOutput(data)
		if parseErr != nil {
			return nil, DetectionFailed, parseErr
		}
		return flagRiskyServices(svcs), DetectionSS, nil
	}
	if isTimeout(err) {
		return nil, DetectionFailed, err
	}

	// Try lsof
	data, err = execInGuest(guest, client, "lsof", "-i", "-nP", "-sTCP:LISTEN")
	if err == nil {
		svcs, parseErr := parseLSOFOutput(data)
		if parseErr != nil {
			return nil, DetectionFailed, parseErr
		}
		return flagRiskyServices(svcs), DetectionLSOF, nil
	}
	if isTimeout(err) {
		return nil, DetectionFailed, err
	}

	// Try /proc/net/tcp
	tcpData, err4 := execInGuest(guest, client, "cat", "/proc/net/tcp")
	tcp6Data, _ := execInGuest(guest, client, "cat", "/proc/net/tcp6")
	if err4 != nil {
		return nil, DetectionFailed, fmt.Errorf("all detection methods failed")
	}
	var svcs []Service
	if tcp, err := parseProcNetTCP(tcpData, "tcp"); err == nil {
		svcs = append(svcs, tcp...)
	}
	if tcp6, err := parseProcNetTCP(tcp6Data, "tcp"); err == nil {
		svcs = append(svcs, tcp6...)
	}
	return flagRiskyServices(svcs), DetectionProcNet, nil
}

func parseSSOutput(data []byte) ([]Service, error) {
	var svcs []Service
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		// Fields: proto state recv-q send-q local peer [users]
		if len(fields) < 5 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		localAddr := fields[4]
		// Split last colon as port separator (handles IPv6 [::]:port)
		lastColon := strings.LastIndex(localAddr, ":")
		if lastColon < 0 {
			continue
		}
		bindAddr := localAddr[:lastColon]
		portStr := localAddr[lastColon+1:]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		// Clean up bind address brackets from IPv6
		bindAddr = strings.Trim(bindAddr, "[]")
		if bindAddr == "*" {
			bindAddr = "0.0.0.0"
		}

		svc := Service{
			Protocol: proto,
			Port:     port,
			BindAddr: bindAddr,
		}

		// Extract process name and PID from users field
		if len(fields) > 6 {
			usersField := strings.Join(fields[6:], " ")
			if m := ssUsersRegexp.FindStringSubmatch(usersField); m != nil {
				svc.ProcessName = m[1]
				svc.PID, _ = strconv.Atoi(m[2])
			}
		}
		svcs = append(svcs, svc)
	}
	return svcs, nil
}

var lsofNameRegexp = regexp.MustCompile(`(?:\*|[\d\.]+|\[.*?\]):(\d+)`)

func parseLSOFOutput(data []byte) ([]Service, error) {
	var svcs []Service
	seen := map[string]bool{}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		cmd := fields[0]
		pid, _ := strconv.Atoi(fields[1])
		nameField := fields[len(fields)-1]

		// NAME field formats: *:22 (TCP) or 127.0.0.1:22 (TCP) or [::]:22 (TCP)
		m := lsofNameRegexp.FindStringSubmatch(nameField)
		if m == nil {
			continue
		}
		port, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		bindAddr := "0.0.0.0"
		colonIdx := strings.LastIndex(nameField, ":")
		if colonIdx > 0 {
			b := nameField[:colonIdx]
			b = strings.Trim(b, "[]")
			if b != "*" && b != "" {
				bindAddr = b
			}
		}
		key := fmt.Sprintf("tcp:%s:%d", bindAddr, port)
		if seen[key] {
			continue
		}
		seen[key] = true
		svcs = append(svcs, Service{
			Protocol:    "tcp",
			Port:        port,
			BindAddr:    bindAddr,
			ProcessName: cmd,
			PID:         pid,
		})
	}
	return svcs, nil
}

func parseProcNetTCP(data []byte, proto string) ([]Service, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty /proc/net/tcp")
	}
	var svcs []Service
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Column 1: local_address (hex), Column 3: state
		if fields[3] != "0A" { // 0A = TCP_LISTEN
			continue
		}
		addrPort := fields[1]
		parts := strings.SplitN(addrPort, ":", 2)
		if len(parts) != 2 {
			continue
		}
		ip, err := hexToIP(parts[0])
		if err != nil {
			continue
		}
		portVal, err := strconv.ParseInt(parts[1], 16, 32)
		if err != nil {
			continue
		}
		port := int(portVal)
		key := fmt.Sprintf("%s:%s:%d", proto, ip, port)
		if seen[key] {
			continue
		}
		seen[key] = true
		svcs = append(svcs, Service{
			Protocol: proto,
			Port:     port,
			BindAddr: ip,
		})
	}
	return svcs, nil
}

// hexToIP decodes a little-endian 8-char hex IP string (e.g. "0101A8C0" → "192.168.1.1").
func hexToIP(hexStr string) (string, error) {
	if len(hexStr) != 8 {
		return "", fmt.Errorf("unexpected hex IP length: %s", hexStr)
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}
	// /proc/net/tcp stores IPs in little-endian order
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0]), nil
}

var riskyPorts = map[int]string{
	21:   "FTP — plaintext credentials",
	23:   "Telnet — plaintext protocol",
	3306: "MySQL — unencrypted, world-accessible",
	5432: "PostgreSQL — unencrypted, world-accessible",
	6379: "Redis — unauthenticated by default",
}

func flagRiskyServices(svcs []Service) []Service {
	for i := range svcs {
		if reason, ok := riskyPorts[svcs[i].Port]; ok {
			if svcs[i].BindAddr == "0.0.0.0" || svcs[i].BindAddr == "::" {
				svcs[i].IsRisky = true
				svcs[i].RiskReason = reason
			}
		}
	}
	return svcs
}

func execInGuest(guest proxmox.Guest, client *proxmox.NodeClient, args ...string) ([]byte, error) {
	if guest.Type == proxmox.GuestTypeLXC {
		return client.ExecInLXC(guest.VMID, args...)
	}
	return client.ExecInQEMU(guest.VMID, args...)
}

func isTimeout(err error) bool {
	return err != nil && strings.Contains(err.Error(), "timeout after")
}
