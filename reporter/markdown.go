package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/richknowles/pct-svcmap/scanner"
	"github.com/richknowles/pct-svcmap/tagger"
)

func RenderMarkdown(w io.Writer, results []scanner.GuestScanResult,
	diffs []tagger.TagDiff, node string, duration time.Duration) error {

	diffMap := map[int]tagger.TagDiff{}
	for _, d := range diffs {
		diffMap[d.VMID] = d
	}

	sorted := make([]scanner.GuestScanResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].VMID < sorted[j].VMID
	})

	var lxcCount, qemuCount, totalSvcs, dockerHosts, riskySvcs, errCount int
	for _, r := range sorted {
		if r.GuestType == "lxc" {
			lxcCount++
		} else {
			qemuCount++
		}
		totalSvcs += len(r.Services)
		if r.DockerAvailable {
			dockerHosts++
		}
		for _, s := range r.Services {
			if s.IsRisky {
				riskySvcs++
			}
		}
		if r.ScanError != "" {
			errCount++
		}
	}

	p := func(format string, args ...interface{}) {
		fmt.Fprintf(w, format, args...)
	}

	p("# Proxmox Service Map — %s — %s\n\n", node, time.Now().Format("2006-01-02 15:04:05"))
	p("## Summary\n\n")
	p("| Metric | Value |\n|---|---|\n")
	p("| Node | %s |\n", mdSafe(node))
	p("| Guests scanned | %d |\n", len(sorted))
	p("| LXC containers | %d |\n", lxcCount)
	p("| QEMU VMs | %d |\n", qemuCount)
	p("| Total services | %d |\n", totalSvcs)
	p("| Docker hosts | %d |\n", dockerHosts)
	p("| Risky services | %d |\n", riskySvcs)
	p("| Scan errors | %d |\n", errCount)
	p("| Scan duration | %s |\n\n", duration.Round(time.Millisecond))

	type riskyEntry struct {
		guest string
		vmid  int
		svc   scanner.Service
	}
	var riskyEntries []riskyEntry
	for _, r := range sorted {
		for _, s := range r.Services {
			if s.IsRisky {
				riskyEntries = append(riskyEntries, riskyEntry{r.Name, r.VMID, s})
			}
		}
	}
	if len(riskyEntries) > 0 {
		p("## Security Warnings\n\n")
		p("| Guest | VMID | Port | Protocol | Bind | Risk |\n|---|---|---|---|---|---|\n")
		for _, e := range riskyEntries {
			severityIcon := ""
			if e.svc.Severity == scanner.SeverityCritical {
				severityIcon = "🔴 "
			} else if e.svc.Severity == scanner.SeverityHigh {
				severityIcon = "🟠 "
			}
			p("| %s | %d | %d | %s | %s | %s%s |\n",
				mdSafe(e.guest), e.vmid, e.svc.Port,
				e.svc.Protocol, e.svc.BindAddr, severityIcon, mdSafe(e.svc.RiskReason))
		}
		p("\n")
	}

	p("## Guests\n\n")
	for _, r := range sorted {
		diff, hasDiff := diffMap[r.VMID]

		statusIcon := "🟢"
		if r.Status == "stopped" {
			statusIcon = "🔴"
		}
		p("### %s (%d) [%s] — %s %s\n\n", mdSafe(r.Name), r.VMID, r.GuestType, statusIcon, r.Status)

		if len(r.IPs) > 0 {
			p("**IPs:** %s  \n", strings.Join(r.IPs, ", "))
		}
		p("**Detection:** %s  \n", string(r.DetectionMethod))

		existingTags := tagger.ParseTagString(r.ExistingTags)
		if len(existingTags) > 0 {
			p("**Tags (existing):** %s  \n", strings.Join(existingTags, ", "))
		}
		if hasDiff && len(diff.NewTags) > 0 {
			p("**Tags (generated):** %s  \n", strings.Join(diff.NewTags, ", "))
		} else if len(r.GeneratedTags) > 0 {
			p("**Tags (generated):** %s  \n", strings.Join(r.GeneratedTags, ", "))
		}
		p("\n")

		if r.ScanError != "" {
			p("> **Scan Error:** %s\n\n", mdSafe(r.ScanError))
		}

		if len(r.Services) > 0 {
			p("#### Services\n\n")
			p("| Port | Proto | Bind | Process | Risk |\n|---|---|---|---|---|\n")
			for _, s := range r.Services {
				proc := s.ProcessName
				if s.PID > 0 && proc != "" {
					proc = fmt.Sprintf("%s (pid %d)", proc, s.PID)
				}
				risk := ""
				if s.IsRisky {
					risk = ":warning: " + s.RiskReason
				}
				p("| %d | %s | %s | %s | %s |\n",
					s.Port, s.Protocol, s.BindAddr, mdSafe(proc), mdSafe(risk))
			}
			p("\n")
		}

		if r.DockerAvailable {
			p("#### Docker Containers\n\n")
			if len(r.DockerContainers) == 0 {
				p("_Docker is available but no containers are running._\n\n")
			} else {
				p("| Container | Image | Published Ports |\n|---|---|---|\n")
				for _, c := range r.DockerContainers {
					var portStrs []string
					for _, p2 := range c.Ports {
						portStrs = append(portStrs,
							fmt.Sprintf("%s:%d→%d/%s", p2.HostIP, p2.HostPort, p2.ContainerPort, p2.Protocol))
					}
					p("| %s | %s | %s |\n",
						mdSafe(c.Name), mdSafe(c.Image), mdSafe(strings.Join(portStrs, ", ")))
				}
				p("\n")
			}
		}
	}

	return nil
}

func mdSafe(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func severityEmoji(s scanner.Severity) string {
	switch s {
	case scanner.SeverityCritical:
		return "🔴"
	case scanner.SeverityHigh:
		return "🟠"
	case scanner.SeverityMedium:
		return "🟡"
	default:
		return "🟢"
	}
}

func severityOrder(s scanner.Severity) int {
	switch s {
	case scanner.SeverityCritical:
		return 0
	case scanner.SeverityHigh:
		return 1
	case scanner.SeverityMedium:
		return 2
	default:
		return 3
	}
}

func sortBySeverity(svcs []scanner.Service) {
	sort.Slice(svcs, func(i, j int) bool {
		return severityOrder(svcs[i].Severity) < severityOrder(svcs[j].Severity)
	})
}

func getRemediation(port int) string {
	riskyPorts := map[int]string{
		21:    "Disable or use SFTP/SSH instead",
		23:   "Disable immediately, use SSH instead",
		111:  "Disable or restrict to localhost",
		445:  "Disable or firewall to trusted networks",
		2375: "Bind to 127.0.0.1 or enable TLS with mutual auth",
		3306: "Bind to localhost or enable TLS",
		5432: "Bind to localhost or enable TLS",
		6379: "Bind to localhost and enable requirepass",
		9200: "Enable x-pack security or use firewall",
		27017: "Enable authentication and bind to localhost",
	}
	if r, ok := riskyPorts[port]; ok {
		return r
	}
	return "Review and restrict access"
}

func getServiceName(port int) string {
	names := map[int]string{
		21:    "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
		80:   "HTTP", 443: "HTTPS", 389: "LDAP", 636: "LDAPS",
		3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
		9200: "Elasticsearch", 27017: "MongoDB", 445: "SMB",
		111:  "RPCbind", 2375: "Docker API",
	}
	if n, ok := names[port]; ok {
		return n
	}
	return "Unknown"
}

func RenderSummaryMarkdown(w io.Writer, results []scanner.GuestScanResult, node string, duration time.Duration) error {
	p := func(format string, args ...interface{}) {
		fmt.Fprintf(w, format, args...)
	}

	p("# Service Summary — %s — %s\n\n", node, time.Now().Format("2006-01-02 15:04:05"))
	p("## Quick Service Reference\n\n")
	p("| Hostname | IP | Port | Service |\n|---|---|---|---|\n")

	sorted := make([]scanner.GuestScanResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].VMID < sorted[j].VMID })

	for _, r := range sorted {
		if len(r.Services) == 0 {
			continue
		}
		primaryIP := "-"
		if len(r.IPs) > 0 {
			primaryIP = r.IPs[0]
		}
		for _, s := range r.Services {
			svcName := getServiceName(s.Port)
			p("| %s | %s | %d/%s | %s |\n", mdSafe(r.Name), primaryIP, s.Port, svcName)
		}
	}

	p("\n*Total: %d hosts, %d services*\n", len(results), countServices(results))
	return nil
}

func RenderSummaryJSON(w io.Writer, results []scanner.GuestScanResult, node string, duration time.Duration) error {
	type SummaryEntry struct {
		Hostname string `json:"hostname"`
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Service  string `json:"service"`
	}
	var entries []SummaryEntry
	for _, r := range results {
		if len(r.Services) == 0 {
			continue
		}
		ip := "-"
		if len(r.IPs) > 0 {
			ip = r.IPs[0]
		}
		for _, s := range r.Services {
			entries = append(entries, SummaryEntry{
				Hostname: r.Name,
				IP:       ip,
				Port:     s.Port,
				Protocol: s.Protocol,
				Service:  getServiceName(s.Port),
			})
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func RenderSecurityMarkdown(w io.Writer, results []scanner.GuestScanResult, node string, duration time.Duration) error {
	p := func(format string, args ...interface{}) {
		fmt.Fprintf(w, format, args...)
	}

	p("# Security Report — %s — %s\n\n", node, time.Now().Format("2006-01-02 15:04:05"))
	p("## Security Issues with Remediation\n\n")
	p("| Severity | Guest | VMID | Port | Service | Remediation |\n")
	p("|---|---|---|---|---|---|\n")

	type entry struct {
		guest      string
		vmid       int
		svc        scanner.Service
		severity   scanner.Severity
		remediate string
	}
	var entries []entry

	for _, r := range results {
		for _, s := range r.Services {
			if s.IsRisky {
				entries = append(entries, entry{
					guest: r.Name, vmid: r.VMID, svc: s,
					severity: s.Severity, remediate: getRemediation(s.Port),
				})
			}
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return severityOrder(entries[i].severity) < severityOrder(entries[j].severity)
	})

	for _, e := range entries {
		svcName := getServiceName(e.svc.Port)
		emoji := severityEmoji(e.severity)
		p("| %s %s | %s | %d | %d/%s | %s |\n",
			emoji, e.severity, mdSafe(e.guest), e.vmid, e.svc.Port, svcName, mdSafe(e.remediate))
	}

	p("\n*Found %d security issues*\n", len(entries))
	return nil
}

func RenderSecurityJSON(w io.Writer, results []scanner.GuestScanResult, node string, duration time.Duration) error {
	type SecurityEntry struct {
		Severity    string `json:"severity"`
		Guest     string `json:"guest"`
		VMID      int    `json:"vmid"`
		Port      int    `json:"port"`
		Service   string `json:"service"`
		BindAddr  string `json:"bind_addr"`
		Remediation string `json:"remediation"`
	}
	var entries []SecurityEntry
	for _, r := range results {
		for _, s := range r.Services {
			if s.IsRisky {
				entries = append(entries, SecurityEntry{
					Severity:    string(s.Severity),
					Guest:     r.Name,
					VMID:      r.VMID,
					Port:      s.Port,
					Service:   getServiceName(s.Port),
					BindAddr:  s.BindAddr,
					Remediation: getRemediation(s.Port),
				})
			}
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func RenderSecurityFullMarkdown(w io.Writer, results []scanner.GuestScanResult, node string, duration time.Duration) error {
	p := func(format string, args ...interface{}) {
		fmt.Fprintf(w, format, args...)
	}

	p("# Full Security Audit — %s — %s\n\n", node, time.Now().Format("2006-01-02 15:04:05"))

	sorted := make([]scanner.GuestScanResult, len(results))
	copy(sorted, results)

	var critical, high, medium, low int
	for _, r := range sorted {
		for _, s := range r.Services {
			if s.IsRisky {
				switch s.Severity {
				case scanner.SeverityCritical:
					critical++
				case scanner.SeverityHigh:
					high++
				case scanner.SeverityMedium:
					medium++
				default:
					low++
				}
			}
		}
	}

	p("## Attack Surface Overview\n\n")
	p("| Risk Level | Count |\n")
	p("|---|---|\n")
	p("| 🔴 CRITICAL | %d |\n", critical)
	p("| 🟠 HIGH | %d |\n", high)
	p("| 🟡 MEDIUM | %d |\n", medium)
	p("| 🟢 LOW | %d |\n\n", low)

	p("## Top Exposed Guests (by Risk Score)\n\n")
	p("| Guest | Risk Score | Issues |\n")
	p("|---|---|---|\n")

	type guestRisk struct {
		name    string
		vmid   int
		score  int
		issues int
	}
	var guestRisks []guestRisk
	for _, r := range sorted {
		var score int
		var issues int
		for _, s := range r.Services {
			if s.IsRisky {
				issues++
				switch s.Severity {
				case scanner.SeverityCritical:
					score += 10
				case scanner.SeverityHigh:
					score += 5
				case scanner.SeverityMedium:
					score += 2
				default:
					score++
				}
			}
		}
		if score > 0 {
			guestRisks = append(guestRisks, guestRisk{r.Name, r.VMID, score, issues})
		}
	}
	sort.Slice(guestRisks, func(i, j int) bool { return guestRisks[i].score > guestRisks[j].score })
	for _, g := range guestRisks {
		p("| %s | %d | %d |\n", mdSafe(g.name), g.score, g.issues)
	}

	p("\n## Hardening Roadmap\n\n")
	p("### Immediate Actions (Critical Issues)\n\n")
	for _, r := range sorted {
		for _, s := range r.Services {
			if s.IsRisky && s.Severity == scanner.SeverityCritical {
				p("- **[%s](%d)**: %s → %s\n", r.Name, r.VMID, getServiceName(s.Port), getRemediation(s.Port))
			}
		}
	}

	p("\n### This Week (High Priority)\n\n")
	for _, r := range sorted {
		for _, s := range r.Services {
			if s.IsRisky && s.Severity == scanner.SeverityHigh {
				p("- **[%s](%d)**: %s → %s\n", r.Name, r.VMID, getServiceName(s.Port), getRemediation(s.Port))
			}
		}
	}

	p("\n### This Month (Medium Priority)\n\n")
	seen := map[string]bool{}
	for _, r := range sorted {
		for _, s := range r.Services {
			if s.IsRisky && s.Severity == scanner.SeverityMedium {
				key := fmt.Sprintf("%d-%d", s.Port, s.BindAddr)
				if !seen[key] {
					p("- %s bound to %s → %s\n", getServiceName(s.Port), s.BindAddr, getRemediation(s.Port))
					seen[key] = true
				}
			}
		}
	}

	return nil
}

type FullSecurityReport struct {
	GeneratedAt   string          `json:"generated_at"`
	Node           string          `json:"node"`
	Summary        FullRiskSummary `json:"summary"`
	Guests        []FullGuestRisk `json:"guests"`
	Remediations   []FullRemediate `json:"remediations"`
}
type FullRiskSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}
type FullGuestRisk struct {
	VMID    int    `json:"vmid"`
	Name   string `json:"name"`
	Score  int    `json:"score"`
	Issues int    `json:"issues"`
}
type FullRemediate struct {
	Service     string `json:"service"`
	Guest      string `json:"guest,omitempty"`
	Port       int    `json:"port"`
	Remediation string `json:"remediation"`
	Priority   string `json:"priority"`
}

func RenderSecurityFullJSON(w io.Writer, results []scanner.GuestScanResult, node string, duration time.Duration) error {

	var summary FullRiskSummary
	var guests []FullGuestRisk
	var remediations []FullRemediate

	for _, r := range results {
		var score int
		var issues int
		for _, s := range r.Services {
			if s.IsRisky {
				issues++
				switch s.Severity {
				case scanner.SeverityCritical:
					summary.Critical++
					score += 10
					remediations = append(remediations, FullRemediate{
						Service: getServiceName(s.Port), Guest: r.Name,
						Port: s.Port, Remediation: getRemediation(s.Port), Priority: "critical",
					})
				case scanner.SeverityHigh:
					summary.High++
					score += 5
				case scanner.SeverityMedium:
					summary.Medium++
					score += 2
				default:
					summary.Low++
					score++
				}
			}
		}
		if score > 0 {
			guests = append(guests, FullGuestRisk{
				VMID: r.VMID, Name: r.Name, Score: score, Issues: issues,
			})
		}
	}

	report := FullSecurityReport{
		GeneratedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Node:        node,
		Summary:     summary,
		Guests:      guests,
		Remediations: remediations,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func countServices(results []scanner.GuestScanResult) int {
	count := 0
	for _, r := range results {
		count += len(r.Services)
	}
	return count
}