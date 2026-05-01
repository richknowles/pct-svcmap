package reporter

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/richknowles/pct-svcmap/scanner"
	"github.com/richknowles/pct-svcmap/tagger"
)

// RenderMarkdown writes a full Markdown report to the provided writer.
func RenderMarkdown(w io.Writer, results []scanner.GuestScanResult,
	diffs []tagger.TagDiff, node string, duration time.Duration) error {

	diffMap := map[int]tagger.TagDiff{}
	for _, d := range diffs {
		diffMap[d.VMID] = d
	}

	// Sort results by VMID for stable output
	sorted := make([]scanner.GuestScanResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].VMID < sorted[j].VMID
	})

	// Compute summary stats
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

	// Header
	p("# Proxmox Service Map — %s — %s\n\n", node, time.Now().Format("2006-01-02 15:04:05"))

	// Summary table
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

	// Security warnings section
	var riskyRows []scanner.Service
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
				riskyRows = append(riskyRows, s)
			}
		}
	}
	_ = riskyRows
	if len(riskyEntries) > 0 {
		p("## Security Warnings\n\n")
		p("| Guest | VMID | Port | Protocol | Bind | Severity | Risk | Remediation |\n|---|---|---|---|---|---|---|---|\n")
		for _, e := range riskyEntries {
			p("| %s | %d | %d | %s | %s | %s | %s | %s |\n",
				mdSafe(e.guest), e.vmid, e.svc.Port,
				e.svc.Protocol, e.svc.BindAddr, string(e.svc.RiskLevel),
				mdSafe(e.svc.RiskReason), mdSafe(e.svc.Remediation))
		}
		p("\n")
	}

	// Per-guest sections
	p("## Guests\n\n")
	for _, r := range sorted {
		diff, hasDiff := diffMap[r.VMID]

		p("### %s (%d) [%s] — %s\n\n", mdSafe(r.Name), r.VMID, r.GuestType, r.Status)

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
			p("| Port | Proto | Bind | Process | Severity | Risk |\n|---|---|---|---|---|---|\n")
			for _, s := range r.Services {
				proc := s.ProcessName
				if s.PID > 0 && proc != "" {
					proc = fmt.Sprintf("%s (pid %d)", proc, s.PID)
				}
				severity := ""
				risk := ""
				if s.IsRisky {
					severity = string(s.RiskLevel)
					risk = s.RiskReason
				}
				p("| %d | %s | %s | %s | %s | %s |\n",
					s.Port, s.Protocol, s.BindAddr, mdSafe(proc), severity, mdSafe(risk))
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

// mdSafe escapes pipe characters to avoid breaking Markdown tables.
func mdSafe(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

// formatIPs joins IP strings for display.
func formatIPs(ips []string) string {
	return strings.Join(ips, ", ")
}
