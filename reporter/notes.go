package reporter

import (
	"fmt"
	"strings"
	"time"

	"github.com/richknowles/pct-svcmap/scanner"
)

const (
	notesStart = "<!-- pct-svcmap:start -->"
	notesEnd   = "<!-- pct-svcmap:end -->"
)

// NotesFormat controls which sections are included in auto-generated notes.
type NotesFormat string

const (
	NotesLinks   NotesFormat = "links"
	NotesAlerts  NotesFormat = "alerts"
	NotesDomains NotesFormat = "domains"
	NotesAll     NotesFormat = "all"
)

// ParseNotesFormats parses a comma-separated format string.
// Empty or "all" returns []NotesFormat{NotesAll}.
func ParseNotesFormats(s string) []NotesFormat {
	s = strings.TrimSpace(s)
	if s == "" || s == "all" {
		return []NotesFormat{NotesAll}
	}
	parts := strings.Split(s, ",")
	var formats []NotesFormat
	for _, p := range parts {
		switch NotesFormat(strings.TrimSpace(p)) {
		case NotesLinks, NotesAlerts, NotesDomains:
			formats = append(formats, NotesFormat(strings.TrimSpace(p)))
		case NotesAll:
			return []NotesFormat{NotesAll}
		}
	}
	if len(formats) == 0 {
		return []NotesFormat{NotesAll}
	}
	return formats
}

func hasNotesFormat(formats []NotesFormat, want NotesFormat) bool {
	for _, f := range formats {
		if f == NotesAll || f == want {
			return true
		}
	}
	return false
}

// webUI describes a well-known web UI port.
type webUI struct {
	Scheme string
	Label  string
}

// knownWebPorts maps port numbers to their typical web UI.
var knownWebPorts = map[int]webUI{
	80:    {"http", "HTTP"},
	443:   {"https", "HTTPS"},
	3000:  {"http", "Grafana"},
	3001:  {"http", "App"},
	4000:  {"http", "App"},
	5000:  {"http", "App"},
	5601:  {"http", "Kibana"},
	6443:  {"https", "Kubernetes API"},
	7480:  {"http", "Ceph RGW"},
	8006:  {"https", "Proxmox UI"},
	8080:  {"http", "HTTP-Alt"},
	8443:  {"https", "HTTPS-Alt"},
	8888:  {"http", "Jupyter"},
	9000:  {"http", "Portainer"},
	9090:  {"http", "Prometheus"},
	9093:  {"http", "Alertmanager"},
	9100:  {"http", "Node Exporter"},
	9200:  {"http", "Elasticsearch"},
	19999: {"http", "Netdata"},
}

// BuildGuestNote generates the pct-svcmap Markdown block for a single guest.
// The returned string includes the start/end delimiter comments.
func BuildGuestNote(result scanner.GuestScanResult, formats []NotesFormat) string {
	var sb strings.Builder

	sb.WriteString(notesStart + "\n")
	sb.WriteString(fmt.Sprintf("## pct-svcmap — %s\n\n", time.Now().Format("2006-01-02 15:04")))
	sb.WriteString(fmt.Sprintf("**Host:** %s (%d) · **Type:** %s · **Status:** %s  \n",
		result.Name, result.VMID, result.GuestType, result.Status))

	if len(result.IPs) > 0 {
		sb.WriteString(fmt.Sprintf("**IPs:** %s  \n", strings.Join(result.IPs, ", ")))
	}
	sb.WriteString("\n")

	// Domains section
	if hasNotesFormat(formats, NotesDomains) && len(result.Domains) > 0 {
		sb.WriteString("### Detected Domains\n\n")
		for _, d := range result.Domains {
			sb.WriteString(fmt.Sprintf("- `%s`\n", d))
		}
		sb.WriteString("\n")
	}

	// Alerts section — security findings table
	if hasNotesFormat(formats, NotesAlerts) {
		var risky []scanner.Service
		for _, s := range result.Services {
			if s.IsRisky {
				risky = append(risky, s)
			}
		}
		if len(risky) > 0 {
			sb.WriteString("### Security Alerts\n\n")
			sb.WriteString("| Severity | Port | Risk | Action |\n|---|---|---|---|\n")
			for _, s := range risky {
				sb.WriteString(fmt.Sprintf("| **%s** | %d | %s | %s |\n",
					string(s.RiskLevel), s.Port,
					mdSafe(s.RiskReason), mdSafe(s.Remediation)))
			}
			sb.WriteString("\n")
		}
	}

	// Links section — clickable web UI URLs
	if hasNotesFormat(formats, NotesLinks) && len(result.IPs) > 0 {
		primaryIP := result.IPs[0]
		seen := map[string]bool{}
		var links []string

		addLink := func(label, url string) {
			entry := fmt.Sprintf("- [%s → %s](%s)", label, url, url)
			if !seen[entry] {
				seen[entry] = true
				links = append(links, entry)
			}
		}

		for _, s := range result.Services {
			if ui, ok := knownWebPorts[s.Port]; ok {
				ip := primaryIP
				if s.BindAddr != "0.0.0.0" && s.BindAddr != "::" && s.BindAddr != "" {
					ip = s.BindAddr
				}
				addLink(ui.Label, fmt.Sprintf("%s://%s:%d", ui.Scheme, ip, s.Port))
			}
		}

		for _, c := range result.DockerContainers {
			for _, dp := range c.Ports {
				if ui, ok := knownWebPorts[dp.HostPort]; ok {
					hostIP := dp.HostIP
					if hostIP == "" || hostIP == "0.0.0.0" {
						hostIP = primaryIP
					}
					label := fmt.Sprintf("%s (%s)", ui.Label, c.Name)
					addLink(label, fmt.Sprintf("%s://%s:%d", ui.Scheme, hostIP, dp.HostPort))
				}
			}
		}

		if len(links) > 0 {
			sb.WriteString("### Quick Access\n\n")
			for _, l := range links {
				sb.WriteString(l + "\n")
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString(notesEnd + "\n")
	return sb.String()
}

// InjectNote replaces the existing pct-svcmap block in the existing notes string,
// or appends the new block if no block exists yet.
// Content outside the delimiters is preserved unchanged.
func InjectNote(existing, newBlock string) string {
	start := strings.Index(existing, notesStart)
	end := strings.Index(existing, notesEnd)

	if start >= 0 && end >= 0 && end > start {
		prefix := existing[:start]
		suffix := existing[end+len(notesEnd):]
		suffix = strings.TrimPrefix(suffix, "\n")
		return prefix + newBlock + suffix
	}

	if strings.TrimSpace(existing) == "" {
		return newBlock
	}
	return strings.TrimRight(existing, "\n") + "\n\n" + newBlock
}
