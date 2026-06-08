package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/richknowles/pct-svcmap/scanner"
)

// portServiceNames maps well-known ports to human-readable names.
var portServiceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpcbind", 139: "netbios",
	143: "imap", 389: "ldap", 443: "https", 445: "smb",
	636: "ldaps", 993: "imaps", 995: "pop3s",
	2375: "docker-api", 3000: "grafana", 3306: "mysql",
	5000: "docker-registry", 5432: "postgres", 5601: "kibana",
	6379: "redis", 6443: "k8s-api", 8080: "http-alt",
	8443: "https-alt", 9090: "prometheus", 9200: "elasticsearch",
	9300: "es-transport", 27017: "mongodb",
}

type summaryRow struct {
	VMID    int
	Host    string
	Type    string
	IP      string
	Port    int
	Proto   string
	Service string
	Process string
	Source  string
}

func buildSummaryRows(results []scanner.GuestScanResult) []summaryRow {
	sorted := make([]scanner.GuestScanResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].VMID < sorted[j].VMID })

	var rows []summaryRow
	for _, r := range sorted {
		ip := strings.Join(r.IPs, ",")
		if ip == "" {
			ip = "-"
		}
		if len(r.Services) == 0 {
			rows = append(rows, summaryRow{
				VMID: r.VMID, Host: r.Name, Type: r.GuestType,
				IP: ip, Proto: "-", Service: "-", Process: "-",
				Source: string(r.DetectionMethod),
			})
			continue
		}
		for _, svc := range r.Services {
			svcName := portServiceNames[svc.Port]
			proc := svc.ProcessName
			if svc.PID > 0 && proc != "" {
				proc = fmt.Sprintf("%s/%d", proc, svc.PID)
			}
			if proc == "" {
				proc = "-"
			}
			rows = append(rows, summaryRow{
				VMID: r.VMID, Host: r.Name, Type: r.GuestType,
				IP: ip, Port: svc.Port, Proto: svc.Protocol,
				Service: svcName, Process: proc,
				Source: string(r.DetectionMethod),
			})
		}
	}
	return rows
}

// RenderSummaryMarkdown writes a flat analytical table to the writer.
func RenderSummaryMarkdown(w io.Writer, results []scanner.GuestScanResult,
	node string, duration time.Duration) error {

	rows := buildSummaryRows(results)
	p := func(format string, args ...interface{}) { fmt.Fprintf(w, format, args...) }

	p("# Service Summary — %s — %s\n\n", node, time.Now().Format("2006-01-02 15:04:05"))
	p("_%d services across %d guests — %s_\n\n",
		countServices(results), len(results), duration.Round(time.Millisecond))
	p("| VMID | Host | Type | IP | Port | Proto | Service | Process | Source |\n")
	p("|---|---|---|---|---|---|---|---|---|\n")
	for _, row := range rows {
		portStr := "-"
		if row.Port > 0 {
			portStr = fmt.Sprintf("%d", row.Port)
		}
		p("| %d | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			row.VMID, mdSafe(row.Host), row.Type, mdSafe(row.IP),
			portStr, row.Proto, row.Service, mdSafe(row.Process), row.Source)
	}
	p("\n")
	return nil
}

// RenderSummaryJSON writes the flat analytical table as JSON.
func RenderSummaryJSON(w io.Writer, results []scanner.GuestScanResult,
	node string, duration time.Duration) error {

	type jsonRow struct {
		VMID    int    `json:"vmid"`
		Host    string `json:"host"`
		Type    string `json:"type"`
		IP      string `json:"ip"`
		Port    int    `json:"port,omitempty"`
		Proto   string `json:"proto,omitempty"`
		Service string `json:"service,omitempty"`
		Process string `json:"process,omitempty"`
		Source  string `json:"source"`
	}
	type jsonSummaryReport struct {
		GeneratedAt   time.Time `json:"generated_at"`
		Node          string    `json:"node"`
		ScanDuration  string    `json:"scan_duration"`
		TotalServices int       `json:"total_services"`
		TotalGuests   int       `json:"total_guests"`
		Rows          []jsonRow `json:"rows"`
	}

	rows := buildSummaryRows(results)
	jsonRows := make([]jsonRow, len(rows))
	for i, r := range rows {
		jsonRows[i] = jsonRow{
			VMID: r.VMID, Host: r.Host, Type: r.Type, IP: r.IP,
			Port: r.Port, Proto: r.Proto, Service: r.Service,
			Process: r.Process, Source: r.Source,
		}
	}

	report := jsonSummaryReport{
		GeneratedAt:   time.Now().UTC(),
		Node:          node,
		ScanDuration:  duration.Round(time.Millisecond).String(),
		TotalServices: countServices(results),
		TotalGuests:   len(results),
		Rows:          jsonRows,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func countServices(results []scanner.GuestScanResult) int {
	n := 0
	for _, r := range results {
		n += len(r.Services)
	}
	return n
}
