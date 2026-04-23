package reporter

import (
	"encoding/json"
	"io"
	"time"

	"github.com/richknowles/pct-svcmap/scanner"
	"github.com/richknowles/pct-svcmap/tagger"
)

// JSONReport is the complete JSON output schema.
type JSONReport struct {
	GeneratedAt  time.Time        `json:"generated_at"`
	Node         string           `json:"node"`
	ScanDuration string           `json:"scan_duration"`
	Summary      JSONSummary      `json:"summary"`
	Guests       []JSONGuestResult `json:"guests"`
}

// JSONSummary holds aggregate statistics.
type JSONSummary struct {
	TotalGuests   int `json:"total_guests"`
	LXCCount      int `json:"lxc_count"`
	QEMUCount     int `json:"qemu_count"`
	TotalServices int `json:"total_services"`
	DockerHosts   int `json:"docker_hosts"`
	RiskyServices int `json:"risky_services"`
	ScanErrors    int `json:"scan_errors"`
}

// JSONGuestResult is the per-guest entry in the JSON output.
type JSONGuestResult struct {
	VMID             int                  `json:"vmid"`
	Name             string               `json:"name"`
	Type             string               `json:"type"`
	Status           string               `json:"status"`
	IPs              []string             `json:"ips"`
	Services         []JSONService        `json:"services"`
	DockerAvailable  bool                 `json:"docker_available"`
	DockerContainers []JSONDockerContainer `json:"docker_containers"`
	AgentAvailable   bool                 `json:"agent_available,omitempty"`
	DetectionMethod  string               `json:"detection_method"`
	ExistingTags     []string             `json:"existing_tags"`
	GeneratedTags    []string             `json:"generated_tags"`
	MergedTags       []string             `json:"merged_tags,omitempty"`
	TagsApplied      bool                 `json:"tags_applied"`
	ScanError        string               `json:"scan_error,omitempty"`
}

// JSONService is the JSON representation of a discovered service.
type JSONService struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	BindAddr    string `json:"bind_addr"`
	ProcessName string `json:"process_name,omitempty"`
	PID         int    `json:"pid,omitempty"`
	IsRisky     bool   `json:"is_risky"`
	RiskReason  string `json:"risk_reason,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

// JSONDockerContainer is the JSON representation of a Docker container.
type JSONDockerContainer struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Image string          `json:"image"`
	Ports []JSONDockerPort `json:"ports"`
}

// JSONDockerPort is one port mapping entry.
type JSONDockerPort struct {
	HostIP        string `json:"host_ip"`
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// RenderJSON serializes the complete report to the writer.
func RenderJSON(w io.Writer, results []scanner.GuestScanResult,
	diffs []tagger.TagDiff, node string, duration time.Duration) error {

	report := buildJSONReport(results, diffs, node, duration)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func buildJSONReport(results []scanner.GuestScanResult,
	diffs []tagger.TagDiff, node string, duration time.Duration) JSONReport {

	diffMap := map[int]tagger.TagDiff{}
	for _, d := range diffs {
		diffMap[d.VMID] = d
	}

	summary := JSONSummary{TotalGuests: len(results)}
	var guests []JSONGuestResult

	for _, r := range results {
		if r.GuestType == "lxc" {
			summary.LXCCount++
		} else {
			summary.QEMUCount++
		}
		summary.TotalServices += len(r.Services)
		if r.DockerAvailable {
			summary.DockerHosts++
		}
		for _, svc := range r.Services {
			if svc.IsRisky {
				summary.RiskyServices++
			}
		}
		if r.ScanError != "" {
			summary.ScanErrors++
		}

		diff, hasDiff := diffMap[r.VMID]
		guests = append(guests, toJSONGuest(r, hasDiff, diff))
	}

	return JSONReport{
		GeneratedAt:  time.Now().UTC(),
		Node:         node,
		ScanDuration: duration.Round(time.Millisecond).String(),
		Summary:      summary,
		Guests:       guests,
	}
}

func toJSONGuest(r scanner.GuestScanResult, hasDiff bool, diff tagger.TagDiff) JSONGuestResult {
	svcs := make([]JSONService, len(r.Services))
	for i, s := range r.Services {
		svcs[i] = JSONService{
			Port: s.Port, Protocol: s.Protocol, BindAddr: s.BindAddr,
			ProcessName: s.ProcessName, PID: s.PID,
			IsRisky: s.IsRisky, RiskReason: s.RiskReason,
			Severity: string(s.Severity),
		}
	}

	containers := make([]JSONDockerContainer, len(r.DockerContainers))
	for i, c := range r.DockerContainers {
		ports := make([]JSONDockerPort, len(c.Ports))
		for j, p := range c.Ports {
			ports[j] = JSONDockerPort{
				HostIP: p.HostIP, HostPort: p.HostPort,
				ContainerPort: p.ContainerPort, Protocol: p.Protocol,
			}
		}
		containers[i] = JSONDockerContainer{ID: c.ID, Name: c.Name, Image: c.Image, Ports: ports}
	}

	existingTags := tagger.ParseTagString(r.ExistingTags)
	if existingTags == nil {
		existingTags = []string{}
	}
	generatedTags := r.GeneratedTags
	if generatedTags == nil {
		generatedTags = []string{}
	}

	g := JSONGuestResult{
		VMID: r.VMID, Name: r.Name, Type: r.GuestType, Status: r.Status,
		IPs:              r.IPs,
		Services:         svcs,
		DockerAvailable:  r.DockerAvailable,
		DockerContainers: containers,
		AgentAvailable:   r.AgentAvailable,
		DetectionMethod:  string(r.DetectionMethod),
		ExistingTags:     existingTags,
		GeneratedTags:    generatedTags,
		TagsApplied:      r.TagsApplied,
		ScanError:        r.ScanError,
	}
	if hasDiff {
		g.MergedTags = diff.MergedTags
	}
	if g.IPs == nil {
		g.IPs = []string{}
	}
	return g
}
