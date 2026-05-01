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

type securityEntry struct {
	Guest     string
	VMID      int
	GuestType string
	IPs       []string
	Svc       scanner.Service
}

type guestScore struct {
	VMID      int
	Name      string
	GuestType string
	IPs       []string
	Score     int
	Critical  int
	High      int
	Medium    int
}

func collectSecurityEntries(results []scanner.GuestScanResult) ([]securityEntry, map[int]*guestScore) {
	var entries []securityEntry
	scores := map[int]*guestScore{}

	for _, r := range results {
		gs := &guestScore{
			VMID: r.VMID, Name: r.Name, GuestType: r.GuestType, IPs: r.IPs,
		}
		scores[r.VMID] = gs

		for _, s := range r.Services {
			if !s.IsRisky {
				continue
			}
			entries = append(entries, securityEntry{r.Name, r.VMID, r.GuestType, r.IPs, s})
			switch s.RiskLevel {
			case scanner.RiskCritical:
				gs.Score += 30
				gs.Critical++
			case scanner.RiskHigh:
				gs.Score += 15
				gs.High++
			case scanner.RiskMedium:
				gs.Score += 5
				gs.Medium++
			}
		}
		if gs.Score > 100 {
			gs.Score = 100
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return severityRank(entries[i].Svc.RiskLevel) < severityRank(entries[j].Svc.RiskLevel)
	})
	return entries, scores
}

func severityRank(level scanner.RiskLevel) int {
	switch level {
	case scanner.RiskCritical:
		return 0
	case scanner.RiskHigh:
		return 1
	case scanner.RiskMedium:
		return 2
	}
	return 3
}

// RenderSecurityMarkdown writes a security-focused report grouped by severity.
func RenderSecurityMarkdown(w io.Writer, results []scanner.GuestScanResult,
	node string, duration time.Duration) error {

	entries, _ := collectSecurityEntries(results)
	p := func(format string, args ...interface{}) { fmt.Fprintf(w, format, args...) }

	totalCritical, totalHigh, totalMedium := countBySeverity(entries)
	p("# Security Report — %s — %s\n\n", node, time.Now().Format("2006-01-02 15:04:05"))
	p("| Metric | Value |\n|---|---|\n")
	p("| Node | %s |\n", mdSafe(node))
	p("| Guests scanned | %d |\n", len(results))
	p("| CRITICAL findings | %d |\n", totalCritical)
	p("| HIGH findings | %d |\n", totalHigh)
	p("| MEDIUM findings | %d |\n", totalMedium)
	p("| Total findings | %d |\n", len(entries))
	p("| Scan duration | %s |\n\n", duration.Round(time.Millisecond))

	if len(entries) == 0 {
		p("_No security findings detected._\n")
		return nil
	}

	for _, level := range []scanner.RiskLevel{scanner.RiskCritical, scanner.RiskHigh, scanner.RiskMedium} {
		group := filterBySeverity(entries, level)
		if len(group) == 0 {
			continue
		}
		p("## %s (%d finding(s))\n\n", string(level), len(group))
		p("| Guest | VMID | Port | Protocol | Bind | Risk | Remediation |\n|---|---|---|---|---|---|---|\n")
		for _, e := range group {
			p("| %s | %d | %d | %s | %s | %s | %s |\n",
				mdSafe(e.Guest), e.VMID, e.Svc.Port, e.Svc.Protocol, e.Svc.BindAddr,
				mdSafe(e.Svc.RiskReason), mdSafe(e.Svc.Remediation))
		}
		p("\n")
	}
	return nil
}

// RenderSecurityJSON writes the security report as JSON.
func RenderSecurityJSON(w io.Writer, results []scanner.GuestScanResult,
	node string, duration time.Duration) error {

	entries, _ := collectSecurityEntries(results)
	totalCritical, totalHigh, totalMedium := countBySeverity(entries)

	type jsonFinding struct {
		Guest       string   `json:"guest"`
		VMID        int      `json:"vmid"`
		GuestType   string   `json:"guest_type"`
		IPs         []string `json:"ips"`
		Port        int      `json:"port"`
		Protocol    string   `json:"protocol"`
		BindAddr    string   `json:"bind_addr"`
		Severity    string   `json:"severity"`
		Risk        string   `json:"risk"`
		Remediation string   `json:"remediation"`
	}
	type jsonSecReport struct {
		GeneratedAt   time.Time    `json:"generated_at"`
		Node          string       `json:"node"`
		ScanDuration  string       `json:"scan_duration"`
		TotalCritical int          `json:"total_critical"`
		TotalHigh     int          `json:"total_high"`
		TotalMedium   int          `json:"total_medium"`
		Findings      []jsonFinding `json:"findings"`
	}

	findings := make([]jsonFinding, 0, len(entries))
	for _, e := range entries {
		findings = append(findings, jsonFinding{
			Guest: e.Guest, VMID: e.VMID, GuestType: e.GuestType, IPs: e.IPs,
			Port: e.Svc.Port, Protocol: e.Svc.Protocol, BindAddr: e.Svc.BindAddr,
			Severity: string(e.Svc.RiskLevel), Risk: e.Svc.RiskReason,
			Remediation: e.Svc.Remediation,
		})
	}

	report := jsonSecReport{
		GeneratedAt:   time.Now().UTC(),
		Node:          node,
		ScanDuration:  duration.Round(time.Millisecond).String(),
		TotalCritical: totalCritical, TotalHigh: totalHigh, TotalMedium: totalMedium,
		Findings: findings,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// RenderSecurityFullMarkdown writes a comprehensive audit: scores, Top 3, findings, roadmap.
func RenderSecurityFullMarkdown(w io.Writer, results []scanner.GuestScanResult,
	node string, duration time.Duration) error {

	entries, scores := collectSecurityEntries(results)
	p := func(format string, args ...interface{}) { fmt.Fprintf(w, format, args...) }

	totalCritical, totalHigh, totalMedium := countBySeverity(entries)
	p("# Security Audit — %s — %s\n\n", node, time.Now().Format("2006-01-02 15:04:05"))
	p("| Metric | Value |\n|---|---|\n")
	p("| Node | %s |\n", mdSafe(node))
	p("| Guests scanned | %d |\n", len(results))
	p("| CRITICAL findings | %d |\n", totalCritical)
	p("| HIGH findings | %d |\n", totalHigh)
	p("| MEDIUM findings | %d |\n", totalMedium)
	p("| Total findings | %d |\n", len(entries))
	p("| Scan duration | %s |\n\n", duration.Round(time.Millisecond))

	// Top 3 most exposed
	ranked := rankedGuests(scores)
	if len(ranked) > 0 {
		p("## Top Exposed Guests\n\n")
		p("| Rank | Guest | VMID | Score | CRITICAL | HIGH | MEDIUM |\n|---|---|---|---|---|---|---|\n")
		limit := 3
		if len(ranked) < limit {
			limit = len(ranked)
		}
		for i, gs := range ranked[:limit] {
			p("| #%d | %s | %d | %d/100 | %d | %d | %d |\n",
				i+1, mdSafe(gs.Name), gs.VMID, gs.Score, gs.Critical, gs.High, gs.Medium)
		}
		p("\n")
	}

	// Full attack surface table
	p("## Attack Surface by Guest\n\n")
	p("| Guest | VMID | Type | IPs | Score | CRITICAL | HIGH | MEDIUM |\n|---|---|---|---|---|---|---|---|\n")
	allGuests := rankedGuestsAll(scores)
	for _, gs := range allGuests {
		ipStr := strings.Join(gs.IPs, ", ")
		if ipStr == "" {
			ipStr = "-"
		}
		p("| %s | %d | %s | %s | %d | %d | %d | %d |\n",
			mdSafe(gs.Name), gs.VMID, gs.GuestType, mdSafe(ipStr),
			gs.Score, gs.Critical, gs.High, gs.Medium)
	}
	p("\n")

	// Findings by severity
	if len(entries) == 0 {
		p("## Findings\n\n_No security findings detected._\n\n")
	} else {
		for _, level := range []scanner.RiskLevel{scanner.RiskCritical, scanner.RiskHigh, scanner.RiskMedium} {
			group := filterBySeverity(entries, level)
			if len(group) == 0 {
				continue
			}
			p("## %s Findings (%d)\n\n", string(level), len(group))
			p("| Guest | VMID | Port | Protocol | Bind | Risk | Remediation |\n|---|---|---|---|---|---|---|\n")
			for _, e := range group {
				p("| %s | %d | %d | %s | %s | %s | %s |\n",
					mdSafe(e.Guest), e.VMID, e.Svc.Port, e.Svc.Protocol, e.Svc.BindAddr,
					mdSafe(e.Svc.RiskReason), mdSafe(e.Svc.Remediation))
			}
			p("\n")
		}
	}

	// Hardening roadmap (deduped by remediation text)
	if len(entries) > 0 {
		p("## Hardening Roadmap\n\nPrioritised actions — most critical first.\n\n")
		seen := map[string]bool{}
		rank := 1
		for _, level := range []scanner.RiskLevel{scanner.RiskCritical, scanner.RiskHigh, scanner.RiskMedium} {
			for _, e := range entries {
				if e.Svc.RiskLevel != level || seen[e.Svc.Remediation] {
					continue
				}
				seen[e.Svc.Remediation] = true
				p("%d. **[%s]** Port %d — %s  \n   _%s_\n", rank,
					string(level), e.Svc.Port, mdSafe(e.Svc.RiskReason), mdSafe(e.Svc.Remediation))
				rank++
			}
		}
		p("\n")
	}
	return nil
}

// RenderSecurityFullJSON writes the full security audit as JSON.
func RenderSecurityFullJSON(w io.Writer, results []scanner.GuestScanResult,
	node string, duration time.Duration) error {

	entries, scores := collectSecurityEntries(results)
	totalCritical, totalHigh, totalMedium := countBySeverity(entries)

	type jsonFinding struct {
		Guest       string   `json:"guest"`
		VMID        int      `json:"vmid"`
		GuestType   string   `json:"guest_type"`
		IPs         []string `json:"ips"`
		Port        int      `json:"port"`
		Protocol    string   `json:"protocol"`
		BindAddr    string   `json:"bind_addr"`
		Severity    string   `json:"severity"`
		Risk        string   `json:"risk"`
		Remediation string   `json:"remediation"`
	}
	type jsonGuestScore struct {
		VMID      int      `json:"vmid"`
		Name      string   `json:"name"`
		GuestType string   `json:"guest_type"`
		IPs       []string `json:"ips"`
		Score     int      `json:"attack_surface_score"`
		Critical  int      `json:"critical"`
		High      int      `json:"high"`
		Medium    int      `json:"medium"`
	}
	type jsonRoadmapItem struct {
		Rank        int    `json:"rank"`
		Severity    string `json:"severity"`
		Port        int    `json:"port"`
		Risk        string `json:"risk"`
		Remediation string `json:"remediation"`
	}
	type jsonSecFullReport struct {
		GeneratedAt   time.Time        `json:"generated_at"`
		Node          string           `json:"node"`
		ScanDuration  string           `json:"scan_duration"`
		TotalCritical int              `json:"total_critical"`
		TotalHigh     int              `json:"total_high"`
		TotalMedium   int              `json:"total_medium"`
		GuestScores   []jsonGuestScore `json:"guest_scores"`
		Findings      []jsonFinding    `json:"findings"`
		Roadmap       []jsonRoadmapItem `json:"hardening_roadmap"`
	}

	findings := make([]jsonFinding, 0, len(entries))
	for _, e := range entries {
		findings = append(findings, jsonFinding{
			Guest: e.Guest, VMID: e.VMID, GuestType: e.GuestType, IPs: e.IPs,
			Port: e.Svc.Port, Protocol: e.Svc.Protocol, BindAddr: e.Svc.BindAddr,
			Severity: string(e.Svc.RiskLevel), Risk: e.Svc.RiskReason,
			Remediation: e.Svc.Remediation,
		})
	}

	allGuests := rankedGuestsAll(scores)
	guestScores := make([]jsonGuestScore, len(allGuests))
	for i, gs := range allGuests {
		guestScores[i] = jsonGuestScore{
			VMID: gs.VMID, Name: gs.Name, GuestType: gs.GuestType, IPs: gs.IPs,
			Score: gs.Score, Critical: gs.Critical, High: gs.High, Medium: gs.Medium,
		}
	}

	seen := map[string]bool{}
	var roadmap []jsonRoadmapItem
	rank := 1
	for _, level := range []scanner.RiskLevel{scanner.RiskCritical, scanner.RiskHigh, scanner.RiskMedium} {
		for _, e := range entries {
			if e.Svc.RiskLevel != level || seen[e.Svc.Remediation] {
				continue
			}
			seen[e.Svc.Remediation] = true
			roadmap = append(roadmap, jsonRoadmapItem{
				Rank: rank, Severity: string(level),
				Port: e.Svc.Port, Risk: e.Svc.RiskReason, Remediation: e.Svc.Remediation,
			})
			rank++
		}
	}

	report := jsonSecFullReport{
		GeneratedAt:   time.Now().UTC(),
		Node:          node,
		ScanDuration:  duration.Round(time.Millisecond).String(),
		TotalCritical: totalCritical, TotalHigh: totalHigh, TotalMedium: totalMedium,
		GuestScores: guestScores, Findings: findings, Roadmap: roadmap,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func countBySeverity(entries []securityEntry) (critical, high, medium int) {
	for _, e := range entries {
		switch e.Svc.RiskLevel {
		case scanner.RiskCritical:
			critical++
		case scanner.RiskHigh:
			high++
		case scanner.RiskMedium:
			medium++
		}
	}
	return
}

func filterBySeverity(entries []securityEntry, level scanner.RiskLevel) []securityEntry {
	var out []securityEntry
	for _, e := range entries {
		if e.Svc.RiskLevel == level {
			out = append(out, e)
		}
	}
	return out
}

func rankedGuests(scores map[int]*guestScore) []*guestScore {
	var list []*guestScore
	for _, gs := range scores {
		if gs.Score > 0 {
			list = append(list, gs)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Score > list[j].Score })
	return list
}

func rankedGuestsAll(scores map[int]*guestScore) []*guestScore {
	var list []*guestScore
	for _, gs := range scores {
		list = append(list, gs)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Score != list[j].Score {
			return list[i].Score > list[j].Score
		}
		return list[i].VMID < list[j].VMID
	})
	return list
}
