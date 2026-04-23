package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/richknowles/pct-svcmap/proxmox"
	"github.com/richknowles/pct-svcmap/reporter"
	"github.com/richknowles/pct-svcmap/scanner"
	"github.com/richknowles/pct-svcmap/tagger"
)

func main() {
nodeFlag := flag.String("node", defaultHostname(), "Proxmox node name")
	workersFlag := flag.Int("workers", 10, "Concurrent worker count")
	timeoutFlag := flag.Int("timeout", 5, "Per-exec timeout in seconds")
	reportFlag := flag.String("report", "", "Output format: md, json, summary, security, security-full")
	reportFormatFlag := flag.String("report-format", "md", "Report format when using summary/security: md or json")
	outputFlag := flag.String("output", "", "Write report to file (default: stdout)")
	tagFlag := flag.Bool("tag", false, "Apply auto-generated tags to guests")
	tagCategoriesFlag := flag.String("tag-categories", "all", "Tag categories: all, type, ports, docker, security, network")
	dryRunFlag := flag.Bool("dry-run", false, "Show tags that would be applied (requires --tag)")
	filterFlag := flag.String("filter", "", "Filter by guest name glob pattern (filepath.Match)")
	includeStoppedFlag := flag.Bool("include-stopped", false, "Include stopped/paused guests")
	verboseFlag := flag.Bool("verbose", false, "Verbose logging to stderr")
	nmapFlag := flag.String("nmap", "", "Nmap scan mode: quick, default, full")
	nmapTargetFlag := flag.String("nmap-target", "localhost", "Target for nmap scan")

	flag.Parse()

	_ = nmapFlag
	_ = nmapTargetFlag

	// Parse tag categories
	tagCategories := parseTagCategories(*tagCategoriesFlag)

	// Validate report flag

	// Validate report flag
	validReports := map[string]bool{
		"md": true, "json": true, "summary": true, "security": true, "security-full": true,
	}
	if *reportFlag != "" && !validReports[*reportFlag] {
		fmt.Fprintln(os.Stderr, "error: --report must be 'md', 'json', 'summary', 'security', or 'security-full'")
		os.Exit(1)
	}

	if *dryRunFlag && !*tagFlag {
		fmt.Fprintln(os.Stderr, "error: --dry-run requires --tag")
		os.Exit(1)
	}

	execCfg := proxmox.ExecConfig{
		TimeoutSecs: *timeoutFlag,
		Verbose:     *verboseFlag,
	}
	nodeClient := &proxmox.NodeClient{
		Node: *nodeFlag,
		Cfg:  execCfg,
	}
	scanCfg := scanner.ScanConfig{
		Node:           *nodeFlag,
		Workers:        *workersFlag,
		TimeoutSecs:    *timeoutFlag,
		IncludeStopped: *includeStoppedFlag,
		FilterGlob:     *filterFlag,
		Verbose:        *verboseFlag,
	}
	mergeCfg := tagger.MergeConfig{
		DryRun:  *dryRunFlag,
		Verbose: *verboseFlag,
	}

	start := time.Now()
	results, err := scanner.ScanAll(nodeClient, scanCfg)
	if err != nil {
		log.Fatalf("scan failed: %v", err)
	}
	duration := time.Since(start)

	// Generate tags into each result (always, even if not writing)
	for i := range results {
		results[i].GeneratedTags = tagger.GenerateTags(results[i], tagCategories...)
	}

	// Apply tags if requested
	var diffs []tagger.TagDiff
	if *tagFlag {
		for _, result := range results {
			gtype := proxmox.GuestType(result.GuestType)
			diff, applyErr := tagger.ApplyTags(result, nodeClient, gtype, mergeCfg)
			if applyErr != nil {
				if *verboseFlag {
					log.Printf("tagging failed for %s (%d): %v", result.Name, result.VMID, applyErr)
				}
			}
			diffs = append(diffs, diff)
		}
		// Mark applied results
		diffMap := map[int]bool{}
		for _, d := range diffs {
			if d.WouldChange && !mergeCfg.DryRun {
				diffMap[d.VMID] = true
			}
		}
		for i := range results {
			if diffMap[results[i].VMID] {
				results[i].TagsApplied = true
			}
		}
	}

	// Determine output writer
	out := os.Stdout
	if *outputFlag != "" {
		f, createErr := os.Create(*outputFlag)
		if createErr != nil {
			log.Fatalf("cannot open output file: %v", createErr)
		}
		defer f.Close()
		out = f
	}

	// Render report
	switch *reportFlag {
	case "md", "json":
		if *reportFlag == "md" {
			if err := reporter.RenderMarkdown(out, results, diffs, *nodeFlag, duration); err != nil {
				log.Fatalf("markdown render failed: %v", err)
			}
		} else {
			if err := reporter.RenderJSON(out, results, diffs, *nodeFlag, duration); err != nil {
				log.Fatalf("json render failed: %v", err)
			}
		}
	case "summary":
		if *reportFormatFlag == "json" {
			if err := reporter.RenderSummaryJSON(out, results, *nodeFlag, duration); err != nil {
				log.Fatalf("summary json render failed: %v", err)
			}
		} else {
			if err := reporter.RenderSummaryMarkdown(out, results, *nodeFlag, duration); err != nil {
				log.Fatalf("summary markdown render failed: %v", err)
			}
		}
	case "security":
		if *reportFormatFlag == "json" {
			if err := reporter.RenderSecurityJSON(out, results, *nodeFlag, duration); err != nil {
				log.Fatalf("security json render failed: %v", err)
			}
		} else {
			if err := reporter.RenderSecurityMarkdown(out, results, *nodeFlag, duration); err != nil {
				log.Fatalf("security markdown render failed: %v", err)
			}
		}
	case "security-full":
		if *reportFormatFlag == "json" {
			if err := reporter.RenderSecurityFullJSON(out, results, *nodeFlag, duration); err != nil {
				log.Fatalf("security-full json render failed: %v", err)
			}
		} else {
			if err := reporter.RenderSecurityFullMarkdown(out, results, *nodeFlag, duration); err != nil {
				log.Fatalf("security-full markdown render failed: %v", err)
			}
		}
	default:
		printSummaryTable(results, diffs, duration)
	}
}

func defaultHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return h
}

// printSummaryTable outputs a compact table when --report is not specified.
func printSummaryTable(results []scanner.GuestScanResult, diffs []tagger.TagDiff, duration time.Duration) {
	diffMap := map[int]tagger.TagDiff{}
	for _, d := range diffs {
		diffMap[d.VMID] = d
	}

	sorted := make([]scanner.GuestScanResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].VMID < sorted[j].VMID })

	fmt.Printf("%-6s  %-24s  %-5s  %-8s  %-20s  %-8s  %-6s  %s\n",
		"VMID", "NAME", "TYPE", "STATUS", "IPs", "SERVICES", "DOCKER", "TAGS")
	fmt.Println(strings.Repeat("-", 100))

	for _, r := range sorted {
		ipStr := strings.Join(r.IPs, ",")
		if ipStr == "" {
			ipStr = "-"
		}
		if len(ipStr) > 20 {
			ipStr = ipStr[:18] + ".."
		}
		docker := "no"
		if r.DockerAvailable {
			docker = "yes"
		}
		allTags := tagger.ParseTagString(r.ExistingTags)
		if d, ok := diffMap[r.VMID]; ok {
			allTags = d.MergedTags
		} else if len(r.GeneratedTags) > 0 {
			allTags = tagger.ParseTagString(
				tagger.FormatTagString(append(tagger.ParseTagString(r.ExistingTags), r.GeneratedTags...)),
			)
		}
		tagStr := strings.Join(allTags, ",")
		if tagStr == "" {
			tagStr = "-"
		}
		name := r.Name
		if len(name) > 24 {
			name = name[:22] + ".."
		}
		fmt.Printf("%-6d  %-24s  %-5s  %-8s  %-20s  %-8d  %-6s  %s\n",
			r.VMID, name, r.GuestType, r.Status, ipStr,
			len(r.Services), docker, tagStr)
	}

	fmt.Printf("\nScanned %d guests in %s\n", len(results), duration.Round(time.Millisecond))
}

func parseTagCategories(catStr string) []tagger.TagCategory {
	catStr = strings.ToLower(strings.TrimSpace(catStr))
	if catStr == "" || catStr == "all" {
		return []tagger.TagCategory{tagger.CategoryAll}
	}
	var cats []tagger.TagCategory
	for _, c := range strings.Split(catStr, ",") {
		c = strings.TrimSpace(c)
		switch c {
		case "type":
			cats = append(cats, tagger.CategoryType)
		case "ports":
			cats = append(cats, tagger.CategoryPorts)
		case "docker":
			cats = append(cats, tagger.CategoryDocker)
		case "security":
			cats = append(cats, tagger.CategorySecurity)
		case "network":
			cats = append(cats, tagger.CategoryNetwork)
		case "all":
			cats = append(cats, tagger.CategoryAll)
		}
	}
	if len(cats) == 0 {
		return []tagger.TagCategory{tagger.CategoryAll}
	}
	return cats
}
