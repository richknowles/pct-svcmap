package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/richknowles/pct-svcmap/proxmox"
	"github.com/richknowles/pct-svcmap/reporter"
	"github.com/richknowles/pct-svcmap/scanner"
	"github.com/richknowles/pct-svcmap/tagger"
)

const currentVersion = "v1.1.1"
const repoURL = "https://github.com/richknowles/pct-svcmap"
const authorName = "Rich Knowles"
const authorEmail = "rich@ajricardo.com"

func main() {
	// Custom help output
	flag.Usage = func() {
		fmt.Printf(`USAGE: pct-svcmap [COMMAND] [ARGS] [OPTIONS]

COMMANDS:
  scan      Scan guests (default, no command needed)
  check     Check for updates (alias: --check-update)
  update    Update to latest (alias: --self-update)

OPTIONS:
  --node string     Proxmox node name (default: hostname)
  --report string   Output format: md, json, summary, security, security-full
  --tag            Apply auto-generated tags to guests
  --filter string  Filter by guest name glob pattern
  --help          Show this help message
  --version       Show version info

EXAMPLES:
  pct-svcmap                           # Quick scan
  pct-svcmap --report md               # Full markdown report
  pct-svcmap --report security         # Security issues only
  pct-svcmap --tag --filter "web-*"     # Tag web-* guests
  pct-svcmap --check-update           # Check for updates

Developed by: %s %s
Bugs? Please open a PR on GitHub: %s
Home page: %s

`, authorName, authorEmail, repoURL+"/issues", repoURL)
	}

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
	checkUpdateFlag := flag.Bool("check-update", false, "Check for new version on GitHub")
	selfUpdateFlag := flag.Bool("self-update", false, "Download and install latest release")
	versionFlag := flag.Bool("version", false, "Show version info")

	flag.Parse()

	// Handle --version flag early
	if *versionFlag {
		fmt.Printf("pct-svcmap %s\n", currentVersion)
		fmt.Printf("Developed by: %s %s\n", authorName, authorEmail)
		fmt.Printf("Home page: %s\n", repoURL)
		return
	}

	// Handle --help flag early
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		flag.Usage()
		return
	}

	// Parse first arg as potential command
	var command string
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		command = os.Args[1]
		// Strip the command from os.Args for flag parsing
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		flag.Parse()
	} else {
		flag.Parse()
	}

	// Handle commands
	switch command {
	case "check":
		*checkUpdateFlag = true
	case "update":
		*selfUpdateFlag = true
	}

	// Handle check-update flag early
	if *checkUpdateFlag {
		checkForUpdate()
		return
	}

	// Handle self-update
	if *selfUpdateFlag {
		doSelfUpdate()
		return
	}

	_ = nmapFlag
	_ = nmapTargetFlag

	// Parse tag categories
	tagCategories := parseTagCategories(*tagCategoriesFlag)

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

func checkForUpdate() {
	fmt.Printf("pct-svcmap %s\n", currentVersion)
	fmt.Println("Developed by:", authorName, authorEmail)
	fmt.Println()

	// Without GitHub token, rate limits apply. Try the releases page instead.

	// Without GitHub token, rate limits apply. Try the releases page instead.
	resp, err := http.Get(repoURL + "/releases")
	if err != nil {
		fmt.Println("Could not fetch latest release:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Could not fetch latest release")
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Look for the latest release tag in HTML
	tagRe := regexp.MustCompile(`/releases/tag/(v[0-9.]+)"`)
	m := tagRe.FindStringSubmatch(string(body))
	if m != nil {
		latest := strings.TrimPrefix(m[1], "v")
		current := strings.TrimPrefix(currentVersion, "v")

		if latest != current {
			fmt.Printf("🔄 Update available: v%s → v%s\n", current, latest)
			fmt.Printf("Download: %s/releases\n", repoURL)
		} else {
			fmt.Println("✅ You are running the latest version")
		}
		return
	}

	// Final fallback
	fmt.Println("ℹ️  Latest version info unavailable (API rate limited)")
	fmt.Println("👉 Check manually:", repoURL+"/releases")
}

func doSelfUpdate() {
	fmt.Printf("pct-svcmap %s\n", currentVersion)
	fmt.Println("Checking for updates...")

	resp, err := http.Get(repoURL + "/releases")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Find latest release asset
	releaseRe := regexp.MustCompile(`/releases/download/(v[0-9.]+)/pct-svcmap"`)
	m := releaseRe.FindStringSubmatch(string(body))

	// Also try alternatives for different OS/arch
	if m == nil {
		// Try linux amd64
		m = regexp.MustCompile(`/releases/download/(v[0-9.]+)/pct-svcmap"`).FindStringSubmatch(string(body))
	}

	if m == nil {
		fmt.Println("❌ Could not find release download URL")
		fmt.Println("👉 Visit", repoURL, "to download manually")
		return
	}

	latest := m[1]
	current := strings.TrimPrefix(currentVersion, "v")

	if latest == current {
		fmt.Println("✅ You are running the latest version")
		return
	}

	fmt.Printf("🔄 Updating from v%s to v%s\n", current, latest)

	downloadURL := fmt.Sprintf("%s/releases/download/%s/pct-svcmap", repoURL, latest)

	// Download to temp file
	tmpFile := "/tmp/pct-svcmap-" + latest
	resp2, err := http.Get(downloadURL)
	if err != nil {
		fmt.Println("Error downloading:", err)
		return
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		fmt.Println("Error: Download returned", resp2.StatusCode)
		return
	}

	f, err := os.Create(tmpFile)
	if err != nil {
		fmt.Println("Error creating temp file:", err)
		return
	}
	defer f.Close()

	_, err = io.Copy(f, resp2.Body)
	if err != nil {
		fmt.Println("Error saving:", err)
		return
	}
	f.Close()

	// Make executable and replace
	os.Chmod(tmpFile, 0755)

	// Find current binary path
	selfPath, err := os.Executable()
	if err != nil {
		selfPath = "/usr/local/bin/pct-svcmap"
	}

	backupPath := selfPath + ".bak"
	os.Rename(selfPath, backupPath)
	os.Rename(tmpFile, selfPath)

	fmt.Printf("✅ Updated to v%s\n", latest)
	fmt.Printf("Run pct-svcmap --check-update to verify\n")
}
