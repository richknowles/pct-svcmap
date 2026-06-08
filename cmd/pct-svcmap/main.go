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

const currentVersion = "v1.2.0"
const repoURL = "https://github.com/richknowles/pct-svcmap"
const authorName = "Rich Knowles"
const authorEmail = "rich@ajricardo.com"

func main() {
	flag.Usage = func() {
		fmt.Printf(`USAGE: pct-svcmap [COMMAND] [ARGS] [OPTIONS]

COMMANDS:
  scan      Scan guests (default, no command needed)
  check     Check for updates (alias: --check-update)
  update    Update to latest (alias: --self-update)

OPTIONS:
  --node string          Proxmox node name (default: hostname)
  --report string        Output type: md, json, summary, security, security-full
  --format string        Output format for summary/security: md, json (default: md)
  --tag                  Apply auto-generated tags to guests
  --tag-categories       Tag categories: type,ports,docker,security,network,all
  --notes                Write auto-generated Markdown to guest notes fields
  --notes-format string  Notes sections: links,alerts,domains,all (default: all)
  --dry-run              Preview changes (requires --tag or --notes)
  --filter string        Filter guests by name glob pattern
  --nmap string          nmap cross-validation mode: quick, default, full
  --include-stopped      Include stopped/paused guests
  --workers int          Concurrent worker count (default: 10)
  --timeout int          Per-exec timeout in seconds (default: 5)
  --verbose              Verbose logging to stderr
  --version              Show version info
  --check-update         Check for updates on GitHub
  --self-update          Download and install latest release

EXAMPLES:
  pct-svcmap                                    # Quick scan
  pct-svcmap --report md                        # Full markdown report
  pct-svcmap --report security                  # Security issues only
  pct-svcmap --tag --filter "web-*"             # Tag web-* guests
  pct-svcmap --notes --notes-format links,alerts # Write notes with links and alerts
  pct-svcmap --notes --dry-run                  # Preview notes without writing
  pct-svcmap --check-update                     # Check for updates

Developed by: %s <%s>
Bugs? %s
Home page: %s

`, authorName, authorEmail, repoURL+"/issues", repoURL)
	}

	nodeFlag := flag.String("node", defaultHostname(), "Proxmox node name")
	workersFlag := flag.Int("workers", 10, "Concurrent worker count")
	timeoutFlag := flag.Int("timeout", 5, "Per-exec timeout in seconds")
	reportFlag := flag.String("report", "", "Report type: md, json, summary, security, security-full")
	formatFlag := flag.String("format", "md", "Output format for summary/security reports: md, json")
	outputFlag := flag.String("output", "", "Write report to file (default: stdout)")
	tagFlag := flag.Bool("tag", false, "Apply auto-generated tags to guests")
	dryRunFlag := flag.Bool("dry-run", false, "Show what would be applied (requires --tag or --notes)")
	tagCategoriesFlag := flag.String("tag-categories", "all", "Tag categories: type,ports,docker,security,network,all")
	notesFlag := flag.Bool("notes", false, "Write auto-generated Markdown to each guest's Proxmox notes field")
	notesFormatFlag := flag.String("notes-format", "all", "Notes sections: links,alerts,domains,all")
	filterFlag := flag.String("filter", "", "Filter by guest name glob pattern (filepath.Match)")
	includeStoppedFlag := flag.Bool("include-stopped", false, "Include stopped/paused guests")
	nmapFlag := flag.String("nmap", "", "nmap cross-validation mode: quick, default, full")
	verboseFlag := flag.Bool("verbose", false, "Verbose logging to stderr")
	checkUpdateFlag := flag.Bool("check-update", false, "Check for new version on GitHub")
	selfUpdateFlag := flag.Bool("self-update", false, "Download and install latest release")
	versionFlag := flag.Bool("version", false, "Show version info")

	// Parse first positional arg as potential command alias
	var command string
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		command = os.Args[1]
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
	}
	flag.Parse()

	switch command {
	case "check":
		*checkUpdateFlag = true
	case "update":
		*selfUpdateFlag = true
	}

	if *versionFlag {
		fmt.Printf("pct-svcmap %s\n", currentVersion)
		fmt.Printf("Developed by: %s <%s>\n", authorName, authorEmail)
		fmt.Printf("Home page: %s\n", repoURL)
		return
	}
	if *checkUpdateFlag {
		checkForUpdate()
		return
	}
	if *selfUpdateFlag {
		doSelfUpdate()
		return
	}

	if *dryRunFlag && !*tagFlag && !*notesFlag {
		fmt.Fprintln(os.Stderr, "error: --dry-run requires --tag or --notes")
		os.Exit(1)
	}
	validReports := map[string]bool{
		"": true, "md": true, "json": true,
		"summary": true, "security": true, "security-full": true,
	}
	if !validReports[*reportFlag] {
		fmt.Fprintln(os.Stderr, "error: --report must be md, json, summary, security, or security-full")
		os.Exit(1)
	}
	if *formatFlag != "md" && *formatFlag != "json" {
		fmt.Fprintln(os.Stderr, "error: --format must be md or json")
		os.Exit(1)
	}
	validNmap := map[string]bool{"": true, "quick": true, "default": true, "full": true}
	if !validNmap[*nmapFlag] {
		fmt.Fprintln(os.Stderr, "error: --nmap must be quick, default, or full")
		os.Exit(1)
	}

	categories := tagger.ParseCategories(*tagCategoriesFlag)
	notesFormats := reporter.ParseNotesFormats(*notesFormatFlag)

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
		NmapMode:       *nmapFlag,
	}
	mergeCfg := tagger.MergeConfig{
		DryRun:     *dryRunFlag,
		Verbose:    *verboseFlag,
		Categories: categories,
	}

	start := time.Now()
	results, err := scanner.ScanAll(nodeClient, scanCfg)
	if err != nil {
		log.Fatalf("scan failed: %v", err)
	}
	duration := time.Since(start)

	for i := range results {
		results[i].GeneratedTags = tagger.GenerateTags(results[i], categories)
	}

	var diffs []tagger.TagDiff
	if *tagFlag {
		for _, result := range results {
			gtype := proxmox.GuestType(result.GuestType)
			diff, applyErr := tagger.ApplyTags(result, nodeClient, gtype, mergeCfg)
			if applyErr != nil && *verboseFlag {
				log.Printf("tagging failed for %s (%d): %v", result.Name, result.VMID, applyErr)
			}
			diffs = append(diffs, diff)
		}
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

	if *notesFlag {
		for i := range results {
			r := &results[i]
			gtype := proxmox.GuestType(r.GuestType)
			newBlock := reporter.BuildGuestNote(*r, notesFormats)

			if *dryRunFlag {
				fmt.Fprintf(os.Stderr, "--- dry-run notes for %s (%d) ---\n%s\n", r.Name, r.VMID, newBlock)
				continue
			}

			existing, getErr := nodeClient.GetGuestNotes(r.VMID, gtype)
			if getErr != nil {
				if *verboseFlag {
					log.Printf("get notes failed for %s (%d): %v", r.Name, r.VMID, getErr)
				}
				continue
			}
			merged := reporter.InjectNote(existing, newBlock)
			if setErr := nodeClient.SetGuestNotes(r.VMID, gtype, merged); setErr != nil {
				if *verboseFlag {
					log.Printf("set notes failed for %s (%d): %v", r.Name, r.VMID, setErr)
				}
				continue
			}
			r.NotesApplied = true
		}
	}

	out := os.Stdout
	if *outputFlag != "" {
		f, createErr := os.Create(*outputFlag)
		if createErr != nil {
			log.Fatalf("cannot open output file: %v", createErr)
		}
		defer f.Close()
		out = f
	}

	var renderErr error
	switch *reportFlag {
	case "md":
		renderErr = reporter.RenderMarkdown(out, results, diffs, *nodeFlag, duration)
	case "json":
		renderErr = reporter.RenderJSON(out, results, diffs, *nodeFlag, duration)
	case "summary":
		if *formatFlag == "json" {
			renderErr = reporter.RenderSummaryJSON(out, results, *nodeFlag, duration)
		} else {
			renderErr = reporter.RenderSummaryMarkdown(out, results, *nodeFlag, duration)
		}
	case "security":
		if *formatFlag == "json" {
			renderErr = reporter.RenderSecurityJSON(out, results, *nodeFlag, duration)
		} else {
			renderErr = reporter.RenderSecurityMarkdown(out, results, *nodeFlag, duration)
		}
	case "security-full":
		if *formatFlag == "json" {
			renderErr = reporter.RenderSecurityFullJSON(out, results, *nodeFlag, duration)
		} else {
			renderErr = reporter.RenderSecurityFullMarkdown(out, results, *nodeFlag, duration)
		}
	default:
		printSummaryTable(results, diffs, duration)
	}
	if renderErr != nil {
		log.Fatalf("render failed: %v", renderErr)
	}
}

func defaultHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return h
}

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

func checkForUpdate() {
	fmt.Printf("pct-svcmap %s\n", currentVersion)
	fmt.Printf("Developed by: %s <%s>\n", authorName, authorEmail)
	fmt.Println()

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

	tagRe := regexp.MustCompile(`/releases/tag/(v[0-9.]+)"`)
	m := tagRe.FindStringSubmatch(string(body))
	if m != nil {
		latest := strings.TrimPrefix(m[1], "v")
		current := strings.TrimPrefix(currentVersion, "v")
		if latest != current {
			fmt.Printf("Update available: %s -> %s\n", currentVersion, m[1])
			fmt.Printf("Download: %s/releases\n", repoURL)
		} else {
			fmt.Println("You are running the latest version")
		}
		return
	}

	fmt.Println("Latest version info unavailable (API rate limited)")
	fmt.Println("Check manually:", repoURL+"/releases")
}

func doSelfUpdate() {
	fmt.Printf("pct-svcmap %s — checking for updates...\n", currentVersion)

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

	releaseRe := regexp.MustCompile(`/releases/download/(v[0-9.]+)/pct-svcmap"`)
	m := releaseRe.FindStringSubmatch(string(body))
	if m == nil {
		fmt.Println("Could not find release download URL")
		fmt.Println("Visit", repoURL, "to download manually")
		return
	}

	latest := m[1]
	if strings.TrimPrefix(latest, "v") == strings.TrimPrefix(currentVersion, "v") {
		fmt.Println("You are running the latest version")
		return
	}

	fmt.Printf("Updating to %s...\n", latest)
	downloadURL := fmt.Sprintf("%s/releases/download/%s/pct-svcmap", repoURL, latest)

	tmpFile := "/tmp/pct-svcmap-" + latest
	resp2, err := http.Get(downloadURL)
	if err != nil {
		fmt.Println("Error downloading:", err)
		return
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		fmt.Println("Error: download returned", resp2.StatusCode)
		return
	}

	f, err := os.Create(tmpFile)
	if err != nil {
		fmt.Println("Error creating temp file:", err)
		return
	}
	_, copyErr := io.Copy(f, resp2.Body)
	f.Close()
	if copyErr != nil {
		fmt.Println("Error saving:", copyErr)
		return
	}

	os.Chmod(tmpFile, 0755)
	selfPath, err := os.Executable()
	if err != nil {
		selfPath = "/usr/local/bin/pct-svcmap"
	}
	os.Rename(selfPath, selfPath+".bak")
	os.Rename(tmpFile, selfPath)
	fmt.Printf("Updated to %s\n", latest)
}
