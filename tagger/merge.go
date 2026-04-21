package tagger

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/rightontron/pct-svcmap/proxmox"
	"github.com/rightontron/pct-svcmap/scanner"
)

// MergeConfig controls tagging behavior.
type MergeConfig struct {
	DryRun  bool
	Verbose bool
}

// TagDiff represents the before/after tag state for one guest.
type TagDiff struct {
	VMID         int
	Name         string
	ExistingTags []string
	NewTags      []string
	MergedTags   []string
	TagString    string
	WouldChange  bool
}

// ApplyTags generates tags, merges with existing ones, and writes to Proxmox
// unless DryRun is set. Always returns a TagDiff describing the change.
func ApplyTags(result scanner.GuestScanResult, client *proxmox.NodeClient,
	gtype proxmox.GuestType, cfg MergeConfig) (TagDiff, error) {

	existing := ParseTagString(result.ExistingTags)
	generated := GenerateTags(result)
	newOnly := diffTags(existing, generated)
	merged := unionTags(existing, generated)

	diff := TagDiff{
		VMID:         result.VMID,
		Name:         result.Name,
		ExistingTags: existing,
		NewTags:      newOnly,
		MergedTags:   merged,
		TagString:    FormatTagString(merged),
		WouldChange:  len(newOnly) > 0,
	}

	if !diff.WouldChange {
		if cfg.Verbose {
			log.Printf("[%s/%d] tags: no new tags to add", result.Name, result.VMID)
		}
		return diff, nil
	}

	if cfg.DryRun {
		log.Printf("[dry-run] %s (%d): would add tags: %s", result.Name, result.VMID,
			strings.Join(newOnly, ", "))
		return diff, nil
	}

	if err := client.SetGuestTags(result.VMID, gtype, diff.TagString); err != nil {
		return diff, fmt.Errorf("set tags for %s (%d): %w", result.Name, result.VMID, err)
	}

	if cfg.Verbose {
		log.Printf("[%s/%d] tags applied: %s", result.Name, result.VMID, diff.TagString)
	}
	return diff, nil
}

// ParseTagString splits a Proxmox tag string into a sorted, deduplicated slice.
// Handles both ";" and "," as delimiters.
func ParseTagString(tagStr string) []string {
	if strings.TrimSpace(tagStr) == "" {
		return []string{}
	}
	// Normalize delimiters
	normalized := strings.ReplaceAll(tagStr, ",", ";")
	parts := strings.Split(normalized, ";")
	var tags []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			tags = append(tags, strings.ToLower(p))
		}
	}
	return deduplicateTags(tags)
}

// FormatTagString joins tags into a Proxmox-compatible semicolon-delimited string.
func FormatTagString(tags []string) string {
	sorted := make([]string, len(tags))
	copy(sorted, tags)
	sort.Strings(sorted)
	return strings.Join(sorted, ";")
}

// unionTags returns a sorted union of two tag slices with no duplicates.
func unionTags(existing, generated []string) []string {
	set := map[string]bool{}
	for _, t := range existing {
		set[t] = true
	}
	for _, t := range generated {
		set[t] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// diffTags returns tags in generated that are not already in existing.
func diffTags(existing, generated []string) []string {
	existSet := map[string]bool{}
	for _, t := range existing {
		existSet[t] = true
	}
	var diff []string
	for _, t := range generated {
		if !existSet[t] {
			diff = append(diff, t)
		}
	}
	return diff
}
