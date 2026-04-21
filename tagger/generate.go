package tagger

import (
	"regexp"
	"sort"
	"strings"

	"github.com/richknowles/pct-svcmap/scanner"
)

// portTags maps well-known ports to semantic tag names.
var portTags = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	389:   "ldap",
	443:   "https",
	636:   "ldaps",
	3000:  "grafana",
	3306:  "mysql",
	5000:  "registry",
	5432:  "postgres",
	5601:  "kibana",
	6379:  "redis",
	6443:  "k8s-api",
	8080:  "http-alt",
	8443:  "https-alt",
	9090:  "prometheus",
	9200:  "elasticsearch",
	9300:  "elasticsearch",
	27017: "mongodb",
}

// GenerateTags derives new tags from a GuestScanResult.
// Returns only newly generated tags; merging with existing is done in merge.go.
func GenerateTags(result scanner.GuestScanResult) []string {
	set := map[string]bool{}

	// Guest type tag
	if result.GuestType == "lxc" {
		set["lxc"] = true
	} else {
		set["vm"] = true
	}

	// Port-based tags
	for _, svc := range result.Services {
		if tag, ok := portTags[svc.Port]; ok {
			set[tag] = true
		}
	}

	// Docker host tag
	if result.DockerAvailable {
		set["docker"] = true
		for _, tag := range TagsFromDockerContainers(result.DockerContainers) {
			set[tag] = true
		}
	}

	// Risky service tag
	for _, svc := range result.Services {
		if svc.IsRisky {
			set["risky"] = true
			break
		}
	}

	// Multi-IP tag
	if len(result.IPs) > 1 {
		set["multi-ip"] = true
	}

	// No-agent tag for QEMU guests without a responding agent
	if result.GuestType == "qemu" && !result.AgentAvailable {
		set["no-agent"] = true
	}

	return deduplicateTags(setToSlice(set))
}

// TagsFromDockerContainers extracts image-based tags from container images.
func TagsFromDockerContainers(containers []scanner.DockerContainer) []string {
	set := map[string]bool{}
	for _, c := range containers {
		name := c.Image
		// Strip tag portion (e.g. "nginx:latest" → "nginx")
		if idx := strings.Index(name, ":"); idx >= 0 {
			name = name[:idx]
		}
		// Strip repo prefix (e.g. "library/nginx" → "nginx")
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		tag := sanitizeTag(name)
		if tag != "" {
			set[tag] = true
		}
	}
	return setToSlice(set)
}

var sanitizeRegexp = regexp.MustCompile(`[^a-z0-9-]`)

// sanitizeTag converts a string to a valid lowercase Proxmox tag.
func sanitizeTag(s string) string {
	s = strings.ToLower(s)
	s = sanitizeRegexp.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

func deduplicateTags(tags []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range tags {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

func setToSlice(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}
