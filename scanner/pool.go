package scanner

import (
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/richknowles/pct-svcmap/proxmox"
)

// ScanAll enumerates all guests, filters them, then fans out to a worker pool.
func ScanAll(client *proxmox.NodeClient, cfg ScanConfig) ([]GuestScanResult, error) {
	lxcs, err := client.ListLXC()
	if err != nil {
		return nil, fmt.Errorf("list LXC: %w", err)
	}
	qemus, err := client.ListQEMU()
	if err != nil {
		return nil, fmt.Errorf("list QEMU: %w", err)
	}

	var guests []proxmox.Guest
	for _, l := range lxcs {
		if !cfg.IncludeStopped && l.Status != "running" {
			continue
		}
		if !matchesFilter(l.Name, cfg.FilterGlob) {
			continue
		}
		guests = append(guests, proxmox.Guest{
			VMID: l.VMID, Name: l.Name, Status: l.Status,
			Type: proxmox.GuestTypeLXC, Tags: l.Tags,
			MaxMemMB: l.MaxMem / 1024 / 1024, CPUs: l.CPUs,
		})
	}
	for _, q := range qemus {
		if !cfg.IncludeStopped && q.Status != "running" {
			continue
		}
		if !matchesFilter(q.Name, cfg.FilterGlob) {
			continue
		}
		guests = append(guests, proxmox.Guest{
			VMID: q.VMID, Name: q.Name, Status: q.Status,
			Type: proxmox.GuestTypeQEMU, Tags: q.Tags,
			MaxMemMB: q.MaxMem / 1024 / 1024, CPUs: q.CPUs,
		})
	}

	if len(guests) == 0 {
		return nil, nil
	}

	return runWorkerPool(guests, cfg, client), nil
}

func runWorkerPool(guests []proxmox.Guest, cfg ScanConfig, client *proxmox.NodeClient) []GuestScanResult {
	jobs := make(chan proxmox.Guest, len(guests))
	results := make(chan GuestScanResult, len(guests))

	var wg sync.WaitGroup
	workers := cfg.Workers
	if workers < 1 {
		workers = 1
	}
	if workers > len(guests) {
		workers = len(guests)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for guest := range jobs {
				results <- scanGuest(guest, cfg, client)
			}
		}()
	}

	for _, g := range guests {
		jobs <- g
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var out []GuestScanResult
	for r := range results {
		out = append(out, r)
	}
	return out
}

func scanGuest(guest proxmox.Guest, cfg ScanConfig, client *proxmox.NodeClient) GuestScanResult {
	result := GuestScanResult{
		VMID:        guest.VMID,
		Name:        guest.Name,
		GuestType:   string(guest.Type),
		Status:      guest.Status,
		ExistingTags: guest.Tags,
		ScannedAt:   time.Now(),
	}

	if guest.Status != "running" {
		result.DetectionMethod = DetectionSkipped
		result.ScanError = "guest is not running"
		return result
	}

	// Fetch IPs
	var ipErr error
	if guest.Type == proxmox.GuestTypeLXC {
		result.IPs, ipErr = client.GetLXCIPs(guest.VMID)
	} else {
		result.AgentAvailable = client.CheckQEMUAgent(guest.VMID)
		if !result.AgentAvailable {
			result.DetectionMethod = DetectionSkipped
			result.ScanError = "QEMU guest agent not available"
			return result
		}
		result.IPs, ipErr = client.GetQEMUIPs(guest.VMID)
	}
	if ipErr != nil && cfg.Verbose {
		log.Printf("[%s/%d] IP fetch error: %v", guest.Name, guest.VMID, ipErr)
	}

	// Detect services
	svcs, method, svcErr := DetectServices(guest, client)
	result.Services = svcs
	result.DetectionMethod = method
	if svcErr != nil {
		result.ScanError = svcErr.Error()
		if cfg.Verbose {
			log.Printf("[%s/%d] service detection: %v", guest.Name, guest.VMID, svcErr)
		}
	}

	// Detect Docker
	containers, available, dockerErr := DetectDocker(guest, client)
	result.DockerAvailable = available
	result.DockerContainers = containers
	if dockerErr != nil && cfg.Verbose {
		log.Printf("[%s/%d] docker: %v", guest.Name, guest.VMID, dockerErr)
	}

	return result
}

func matchesFilter(name, pattern string) bool {
	if pattern == "" {
		return true
	}
	matched, err := filepath.Match(pattern, name)
	return err == nil && matched
}
