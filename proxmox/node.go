package proxmox

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NodeClient wraps ExecConfig and node name for all Proxmox API calls.
type NodeClient struct {
	Node string
	Cfg  ExecConfig
}

// ListLXC returns all LXC containers on the node.
func (c *NodeClient) ListLXC() ([]LXCGuest, error) {
	data, err := RunCommand(c.Cfg, "pvesh", "get",
		fmt.Sprintf("/nodes/%s/lxc", c.Node),
		"--output-format", "json",
	)
	if err != nil {
		return nil, fmt.Errorf("list lxc: %w", err)
	}
	var guests []LXCGuest
	if err := json.Unmarshal(data, &guests); err != nil {
		return nil, fmt.Errorf("parse lxc list: %w", err)
	}
	return guests, nil
}

// ListQEMU returns all QEMU VMs on the node.
func (c *NodeClient) ListQEMU() ([]QEMUGuest, error) {
	data, err := RunCommand(c.Cfg, "pvesh", "get",
		fmt.Sprintf("/nodes/%s/qemu", c.Node),
		"--output-format", "json",
	)
	if err != nil {
		return nil, fmt.Errorf("list qemu: %w", err)
	}
	var guests []QEMUGuest
	if err := json.Unmarshal(data, &guests); err != nil {
		return nil, fmt.Errorf("parse qemu list: %w", err)
	}
	return guests, nil
}

// GetLXCIPs executes `ip -j addr` inside an LXC container and returns
// all non-loopback IPv4 addresses.
func (c *NodeClient) GetLXCIPs(vmid int) ([]string, error) {
	data, err := c.ExecInLXC(vmid, "ip", "-j", "addr")
	if err != nil {
		return nil, err
	}
	return parseIPsFromLXC(data)
}

// GetQEMUIPs fetches IPs via qm guest network-get-interfaces.
func (c *NodeClient) GetQEMUIPs(vmid int) ([]string, error) {
	data, err := RunCommand(c.Cfg, "qm", "guest", "network-get-interfaces",
		fmt.Sprintf("%d", vmid),
	)
	if err != nil {
		return nil, err
	}
	return parseIPsFromQEMU(data)
}

// CheckQEMUAgent returns true if the QEMU guest agent responds within timeout.
func (c *NodeClient) CheckQEMUAgent(vmid int) bool {
	_, err := RunCommand(c.Cfg, "pvesh", "get",
		fmt.Sprintf("/nodes/%s/qemu/%d/agent/info", c.Node, vmid),
		"--output-format", "json",
	)
	return err == nil
}

// ExecInLXC runs a command inside an LXC container via pct exec.
func (c *NodeClient) ExecInLXC(vmid int, args ...string) ([]byte, error) {
	pctArgs := append([]string{"exec", fmt.Sprintf("%d", vmid), "--"}, args...)
	return RunCommand(c.Cfg, "pct", pctArgs...)
}

// ExecInQEMU runs a command inside a QEMU VM via qm guest exec.
func (c *NodeClient) ExecInQEMU(vmid int, args ...string) ([]byte, error) {
	qmArgs := append([]string{"guest", "exec", fmt.Sprintf("%d", vmid), "--"}, args...)
	return RunCommand(c.Cfg, "qm", qmArgs...)
}

// SetGuestTags writes a semicolon-delimited tag string to the guest config.
func (c *NodeClient) SetGuestTags(vmid int, gtype GuestType, tags string) error {
	path := fmt.Sprintf("/nodes/%s/%s/%d/config", c.Node, string(gtype), vmid)
	_, err := RunCommand(c.Cfg, "pvesh", "set", path, "--tags", tags)
	return err
}

func parseIPsFromLXC(data []byte) ([]string, error) {
	var entries []IPAddrEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse ip addr: %w", err)
	}
	var ips []string
	for _, entry := range entries {
		for _, a := range entry.AddrInfo {
			if a.Family == "inet" {
				ips = append(ips, a.Local)
			}
		}
	}
	return filterLoopback(ips), nil
}

func parseIPsFromQEMU(data []byte) ([]string, error) {
	var ifaces []QMNetInterface
	if err := json.Unmarshal(data, &ifaces); err != nil {
		return nil, fmt.Errorf("parse qm net: %w", err)
	}
	var ips []string
	for _, iface := range ifaces {
		for _, a := range iface.IPAddresses {
			if a.IPAddressType == "ipv4" {
				ips = append(ips, a.IPAddress)
			}
		}
	}
	return filterLoopback(ips), nil
}

func filterLoopback(ips []string) []string {
	var out []string
	for _, ip := range ips {
		if !strings.HasPrefix(ip, "127.") && !strings.HasPrefix(ip, "169.254.") {
			out = append(out, ip)
		}
	}
	return out
}
