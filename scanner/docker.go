package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/richknowles/pct-svcmap/proxmox"
)

// dockerPortRegexp matches host:port->containerPort/proto mappings.
// Handles: 0.0.0.0:80->80/tcp  :::80->80/tcp  192.168.1.5:8080->8080/tcp
var dockerPortRegexp = regexp.MustCompile(`^([\d\.:]+):(\d+)->(\d+)/(tcp|udp)$`)

// DetectDocker checks if Docker is present in the guest and enumerates containers.
func DetectDocker(guest proxmox.Guest, client *proxmox.NodeClient) ([]DockerContainer, bool, error) {
	if !checkDockerAvailable(guest, client) {
		return nil, false, nil
	}
	data, err := execInGuest(guest, client,
		"docker", "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Ports}}",
	)
	if err != nil {
		return nil, true, fmt.Errorf("docker ps: %w", err)
	}
	containers, err := parseDockerPSOutput(data)
	return containers, true, err
}

func checkDockerAvailable(guest proxmox.Guest, client *proxmox.NodeClient) bool {
	_, err := execInGuest(guest, client, "docker", "info", "--format", "{{.ID}}")
	return err == nil
}

func parseDockerPSOutput(data []byte) ([]DockerContainer, error) {
	var containers []DockerContainer
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 4 {
			continue
		}
		c := DockerContainer{
			ID:    parts[0],
			Name:  parts[1],
			Image: parts[2],
			Ports: parseDockerPorts(parts[3]),
		}
		containers = append(containers, c)
	}
	return containers, nil
}

func parseDockerPorts(portsField string) []DockerPort {
	if strings.TrimSpace(portsField) == "" {
		return nil
	}
	var ports []DockerPort
	for _, mapping := range strings.Split(portsField, ", ") {
		mapping = strings.TrimSpace(mapping)
		if mapping == "" {
			continue
		}
		// Normalize IPv6 shorthand ::: to a parseable form
		normalized := mapping
		if strings.HasPrefix(normalized, ":::") {
			normalized = "::" + normalized[2:]
		}
		m := dockerPortRegexp.FindStringSubmatch(normalized)
		if m == nil {
			continue
		}
		hostIP := m[1]
		hostPort, _ := strconv.Atoi(m[2])
		containerPort, _ := strconv.Atoi(m[3])
		proto := m[4]
		ports = append(ports, DockerPort{
			HostIP:        hostIP,
			HostPort:      hostPort,
			ContainerPort: containerPort,
			Protocol:      proto,
		})
	}
	return ports
}
