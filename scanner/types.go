package scanner

import "time"

// Severity levels for risky services.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow     Severity = "LOW"
)

// Service represents a single listening network service on a guest.
type Service struct {
	Protocol    string
	Port        int
	BindAddr    string
	ProcessName string
	PID         int
	IsRisky     bool
	RiskReason  string
	Severity    Severity
}

// DockerPort is one published port mapping from a Docker container.
type DockerPort struct {
	HostIP        string
	HostPort      int
	ContainerPort int
	Protocol      string
}

// DockerContainer represents a running Docker container with mapped ports.
type DockerContainer struct {
	ID    string
	Name  string
	Image string
	Ports []DockerPort
}

// DetectionMethod records which fallback method was used for service detection.
type DetectionMethod string

const (
	DetectionSS      DetectionMethod = "ss"
	DetectionLSOF    DetectionMethod = "lsof"
	DetectionProcNet DetectionMethod = "proc/net"
	DetectionFailed  DetectionMethod = "failed"
	DetectionSkipped DetectionMethod = "skipped"
)

// GuestScanResult is the complete scan output for a single guest.
type GuestScanResult struct {
	VMID             int
	Name             string
	GuestType        string
	Status           string
	IPs              []string
	Services         []Service
	DockerContainers []DockerContainer
	DockerAvailable  bool
	AgentAvailable   bool
	DetectionMethod  DetectionMethod
	ScanError        string
	ScannedAt        time.Time
	ExistingTags     string
	GeneratedTags    []string
	TagsApplied      bool
}

// ScanConfig holds all runtime configuration passed to the worker pool.
type ScanConfig struct {
	Node           string
	Workers        int
	TimeoutSecs    int
	IncludeStopped bool
	FilterGlob     string
	Verbose        bool
}
