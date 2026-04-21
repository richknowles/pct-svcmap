package proxmox

// LXCGuest represents one entry from pvesh get /nodes/{node}/lxc.
type LXCGuest struct {
	VMID   int    `json:"vmid"`
	Name   string `json:"name"`
	Status string `json:"status"`
	MaxMem int64  `json:"maxmem"`
	CPUs   int    `json:"cpus"`
	Uptime int64  `json:"uptime"`
	Tags   string `json:"tags"`
}

// QEMUGuest represents one entry from pvesh get /nodes/{node}/qemu.
type QEMUGuest struct {
	VMID   int    `json:"vmid"`
	Name   string `json:"name"`
	Status string `json:"status"`
	CPUs   int    `json:"cpus"`
	MaxMem int64  `json:"maxmem"`
	Uptime int64  `json:"uptime"`
	Tags   string `json:"tags"`
}

// GuestType distinguishes LXC containers from QEMU VMs.
type GuestType string

const (
	GuestTypeLXC  GuestType = "lxc"
	GuestTypeQEMU GuestType = "qemu"
)

// Guest is a unified representation used throughout the pipeline.
type Guest struct {
	VMID     int
	Name     string
	Status   string
	Type     GuestType
	Tags     string
	MaxMemMB int64
	CPUs     int
}

// IPAddrEntry maps one interface from `ip -j addr` output (LXC).
type IPAddrEntry struct {
	IfName   string     `json:"ifname"`
	AddrInfo []AddrInfo `json:"addr_info"`
}

// AddrInfo represents one address within an interface.
type AddrInfo struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	PrefixLen int    `json:"prefixlen"`
}

// QMNetInterface maps one interface from qm guest network-get-interfaces (QEMU).
type QMNetInterface struct {
	Name        string        `json:"name"`
	IPAddresses []QMIPAddress `json:"ip-addresses"`
}

// QMIPAddress is one IP entry from qm guest network-get-interfaces.
type QMIPAddress struct {
	IPAddressType string `json:"ip-address-type"`
	IPAddress     string `json:"ip-address"`
	Prefix        int    `json:"prefix"`
}
