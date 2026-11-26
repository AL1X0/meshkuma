package probes

// ProbeMetrics holds structured, local-only telemetry collected during a probe check
// for detailed charts and resource breakdowns in the web UI. It is intentionally
// omitted from Nostr P2P heartbeats (`json:"-"` on ProbeResult) to keep relay payloads minimal.
type ProbeMetrics struct {
	Hostname   string   `json:"hostname,omitempty"`
	OS         string   `json:"os,omitempty"`
	UptimeSec  int64    `json:"uptime_sec,omitempty"`
	LoadAvg    string   `json:"load_avg,omitempty"`
	CPUPercent *float64 `json:"cpu_percent,omitempty"`
	RAMPercent *float64 `json:"ram_percent,omitempty"`
	RAMUsedMB  float64  `json:"ram_used_mb,omitempty"`
	RAMTotalMB float64  `json:"ram_total_mb,omitempty"`
	DiskMaxPct *float64 `json:"disk_max_pct,omitempty"`
	TempC      *float64 `json:"temp_c,omitempty"`
	MaxTempC   float64  `json:"max_temp_c,omitempty"`
	HTTPStatus int      `json:"http_status,omitempty"`
	TLSDays    *int     `json:"tls_days,omitempty"`
	TLSExpiry  string   `json:"tls_expiry,omitempty"`
	TLSSubject string   `json:"tls_subject,omitempty"`
	Target     string   `json:"target,omitempty"`
	SNMPValue  string   `json:"snmp_value,omitempty"`

	Disks      []DiskMetric      `json:"disks,omitempty"`
	Nodes      []NodeMetric      `json:"nodes,omitempty"`
	Guests     []GuestMetric     `json:"guests,omitempty"`
	Services   []ServiceMetric   `json:"services,omitempty"`
	Containers []ContainerMetric `json:"containers,omitempty"`
	Sensors    []SensorMetric    `json:"sensors,omitempty"`
}

// DiskMetric describes space usage on a filesystem, volume, or Proxmox storage.
type DiskMetric struct {
	Name        string  `json:"name"`
	Mount       string  `json:"mount,omitempty"`
	FSType      string  `json:"fs_type,omitempty"`
	UsedPercent float64 `json:"used_percent"`
	UsedGB      float64 `json:"used_gb,omitempty"`
	TotalGB     float64 `json:"total_gb,omitempty"`
	Status      string  `json:"status,omitempty"`
}

// NodeMetric describes one Proxmox VE cluster node.
type NodeMetric struct {
	Name        string  `json:"name"`
	Status      string  `json:"status"`
	CPUPercent  float64 `json:"cpu_percent"`
	RAMPercent  float64 `json:"ram_percent"`
	DiskPercent float64 `json:"disk_percent"`
	UptimeSec   int64   `json:"uptime_sec,omitempty"`
}

// GuestMetric describes one VM or LXC container (Proxmox or Hyper-V).
type GuestMetric struct {
	ID         string   `json:"id,omitempty"`
	Name       string   `json:"name"`
	Type       string   `json:"type"` // "qemu", "lxc", "hyper-v"
	Node       string   `json:"node,omitempty"`
	Status     string   `json:"status"`
	Health     string   `json:"health,omitempty"`
	CPUPercent *float64 `json:"cpu_percent,omitempty"`
	RAMPercent *float64 `json:"ram_percent,omitempty"`
}

// ServiceMetric describes one system service monitored on Windows or Linux.
type ServiceMetric struct {
	Name  string `json:"name"`
	State string `json:"state"`
	OK    bool   `json:"ok"`
}

// ContainerMetric describes one Docker container inspected by DockerProbe.
type ContainerMetric struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Status   string `json:"status,omitempty"`
	Health   string `json:"health,omitempty"`
	Restarts int    `json:"restarts,omitempty"`
	OK       bool   `json:"ok"`
}

// SensorMetric describes a hardware or array sensor (e.g., Synology RAID/disks/fans).
type SensorMetric struct {
	Group string `json:"group"`
	Name  string `json:"name"`
	Value string `json:"value"`
	OK    bool   `json:"ok"`
}

func floatPtr(v float64) *float64 {
	x := v
	return &x
}

func intPtr(v int) *int {
	x := v
	return &x
}
