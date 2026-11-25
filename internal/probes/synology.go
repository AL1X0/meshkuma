package probes

import (
	"context"
	"fmt"
	"strings"
	"time"

	"meshwatch/internal/config"
)

const (
	// Synology SNMP MIB OIDs (SYNOLOGY-SYSTEM-MIB, SYNOLOGY-DISK-MIB, SYNOLOGY-RAID-MIB).
	synoOIDSystemStatus = ".1.3.6.1.4.1.6574.1.1.0"
	synoOIDTemperature  = ".1.3.6.1.4.1.6574.1.2.0"
	synoOIDSystemFan    = ".1.3.6.1.4.1.6574.1.4.1.0"
	synoOIDPowerFan     = ".1.3.6.1.4.1.6574.1.4.2.0"
	synoOIDRAIDStatus   = ".1.3.6.1.4.1.6574.3.1.1.4"
	synoOIDDiskStatus   = ".1.3.6.1.4.1.6574.2.1.1.5"
)

// SynologyProbe monitors Synology NAS health over SNMPv2c or SNMPv3.
type SynologyProbe struct {
	id       string
	maxTempC int
	client   SNMPClient
}

// NewSynologyProbe creates a SynologyProbe backed by gosnmp.
func NewSynologyProbe(cfg config.ProbeConfig) (*SynologyProbe, error) {
	return NewSynologyProbeWithClient(cfg, newGoSNMPClient(cfg)), nil
}

// NewSynologyProbeWithClient creates a SynologyProbe with an injected SNMPClient for unit testing.
func NewSynologyProbeWithClient(cfg config.ProbeConfig, client SNMPClient) *SynologyProbe {
	maxTemp := cfg.MaxTempC
	if maxTemp <= 0 {
		maxTemp = config.DefaultSynologyMaxTempC
	}
	return &SynologyProbe{
		id:       cfg.ID,
		maxTempC: maxTemp,
		client:   client,
	}
}

func (p *SynologyProbe) ID() string   { return p.id }
func (p *SynologyProbe) Kind() string { return "synology" }

func (p *SynologyProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()

	scalars, err := p.client.Get(ctx, []string{
		synoOIDSystemStatus,
		synoOIDTemperature,
		synoOIDSystemFan,
		synoOIDPowerFan,
	})
	if err != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("SNMP scalar query failed: %v", err),
			Latency: time.Since(start).Milliseconds(),
		}
	}

	raidVars, err := p.client.Walk(ctx, synoOIDRAIDStatus)
	if err != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("SNMP RAID walk failed: %v", err),
			Latency: time.Since(start).Milliseconds(),
		}
	}

	diskVars, err := p.client.Walk(ctx, synoOIDDiskStatus)
	if err != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("SNMP Disk walk failed: %v", err),
			Latency: time.Since(start).Milliseconds(),
		}
	}

	latency := time.Since(start).Milliseconds()
	ok, summary := evaluateSynologyMetrics(scalars, raidVars, diskVars, p.maxTempC)
	return ProbeResult{
		ID:      p.id,
		Kind:    p.Kind(),
		OK:      ok,
		Summary: summary,
		Latency: latency,
	}
}

func evaluateSynologyMetrics(scalars, raidVars, diskVars []SNMPVariable, maxTempC int) (bool, string) {
	byOID := make(map[string]any, len(scalars))
	for _, v := range scalars {
		byOID[normalizeOID(v.OID)] = v.Value
	}

	var issues []string
	tempStr := ""

	// System status (1 = Normal, 2 = Failed)
	if raw, ok := byOID[synoOIDSystemStatus]; ok {
		if st, valid := snmpValueToInt64(raw); !valid || st != 1 {
			issues = append(issues, fmt.Sprintf("System failed (status=%v)", raw))
		}
	} else {
		issues = append(issues, "missing system status OID")
	}

	// System temperature
	if raw, ok := byOID[synoOIDTemperature]; ok {
		if temp, valid := snmpValueToInt64(raw); valid {
			tempStr = fmt.Sprintf("%d°C", temp)
			if int(temp) > maxTempC {
				issues = append(issues, fmt.Sprintf("Temp %d°C > %d°C", temp, maxTempC))
			}
		} else {
			issues = append(issues, fmt.Sprintf("invalid temperature value %v", raw))
		}
	}

	// Fans (1 = Normal, 2 = Failed)
	if raw, ok := byOID[synoOIDSystemFan]; ok {
		if st, valid := snmpValueToInt64(raw); !valid || st != 1 {
			issues = append(issues, fmt.Sprintf("System fan failed (status=%v)", raw))
		}
	}
	if raw, ok := byOID[synoOIDPowerFan]; ok {
		if st, valid := snmpValueToInt64(raw); !valid || st != 1 {
			issues = append(issues, fmt.Sprintf("Power fan failed (status=%v)", raw))
		}
	}

	// RAID statuses (1 = Normal)
	raidCount := len(raidVars)
	for idx, rv := range raidVars {
		st, valid := snmpValueToInt64(rv.Value)
		if !valid || st != 1 {
			issues = append(issues, fmt.Sprintf("RAID#%d %s (%v)", idx+1, synologyRAIDLabel(st), rv.Value))
		}
	}

	// Disk statuses (1 = Normal)
	diskCount := len(diskVars)
	for idx, dv := range diskVars {
		st, valid := snmpValueToInt64(dv.Value)
		if !valid || st != 1 {
			issues = append(issues, fmt.Sprintf("Disk#%d %s (%v)", idx+1, synologyDiskLabel(st), dv.Value))
		}
	}

	if len(issues) > 0 {
		return false, strings.Join(issues, "; ")
	}

	var parts []string
	if raidCount > 0 {
		parts = append(parts, fmt.Sprintf("RAID OK (%d)", raidCount))
	} else {
		parts = append(parts, "RAID OK")
	}
	if diskCount > 0 {
		parts = append(parts, fmt.Sprintf("Disks OK (%d)", diskCount))
	}
	if tempStr != "" {
		parts = append(parts, tempStr)
	}
	return true, strings.Join(parts, ", ")
}

func normalizeOID(oid string) string {
	oid = strings.TrimSpace(oid)
	if oid != "" && !strings.HasPrefix(oid, ".") {
		return "." + oid
	}
	return oid
}

func synologyRAIDLabel(code int64) string {
	switch code {
	case 1:
		return "Normal"
	case 2:
		return "Repairing"
	case 3:
		return "Migrating"
	case 4:
		return "Expanding"
	case 5:
		return "Deleting"
	case 6:
		return "Creating"
	case 7:
		return "Syncing"
	case 8:
		return "ParityChecking"
	case 9:
		return "Assembling"
	case 10:
		return "Canceling"
	case 11:
		return "Degraded"
	case 12:
		return "Crashed"
	default:
		return "Abnormal"
	}
}

func synologyDiskLabel(code int64) string {
	switch code {
	case 1:
		return "Normal"
	case 2:
		return "Initialized"
	case 3:
		return "NotInitialized"
	case 4:
		return "SystemPartitionFailed"
	case 5:
		return "Crashed"
	default:
		return "Abnormal"
	}
}
