package probes

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"meshwatch/internal/config"
)

// SNMPVariable is a lightweight, mockable representation of an SNMP PDU result.
type SNMPVariable struct {
	OID   string
	Value any
}

// SNMPClient abstracts SNMP Get and Walk operations for testability.
type SNMPClient interface {
	Get(ctx context.Context, oids []string) ([]SNMPVariable, error)
	Walk(ctx context.Context, rootOID string) ([]SNMPVariable, error)
}

type gosnmpClient struct {
	cfg config.ProbeConfig
}

func newGoSNMPClient(cfg config.ProbeConfig) SNMPClient {
	return &gosnmpClient{cfg: cfg}
}

func (c *gosnmpClient) dial(ctx context.Context) (*gosnmp.GoSNMP, error) {
	timeout := c.cfg.Timeout
	if deadline, ok := ctx.Deadline(); ok {
		if rem := time.Until(deadline); rem > 0 && rem < timeout {
			timeout = rem
		}
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	port := uint16(c.cfg.Port)
	if port == 0 {
		port = config.DefaultSNMPPort
	}

	g := &gosnmp.GoSNMP{
		Target:    c.cfg.Host,
		Port:      port,
		Timeout:   timeout,
		Retries:   1,
		Transport: "udp",
		Context:   ctx,
	}

	switch c.cfg.SNMPVersion {
	case "3":
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		authProto, hasAuth, err := parseSNMPAuthProto(c.cfg.AuthProto)
		if err != nil {
			return nil, err
		}
		privProto, hasPriv, err := parseSNMPPrivProto(c.cfg.PrivProto)
		if err != nil {
			return nil, err
		}
		switch {
		case hasAuth && hasPriv:
			g.MsgFlags = gosnmp.AuthPriv
		case hasAuth:
			g.MsgFlags = gosnmp.AuthNoPriv
		default:
			g.MsgFlags = gosnmp.NoAuthNoPriv
		}
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 c.cfg.User,
			AuthenticationProtocol:   authProto,
			AuthenticationPassphrase: c.cfg.AuthPass,
			PrivacyProtocol:          privProto,
			PrivacyPassphrase:        c.cfg.PrivPass,
		}
	default:
		g.Version = gosnmp.Version2c
		g.Community = c.cfg.Community
	}

	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect %s:%d: %w", c.cfg.Host, port, err)
	}
	return g, nil
}

func (c *gosnmpClient) Get(ctx context.Context, oids []string) ([]SNMPVariable, error) {
	g, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer g.Conn.Close()

	pkt, err := g.Get(oids)
	if err != nil {
		return nil, err
	}
	out := make([]SNMPVariable, 0, len(pkt.Variables))
	for _, pdu := range pkt.Variables {
		if pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance || pdu.Type == gosnmp.EndOfMibView {
			continue
		}
		out = append(out, SNMPVariable{OID: pdu.Name, Value: normalizeSNMPValue(pdu)})
	}
	return out, nil
}

func (c *gosnmpClient) Walk(ctx context.Context, rootOID string) ([]SNMPVariable, error) {
	g, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer g.Conn.Close()

	var out []SNMPVariable
	err = g.BulkWalk(rootOID, func(pdu gosnmp.SnmpPDU) error {
		if pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance || pdu.Type == gosnmp.EndOfMibView {
			return nil
		}
		out = append(out, SNMPVariable{OID: pdu.Name, Value: normalizeSNMPValue(pdu)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeSNMPValue(pdu gosnmp.SnmpPDU) any {
	switch pdu.Type {
	case gosnmp.OctetString:
		if b, ok := pdu.Value.([]byte); ok {
			return string(b)
		}
		return pdu.Value
	default:
		return pdu.Value
	}
}

func parseSNMPAuthProto(s string) (gosnmp.SnmpV3AuthProtocol, bool, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "NONE", "NOAUTH":
		return gosnmp.NoAuth, false, nil
	case "MD5":
		return gosnmp.MD5, true, nil
	case "SHA":
		return gosnmp.SHA, true, nil
	case "SHA224":
		return gosnmp.SHA224, true, nil
	case "SHA256":
		return gosnmp.SHA256, true, nil
	case "SHA384":
		return gosnmp.SHA384, true, nil
	case "SHA512":
		return gosnmp.SHA512, true, nil
	default:
		return gosnmp.NoAuth, false, fmt.Errorf("unsupported SNMPv3 auth_proto %q", s)
	}
}

func parseSNMPPrivProto(s string) (gosnmp.SnmpV3PrivProtocol, bool, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "NONE", "NOPRIV":
		return gosnmp.NoPriv, false, nil
	case "DES":
		return gosnmp.DES, true, nil
	case "AES":
		return gosnmp.AES, true, nil
	case "AES192":
		return gosnmp.AES192, true, nil
	case "AES256":
		return gosnmp.AES256, true, nil
	case "AES192C":
		return gosnmp.AES192C, true, nil
	case "AES256C":
		return gosnmp.AES256C, true, nil
	default:
		return gosnmp.NoPriv, false, fmt.Errorf("unsupported SNMPv3 priv_proto %q", s)
	}
}

func snmpValueToInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case uint:
		return int64(x), true
	case uint32:
		return int64(x), true
	case uint64:
		return int64(x), true
	case float64:
		return int64(x), true
	case *big.Int:
		if x != nil && x.IsInt64() {
			return x.Int64(), true
		}
		return 0, false
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n, err == nil
	case []byte:
		n, err := strconv.ParseInt(strings.TrimSpace(string(x)), 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

func snmpValueToFloat64(v any) (float64, bool) {
	if i, ok := snmpValueToInt64(v); ok {
		return float64(i), true
	}
	switch x := v.(type) {
	case float32:
		return float64(x), true
	case float64:
		return x, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	case []byte:
		f, err := strconv.ParseFloat(strings.TrimSpace(string(x)), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func snmpValueToString(v any) string {
	switch x := v.(type) {
	case []byte:
		return string(x)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// SNMPOIDProbe checks a single arbitrary SNMP OID against an expected value or min/max bounds.
type SNMPOIDProbe struct {
	id            string
	oid           string
	expectedValue string
	minValue      *float64
	maxValue      *float64
	client        SNMPClient
}

// NewSNMPOIDProbe creates a generic SNMP OID probe backed by gosnmp.
func NewSNMPOIDProbe(cfg config.ProbeConfig) (*SNMPOIDProbe, error) {
	return NewSNMPOIDProbeWithClient(cfg, newGoSNMPClient(cfg)), nil
}

// NewSNMPOIDProbeWithClient creates a generic SNMP OID probe with an injected SNMPClient (for tests).
func NewSNMPOIDProbeWithClient(cfg config.ProbeConfig, client SNMPClient) *SNMPOIDProbe {
	return &SNMPOIDProbe{
		id:            cfg.ID,
		oid:           cfg.OID,
		expectedValue: cfg.ExpectedValue,
		minValue:      cfg.MinValue,
		maxValue:      cfg.MaxValue,
		client:        client,
	}
}

func (p *SNMPOIDProbe) ID() string   { return p.id }
func (p *SNMPOIDProbe) Kind() string { return "snmp_oid" }

func (p *SNMPOIDProbe) Check(ctx context.Context) ProbeResult {
	start := time.Now()
	vars, err := p.client.Get(ctx, []string{p.oid})
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("SNMP get %s failed: %v", p.oid, err),
			Latency: latency,
		}
	}
	if len(vars) == 0 {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("SNMP OID %s returned no value", p.oid),
			Latency: latency,
		}
	}

	val := vars[0].Value
	strVal := strings.TrimSpace(snmpValueToString(val))

	if p.expectedValue != "" && strVal != p.expectedValue {
		return ProbeResult{
			ID:      p.id,
			Kind:    p.Kind(),
			OK:      false,
			Summary: fmt.Sprintf("OID %s=%q (expected %q)", p.oid, strVal, p.expectedValue),
			Latency: latency,
		}
	}

	if p.minValue != nil || p.maxValue != nil {
		num, ok := snmpValueToFloat64(val)
		if !ok {
			return ProbeResult{
				ID:      p.id,
				Kind:    p.Kind(),
				OK:      false,
				Summary: fmt.Sprintf("OID %s=%q is not numeric", p.oid, strVal),
				Latency: latency,
			}
		}
		if p.minValue != nil && num < *p.minValue {
			return ProbeResult{
				ID:      p.id,
				Kind:    p.Kind(),
				OK:      false,
				Summary: fmt.Sprintf("OID %s=%.2f (< min %.2f)", p.oid, num, *p.minValue),
				Latency: latency,
			}
		}
		if p.maxValue != nil && num > *p.maxValue {
			return ProbeResult{
				ID:      p.id,
				Kind:    p.Kind(),
				OK:      false,
				Summary: fmt.Sprintf("OID %s=%.2f (> max %.2f)", p.oid, num, *p.maxValue),
				Latency: latency,
			}
		}
	}

	return ProbeResult{
		ID:      p.id,
		Kind:    p.Kind(),
		OK:      true,
		Summary: fmt.Sprintf("OID %s=%s OK", p.oid, strVal),
		Latency: latency,
	}
}
