package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nbd-wtf/go-nostr"

	mwcrypto "meshwatch/internal/crypto"
)

func TestCmdKeygen(t *testing.T) {
	var out, errBuf bytes.Buffer
	if err := runCLI([]string{"keygen"}, &out, &errBuf); err != nil {
		t.Fatalf("runCLI(keygen) error = %v", err)
	}

	text := out.String()
	extract := func(key string) string {
		re := regexp.MustCompile(key + `:\s+"([0-9a-f]+)"`)
		m := re.FindStringSubmatch(text)
		if len(m) != 2 {
			t.Fatalf("missing %s in keygen output:\n%s", key, text)
		}
		return m[1]
	}

	priv := extract("private_key_hex")
	pub := extract("pubkey_hex")
	psk := extract("group_psk_hex")
	tag := extract("topic_tag")

	derivedPub, err := nostr.GetPublicKey(priv)
	if err != nil {
		t.Fatalf("invalid private key: %v", err)
	}
	if derivedPub != pub {
		t.Fatalf("derived pubkey %q != printed %q", derivedPub, pub)
	}
	c, err := mwcrypto.NewCipherFromString(psk)
	if err != nil {
		t.Fatalf("invalid PSK: %v", err)
	}
	if c.TopicTag() != tag {
		t.Fatalf("derived topic tag %q != printed %q", c.TopicTag(), tag)
	}
}

func TestCmdTestNotify(t *testing.T) {
	var ntfyHits atomic.Int32
	var photonHits atomic.Int32

	ntfySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ntfyHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ntfySrv.Close()

	photonSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["recipient"] != "+33600000000" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		photonHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer photonSrv.Close()

	priv, _, _ := mwcrypto.GenerateNostrKeypair()
	psk, _ := mwcrypto.GeneratePSK()
	cfgYAML := fmt.Sprintf(`
node:
  name: "homelab-test"
  private_key_hex: "%s"
  group_psk_hex: "%s"
nostr:
  relays: ["wss://nos.lol"]
notifications:
  ntfy:
    enabled: true
    url: "%s/test-topic"
  photon_imessage:
    enabled: true
    url: "%s/send"
    token: "secret"
    recipient: "+33600000000"
`, priv, psk, ntfySrv.URL, photonSrv.URL)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var out, errBuf bytes.Buffer
	if err := runCLI([]string{"test-notify", "--config", cfgPath}, &out, &errBuf); err != nil {
		t.Fatalf("runCLI(test-notify) error = %v\nstdout:\n%s", err, out.String())
	}
	if ntfyHits.Load() != 1 || photonHits.Load() != 1 {
		t.Fatalf("expected 1 hit each, got ntfy=%d photon=%d", ntfyHits.Load(), photonHits.Load())
	}
	if !strings.Contains(out.String(), `Testing notifier "ntfy"... OK`) ||
		!strings.Contains(out.String(), `Testing notifier "photon_imessage"... OK`) {
		t.Fatalf("unexpected stdout:\n%s", out.String())
	}
}
