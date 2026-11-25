package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	pskHex, err := GeneratePSK()
	if err != nil {
		t.Fatalf("GeneratePSK() error = %v", err)
	}
	c, err := NewCipherFromString(pskHex)
	if err != nil {
		t.Fatalf("NewCipherFromString() error = %v", err)
	}

	payload := []byte(`{"type":"heartbeat","node_name":"homelab-alix","overall_ok":true}`)
	enc1, err := c.Encrypt(payload)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	enc2, err := c.Encrypt(payload)
	if err != nil {
		t.Fatalf("Encrypt() second call error = %v", err)
	}
	if enc1 == enc2 {
		t.Fatalf("Encrypt() produced identical ciphertext for two calls; nonce must be unique")
	}

	dec, err := c.Decrypt(enc1)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(dec, payload) {
		t.Fatalf("Decrypt() = %q, want %q", dec, payload)
	}

	// Empty plaintext must also work cleanly.
	encEmpty, err := c.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt(empty) error = %v", err)
	}
	decEmpty, err := c.Decrypt(encEmpty)
	if err != nil {
		t.Fatalf("Decrypt(empty) error = %v", err)
	}
	if len(decEmpty) != 0 {
		t.Fatalf("Decrypt(empty) len = %d, want 0", len(decEmpty))
	}
}

func TestDecryptRejectsWrongPSK(t *testing.T) {
	psk1, err := GeneratePSK()
	if err != nil {
		t.Fatalf("GeneratePSK() error = %v", err)
	}
	psk2, err := GeneratePSK()
	if err != nil {
		t.Fatalf("GeneratePSK() error = %v", err)
	}

	c1, err := NewCipherFromString(psk1)
	if err != nil {
		t.Fatalf("NewCipherFromString(psk1) error = %v", err)
	}
	c2, err := NewCipherFromString(psk2)
	if err != nil {
		t.Fatalf("NewCipherFromString(psk2) error = %v", err)
	}

	enc, err := c1.Encrypt([]byte(`{"type":"heartbeat"}`))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if _, err := c2.Decrypt(enc); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("Decrypt() with wrong PSK error = %v, want %v", err, ErrDecryptFailed)
	}
}

func TestDecryptRejectsTamperedAndTruncatedCiphertext(t *testing.T) {
	pskHex, _ := GeneratePSK()
	c, _ := NewCipherFromString(pskHex)

	enc, err := c.Encrypt([]byte("secret-heartbeat"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(enc)

	// Flip a byte in ciphertext.
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := c.Decrypt(base64.StdEncoding.EncodeToString(tampered)); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("Decrypt(tampered) error = %v, want ErrDecryptFailed", err)
	}

	// Flip a byte in nonce.
	tamperedNonce := append([]byte(nil), raw...)
	tamperedNonce[0] ^= 0x01
	if _, err := c.Decrypt(base64.StdEncoding.EncodeToString(tamperedNonce)); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("Decrypt(tamperedNonce) error = %v, want ErrDecryptFailed", err)
	}

	// Truncated payload (< 12 + 16 bytes).
	short := base64.StdEncoding.EncodeToString(raw[:20])
	if _, err := c.Decrypt(short); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("Decrypt(short) error = %v, want ErrInvalidCiphertext", err)
	}

	// Invalid base64.
	if _, err := c.Decrypt("%%%not-base64%%%"); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("Decrypt(invalid-b64) error = %v, want ErrInvalidCiphertext", err)
	}
}

func TestTopicTagAndPSKFormats(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	pskHex := hex.EncodeToString(raw)
	pskB64 := base64.StdEncoding.EncodeToString(raw)

	cHex, err := NewCipherFromString(pskHex)
	if err != nil {
		t.Fatalf("NewCipherFromString(hex) error = %v", err)
	}
	cB64, err := NewCipherFromString(pskB64)
	if err != nil {
		t.Fatalf("NewCipherFromString(b64) error = %v", err)
	}

	if len(cHex.TopicTag()) != TopicTagLen {
		t.Fatalf("TopicTag() len = %d, want %d", len(cHex.TopicTag()), TopicTagLen)
	}
	if _, err := hex.DecodeString(cHex.TopicTag()); err != nil {
		t.Fatalf("TopicTag() %q is not valid hex: %v", cHex.TopicTag(), err)
	}
	if cHex.TopicTag() != cB64.TopicTag() {
		t.Fatalf("TopicTag mismatch between hex (%s) and base64 (%s)", cHex.TopicTag(), cB64.TopicTag())
	}

	// Cross-decrypt between hex-initialized and base64-initialized ciphers.
	enc, err := cHex.Encrypt([]byte("hello mesh"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	dec, err := cB64.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt() across hex/b64 error = %v", err)
	}
	if string(dec) != "hello mesh" {
		t.Fatalf("Decrypt() = %q, want %q", dec, "hello mesh")
	}

	// Different PSK produces different topic tag.
	otherHex, _ := GeneratePSK()
	cOther, _ := NewCipherFromString(otherHex)
	if cOther.TopicTag() == cHex.TopicTag() {
		t.Fatalf("different PSKs produced identical topic tag %s", cHex.TopicTag())
	}
}

func TestParsePSKValidation(t *testing.T) {
	invalid := []string{
		"",
		"   ",
		"abcd",
		"REMPLACER_VIA_KEYGEN",
		hex.EncodeToString(make([]byte, 16)),
		base64.StdEncoding.EncodeToString(make([]byte, 31)),
	}
	for _, tc := range invalid {
		if _, err := ParsePSK(tc); !errors.Is(err, ErrInvalidPSK) {
			t.Errorf("ParsePSK(%q) error = %v, want ErrInvalidPSK", tc, err)
		}
	}
}

func TestJSONRoundTripAndKeygen(t *testing.T) {
	priv, pub, err := GenerateNostrKeypair()
	if err != nil {
		t.Fatalf("GenerateNostrKeypair() error = %v", err)
	}
	if len(priv) != 64 || len(pub) != 64 {
		t.Fatalf("unexpected key lengths: priv=%d pub=%d", len(priv), len(pub))
	}
	derived, err := nostr.GetPublicKey(priv)
	if err != nil || derived != pub {
		t.Fatalf("GetPublicKey mismatch: got %q (err=%v), want %q", derived, err, pub)
	}

	psk, err := GeneratePSK()
	if err != nil {
		t.Fatalf("GeneratePSK() error = %v", err)
	}
	c, _ := NewCipherFromString(psk)

	type sample struct {
		Type string `json:"type"`
		OK   bool   `json:"ok"`
	}
	in := sample{Type: "heartbeat", OK: true}
	enc, err := c.EncryptJSON(in)
	if err != nil {
		t.Fatalf("EncryptJSON() error = %v", err)
	}
	var out sample
	if err := c.DecryptJSON(enc, &out); err != nil {
		t.Fatalf("DecryptJSON() error = %v", err)
	}
	if out != in {
		t.Fatalf("DecryptJSON() = %+v, want %+v", out, in)
	}
}
