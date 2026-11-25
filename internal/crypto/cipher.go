package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/crypto/hkdf"
)

const (
	// HKDFSalt is the fixed application salt used to derive the AES-256-GCM key from group_psk.
	HKDFSalt = "meshwatch-v1-enc"
	// HKDFInfo binds the derived key to MeshWatch v1 AES-256-GCM payload encryption.
	HKDFInfo = "meshwatch-v1-aes256gcm"
	// TopicPrefix is the domain separator for deriving the Nostr #t routing tag.
	TopicPrefix = "meshwatch-v1-topic:"
	// PSKSize is the required length in bytes of a group pre-shared key.
	PSKSize = 32
	// TopicTagLen is the length in hex characters of the Nostr #t routing tag.
	TopicTagLen = 16
)

var (
	ErrInvalidPSK        = errors.New("group PSK must decode to exactly 32 bytes (64 hex chars or base64)")
	ErrInvalidCiphertext = errors.New("invalid or truncated ciphertext")
	ErrDecryptFailed     = errors.New("decryption failed: authentication tag mismatch or wrong key")
)

// Cipher handles HKDF key derivation, topic tag derivation, and AES-256-GCM
// encryption/decryption for MeshWatch Nostr payloads.
type Cipher struct {
	aead     cipher.AEAD
	topicTag string
}

// ParsePSK decodes a 32-byte pre-shared key from hex (64 chars) or base64.
func ParsePSK(encoded string) ([]byte, error) {
	s := strings.TrimSpace(encoded)
	if s == "" {
		return nil, ErrInvalidPSK
	}

	// Primary format: 64-char hex string.
	if len(s) == PSKSize*2 {
		if raw, err := hex.DecodeString(s); err == nil && len(raw) == PSKSize {
			return raw, nil
		}
	}

	// Fallback: standard or URL-safe base64 (with or without padding).
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if raw, err := enc.DecodeString(s); err == nil && len(raw) == PSKSize {
			return raw, nil
		}
	}

	return nil, ErrInvalidPSK
}

// GeneratePSK generates a cryptographically secure 32-byte PSK encoded as lowercase hex.
func GeneratePSK() (string, error) {
	buf := make([]byte, PSKSize)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("generate random PSK: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// GenerateNostrKeypair generates a new secp256k1 Nostr private/public keypair in hex.
func GenerateNostrKeypair() (privHex string, pubHex string, err error) {
	privHex = nostr.GeneratePrivateKey()
	pubHex, err = nostr.GetPublicKey(privHex)
	if err != nil {
		return "", "", fmt.Errorf("derive nostr public key: %w", err)
	}
	return privHex, pubHex, nil
}

// DeriveTopicTag computes hex(SHA256("meshwatch-v1-topic:" + psk))[:16].
func DeriveTopicTag(psk []byte) (string, error) {
	if len(psk) != PSKSize {
		return "", ErrInvalidPSK
	}
	h := sha256.New()
	h.Write([]byte(TopicPrefix))
	h.Write(psk)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:TopicTagLen], nil
}

// NewCipher builds a MeshWatch Cipher from raw 32-byte group PSK.
func NewCipher(psk []byte) (*Cipher, error) {
	if len(psk) != PSKSize {
		return nil, ErrInvalidPSK
	}

	kdf := hkdf.New(sha256.New, psk, []byte(HKDFSalt), []byte(HKDFInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("derive encryption key via HKDF: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init AES-GCM: %w", err)
	}

	topicTag, err := DeriveTopicTag(psk)
	if err != nil {
		return nil, err
	}

	return &Cipher{
		aead:     aead,
		topicTag: topicTag,
	}, nil
}

// NewCipherFromString parses an encoded PSK (hex or base64) and returns a Cipher.
func NewCipherFromString(encodedPSK string) (*Cipher, error) {
	psk, err := ParsePSK(encodedPSK)
	if err != nil {
		return nil, err
	}
	return NewCipher(psk)
}

// TopicTag returns the 16-hex-character #t routing tag derived from the group PSK.
func (c *Cipher) TopicTag() string {
	return c.topicTag
}

// Encrypt encrypts plaintext into base64(nonce_12_bytes || AES-256-GCM(plaintext)).
func (c *Cipher) Encrypt(plaintext []byte) (string, error) {
	nonceSize := c.aead.NonceSize()
	buf := make([]byte, nonceSize, nonceSize+len(plaintext)+c.aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("generate GCM nonce: %w", err)
	}
	sealed := c.aead.Seal(buf, buf, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt decodes base64(nonce_12_bytes || ciphertext) and authenticates/decrypts it.
func (c *Cipher) Decrypt(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64", ErrInvalidCiphertext)
	}

	nonceSize := c.aead.NonceSize()
	if len(raw) < nonceSize+c.aead.Overhead() {
		return nil, ErrInvalidCiphertext
	}

	nonce := raw[:nonceSize]
	ciphertext := raw[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plaintext, nil
}

// EncryptJSON marshals v as JSON and encrypts it.
func (c *Cipher) EncryptJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal payload JSON: %w", err)
	}
	return c.Encrypt(raw)
}

// DecryptJSON decrypts encoded content and unmarshals the JSON into dst.
func (c *Cipher) DecryptJSON(encoded string, dst any) error {
	raw, err := c.Decrypt(encoded)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("unmarshal decrypted JSON: %w", err)
	}
	return nil
}
