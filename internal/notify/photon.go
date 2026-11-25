package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"meshwatch/internal/config"
)

const (
	defaultPhotonCloudBaseURL = "https://api.photon.codes/v1"
	defaultPhotonProxyBaseURL = "https://imessage-swagger.photon.codes"
	photonAPIVersion          = "2026-07-01"
)

// PhotonNotifier sends MeshWatch alerts through Photon iMessage with 3 exponential
// backoff retries (2s, 5s, 10s) on network/timeout/5xx errors.
//
// Supported modes (per official Photon docs):
//   - "cloud": Photon 2.0 Cloud API (POST /v1/projects/{id}/messages with Bearer pho_sk_... + Idempotency-Key)
//   - "proxy": Photon Advanced iMessage HTTP Proxy (POST /send with {"to","text"} and Bearer base64(serverUrl|apiKey))
//   - "custom": Generic JSON webhook with configurable recipient_field / message_field
type PhotonNotifier struct {
	mode           string
	endpoint       string
	projectID      string
	apiKey         string
	serverURL      string
	token          string
	recipient      string
	recipientField string
	messageField   string
	client         *http.Client
	backoffs       []time.Duration

	mu       sync.Mutex
	senderID string
	spaceID  string
}

// NewPhotonNotifier constructs a PhotonNotifier from configuration.
func NewPhotonNotifier(cfg config.PhotonConfig) *PhotonNotifier {
	mode := cfg.EffectiveMode()
	endpoint := strings.TrimSpace(cfg.URL)
	if endpoint == "" {
		switch mode {
		case "cloud":
			endpoint = defaultPhotonCloudBaseURL
		case "proxy":
			endpoint = defaultPhotonProxyBaseURL
		}
	}

	recField := strings.TrimSpace(cfg.RecipientField)
	if recField == "" {
		recField = "recipient"
	}
	msgField := strings.TrimSpace(cfg.MessageField)
	if msgField == "" {
		msgField = "message"
	}

	apiKey := strings.TrimSpace(cfg.APIKey)
	token := strings.TrimSpace(cfg.Token)
	if apiKey == "" && mode == "cloud" {
		apiKey = token
	}

	return &PhotonNotifier{
		mode:           mode,
		endpoint:       strings.TrimRight(endpoint, "/"),
		projectID:      strings.TrimSpace(cfg.ProjectID),
		apiKey:         apiKey,
		serverURL:      strings.TrimSpace(cfg.ServerURL),
		token:          token,
		recipient:      strings.TrimSpace(cfg.Recipient),
		recipientField: recField,
		messageField:   msgField,
		senderID:       strings.TrimSpace(cfg.SenderID),
		spaceID:        strings.TrimSpace(cfg.SpaceID),
		client: &http.Client{
			Timeout:   defaultNotifyHTTPTimeout,
			Transport: &http.Transport{DisableKeepAlives: true},
		},
		backoffs: append([]time.Duration(nil), DefaultRetryBackoffs...),
	}
}

func (p *PhotonNotifier) Name() string { return "photon_imessage" }

func (p *PhotonNotifier) Send(ctx context.Context, alert Alert) error {
	text := alert.Title() + "\n" + alert.Body()
	switch p.mode {
	case "cloud":
		return p.sendCloud(ctx, alert, text)
	case "proxy":
		return p.sendProxy(ctx, text)
	default:
		return p.sendCustom(ctx, text)
	}
}

// sendProxy targets Photon Advanced iMessage HTTP Proxy (`photon-hq/advanced-imessage-http-proxy`):
//
//	POST <proxy>/send
//	Authorization: Bearer base64("<serverUrl>|<apiKey>")
//	Body: {"to": "<recipient>", "text": "<message>"}
func (p *PhotonNotifier) sendProxy(ctx context.Context, text string) error {
	endpoint := p.endpoint
	if !strings.HasSuffix(strings.ToLower(endpoint), "/send") {
		endpoint += "/send"
	}

	bearer := p.token
	if p.serverURL != "" && p.apiKey != "" {
		bearer = base64.StdEncoding.EncodeToString([]byte(p.serverURL + "|" + p.apiKey))
	} else if bearer == "" {
		bearer = p.apiKey
	}

	raw, err := json.Marshal(map[string]string{
		"to":   p.recipient,
		"text": text,
	})
	if err != nil {
		return fmt.Errorf("marshal photon proxy payload: %w", err)
	}

	return p.postWithRetry(ctx, endpoint, bearer, nil, raw)
}

// sendCloud targets Photon 2.0 Cloud API (`https://api.photon.codes/v1`):
//
//	POST /projects/{projectId}/messages
//	Authorization: Bearer <pho_sk_...>
//	Idempotency-Key: <stable key>
//	Photon-Version: 2026-07-01
//	Body: {"spaceId": "...", "senderId": "...", "content": {"type":"text","format":"plain","text":"..."}}
func (p *PhotonNotifier) sendCloud(ctx context.Context, alert Alert, text string) error {
	if p.projectID == "" {
		return errors.New("photon cloud: project_id (pho_prj_...) requis")
	}
	if p.apiKey == "" {
		return errors.New("photon cloud: api_key (pho_sk_...) requise")
	}

	senderID, spaceID, err := p.resolveCloudTarget(ctx)
	if err != nil {
		return err
	}

	idemKey := buildIdempotencyKey(alert)
	payload := map[string]any{
		"spaceId":  spaceID,
		"senderId": senderID,
		"content": map[string]string{
			"type":   "text",
			"format": "plain",
			"text":   text,
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal photon cloud payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/projects/%s/messages", p.cloudBaseURL(), url.PathEscape(p.projectID))
	headers := map[string]string{
		"Idempotency-Key": idemKey,
		"Photon-Version":  photonAPIVersion,
	}
	return p.postWithRetry(ctx, endpoint, p.apiKey, headers, raw)
}

func (p *PhotonNotifier) cloudBaseURL() string {
	base := strings.TrimRight(p.endpoint, "/")
	if base == "" {
		return defaultPhotonCloudBaseURL
	}
	if !strings.HasSuffix(base, "/v1") && strings.Contains(strings.ToLower(base), "api.photon.codes") {
		base += "/v1"
	}
	return base
}

func (p *PhotonNotifier) resolveCloudTarget(ctx context.Context) (string, string, error) {
	p.mu.Lock()
	cachedSender, cachedSpace := p.senderID, p.spaceID
	p.mu.Unlock()
	if cachedSender != "" && cachedSpace != "" {
		return cachedSender, cachedSpace, nil
	}

	base := p.cloudBaseURL()
	proj := url.PathEscape(p.projectID)

	senderID := cachedSender
	if senderID == "" {
		// 1. Find the project's active iMessage agent user.
		usersURL := fmt.Sprintf("%s/projects/%s/users?platform=imessage&pageSize=100", base, proj)
		var usersPage struct {
			Items []struct {
				ID     string `json:"id"`
				Kind   string `json:"kind"`
				Handle string `json:"handle"`
			} `json:"items"`
		}
		if err := p.cloudJSONRequest(ctx, http.MethodGet, usersURL, nil, &usersPage); err != nil {
			return "", "", fmt.Errorf("photon cloud: impossible de lire les utilisateurs iMessage : %w", err)
		}
		for _, u := range usersPage.Items {
			if strings.EqualFold(u.Kind, "agent") && u.ID != "" {
				senderID = u.ID
				break
			}
		}
		if senderID == "" {
			return "", "", errors.New("photon cloud: aucune ligne iMessage agent trouvée sur ce projet (assignez une ligne iMessage sur app.beta.photon.codes et envoyez un premier message à cette ligne)")
		}
	}

	spaceID := cachedSpace
	if spaceID == "" {
		if p.recipient == "" {
			return "", "", errors.New("photon cloud: destinataire (numéro E.164 ou email iMessage) requis")
		}
		// 2. Create or get the recipient iMessage user.
		createUserURL := fmt.Sprintf("%s/projects/%s/users", base, proj)
		var peerUser struct {
			ID string `json:"id"`
		}
		if err := p.cloudJSONRequest(ctx, http.MethodPost, createUserURL, map[string]string{
			"platform": "imessage",
			"handle":   p.recipient,
		}, &peerUser); err != nil {
			return "", "", fmt.Errorf("photon cloud: impossible de résoudre le destinataire %q : %w", p.recipient, err)
		}
		if peerUser.ID == "" {
			return "", "", errors.New("photon cloud: réponse utilisateur vide")
		}

		// 3. Create or get the direct iMessage Space between agent and recipient.
		createSpaceURL := fmt.Sprintf("%s/projects/%s/spaces", base, proj)
		var space struct {
			ID string `json:"id"`
		}
		if err := p.cloudJSONRequest(ctx, http.MethodPost, createSpaceURL, map[string]any{
			"platform":       "imessage",
			"participantIds": []string{senderID, peerUser.ID},
		}, &space); err != nil {
			return "", "", fmt.Errorf("photon cloud: impossible d'ouvrir la conversation iMessage : %w", err)
		}
		if space.ID == "" {
			return "", "", errors.New("photon cloud: réponse conversation vide")
		}
		spaceID = space.ID
	}

	p.mu.Lock()
	p.senderID = senderID
	p.spaceID = spaceID
	p.mu.Unlock()
	return senderID, spaceID, nil
}

func (p *PhotonNotifier) cloudJSONRequest(ctx context.Context, method, endpoint string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Photon-Version", photonAPIVersion)
	req.Header.Set("User-Agent", "MeshWatch/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return err
		}
	}
	return nil
}

func (p *PhotonNotifier) sendCustom(ctx context.Context, text string) error {
	payload := map[string]string{
		p.recipientField: p.recipient,
		p.messageField:   text,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal photon payload: %w", err)
	}
	bearer := p.token
	if bearer == "" {
		bearer = p.apiKey
	}
	return p.postWithRetry(ctx, p.endpoint, bearer, nil, raw)
}

func (p *PhotonNotifier) postWithRetry(ctx context.Context, endpoint, bearer string, extraHeaders map[string]string, raw []byte) error {
	return retryWithBackoff(ctx, p.backoffs, func(_ int) (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
		if err != nil {
			return false, fmt.Errorf("create photon request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "MeshWatch/1.0")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}

		resp, err := p.client.Do(req)
		if err != nil {
			return ctx.Err() == nil, fmt.Errorf("photon POST failed: %w", err)
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return false, nil
		}
		return isRetryableStatus(resp.StatusCode), fmt.Errorf("photon returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	})
}

func buildIdempotencyKey(alert Alert) string {
	var b strings.Builder
	b.WriteString("mw:")
	if alert.State != "" {
		b.WriteString(strings.ToLower(string(alert.State)))
		b.WriteByte(':')
	}
	rawID := strings.TrimSpace(alert.IncidentID)
	if rawID != "" {
		for _, r := range rawID {
			if r >= 0x21 && r <= 0x7e {
				b.WriteRune(r)
			} else {
				b.WriteByte('_')
			}
		}
	} else {
		var rnd [8]byte
		_, _ = rand.Read(rnd[:])
		b.WriteString(hex.EncodeToString(rnd[:]))
	}
	key := b.String()
	if len(key) > 200 {
		key = key[:200]
	}
	return key
}
