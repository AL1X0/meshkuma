package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"meshwatch/internal/config"
)

const (
	defaultPhotonSpectrumBaseURL    = "https://spectrum.photon.codes"
	defaultSpectrumSharedIMessage   = "https://imessage.spectrum.photon.codes"
	defaultPhotonCloudBaseURL       = "https://api.photon.codes/v1"
	defaultPhotonProxyBaseURL       = "https://imessage-swagger.photon.codes"
	photonAPIVersion                = "2026-07-01"
)

// PhotonNotifier sends MeshWatch alerts through Photon iMessage with 3 exponential
// backoff retries (2s, 5s, 10s) on transient errors.
//
// Supported modes (per official Photon docs):
//   - "cloud" / "spectrum": automatically routes UUID project credentials to Photon Stable
//     (`https://spectrum.photon.codes` Basic Auth + HTTP/2 gRPC to `imessage.spectrum.photon.codes`)
//     or `pho_prj_` / `pho_sk_` credentials to Photon Beta 2.0 (`https://api.photon.codes/v1`)
//   - "proxy": Photon Advanced iMessage HTTP Proxy (POST /send with {"to","text"})
//   - "custom": Generic JSON webhook with configurable recipient_field / message_field
type PhotonNotifier struct {
	mode                    string
	endpoint                string
	projectID               string
	apiKey                  string
	serverURL               string
	token                   string
	recipient               string
	recipientField          string
	messageField            string
	client                  *http.Client
	grpcClient              *http.Client
	spectrumIMessageBaseURL string
	backoffs                []time.Duration

	mu         sync.Mutex
	senderID   string
	spaceID    string
	specType   string
	specToken  string
	specHost   string
	specExpiry time.Time
}

// NewPhotonNotifier constructs a PhotonNotifier from configuration.
func NewPhotonNotifier(cfg config.PhotonConfig) *PhotonNotifier {
	mode := cfg.EffectiveMode()
	endpoint := strings.TrimSpace(cfg.URL)
	if endpoint == "" && mode == "proxy" {
		endpoint = defaultPhotonProxyBaseURL
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
	if apiKey == "" && (mode == "cloud" || mode == "spectrum") {
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
		// Keep connections persistent with ForceAttemptHTTP2 so Go uses HTTP/2 for gRPC.
		grpcClient: &http.Client{
			Timeout: defaultNotifyHTTPTimeout,
			Transport: &http.Transport{
				ForceAttemptHTTP2: true,
			},
		},
		backoffs: append([]time.Duration(nil), DefaultRetryBackoffs...),
	}
}

func (p *PhotonNotifier) Name() string { return "photon_imessage" }

func (p *PhotonNotifier) Send(ctx context.Context, alert Alert) error {
	text := alert.Title() + "\n" + alert.Body()
	switch p.mode {
	case "spectrum":
		return p.sendSpectrum(ctx, alert, text)
	case "cloud":
		if p.isBeta2Cloud() {
			return p.sendBeta2Cloud(ctx, alert, text)
		}
		return p.sendSpectrum(ctx, alert, text)
	case "proxy":
		return p.sendProxy(ctx, text)
	default:
		return p.sendCustom(ctx, text)
	}
}

// isBeta2Cloud distinguishes Photon Beta 2.0 (`pho_prj_` / `pho_sk_`) from Photon Stable/Spectrum (UUID).
func (p *PhotonNotifier) isBeta2Cloud() bool {
	if strings.EqualFold(p.mode, "spectrum") {
		return false
	}
	if strings.HasPrefix(p.projectID, "pho_prj_") ||
		strings.HasPrefix(p.apiKey, "pho_sk_") ||
		strings.HasPrefix(p.apiKey, "pho_ask_") {
		return true
	}
	lowerURL := strings.ToLower(p.endpoint)
	if strings.Contains(lowerURL, "spectrum.photon.codes") {
		return false
	}
	if strings.Contains(lowerURL, "api.photon.codes") && !looksLikeUUID(p.projectID) {
		return true
	}
	return false
}

func looksLikeUUID(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

/* ---------------- PHOTON STABLE / SPECTRUM (BASIC AUTH + HTTP/2 gRPC) ---------------- */

func (p *PhotonNotifier) spectrumBaseURL() string {
	base := strings.TrimRight(p.endpoint, "/")
	lower := strings.ToLower(base)
	// Ignore legacy Beta 2.0 default URL when project credentials are Spectrum UUIDs.
	if base == "" || strings.Contains(lower, "api.photon.codes") {
		return defaultPhotonSpectrumBaseURL
	}
	return base
}

func (p *PhotonNotifier) sendSpectrum(ctx context.Context, alert Alert, text string) error {
	if p.projectID == "" {
		return errors.New("photon: identifiant projet requis")
	}
	if p.apiKey == "" {
		return errors.New("photon: clé secrète projet requise")
	}
	if p.recipient == "" {
		return errors.New("photon: numéro ou email du destinataire requis")
	}

	lineType, host, token, err := p.getSpectrumIMessageToken(ctx, false)
	if err != nil {
		return err
	}

	chatGUID, err := p.resolveSpectrumChatGUID(ctx, lineType, host, token)
	if err != nil {
		return err
	}

	idemKey := buildIdempotencyKey(alert)
	reqProto := encodeSendTextMessageRequest(chatGUID, text, idemKey)

	return p.postSpectrumGRPC(ctx, host, token, idemKey, reqProto)
}

type spectrumTokenResponse struct {
	Succeed bool   `json:"succeed"`
	Message string `json:"message"`
	Data    struct {
		Type      string            `json:"type"`
		Token     string            `json:"token"`
		Auth      map[string]string `json:"auth"`
		Numbers   map[string]string `json:"numbers"`
		ExpiresIn int64             `json:"expiresIn"`
	} `json:"data"`
}

func (p *PhotonNotifier) clearSpectrumTokenCache() {
	p.mu.Lock()
	p.specToken = ""
	p.specHost = ""
	p.specType = ""
	p.specExpiry = time.Time{}
	p.mu.Unlock()
}

func (p *PhotonNotifier) getSpectrumIMessageToken(ctx context.Context, forceRefresh bool) (lineType, host, token string, err error) {
	p.mu.Lock()
	if !forceRefresh && p.specToken != "" && p.specHost != "" && time.Now().Before(p.specExpiry) {
		lt, h, tk := p.specType, p.specHost, p.specToken
		p.mu.Unlock()
		return lt, h, tk, nil
	}
	p.mu.Unlock()

	endpoint := fmt.Sprintf("%s/projects/%s/imessage/tokens", p.spectrumBaseURL(), url.PathEscape(p.projectID))
	creds := base64.StdEncoding.EncodeToString([]byte(p.projectID + ":" + p.apiKey))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Authorization", "Basic "+creds)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "MeshWatch/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("photon spectrum: connexion impossible : %w", err)
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", "", "", fmt.Errorf("photon spectrum: identifiants refusés (%s), vérifiez Project ID et Project Secret sur app.photon.codes", formatPhotonProblem(resp.StatusCode, respBody))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", "", fmt.Errorf("photon spectrum: récupération du jeton iMessage échouée (%s)", formatPhotonProblem(resp.StatusCode, respBody))
	}

	var parsed spectrumTokenResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", "", "", fmt.Errorf("photon spectrum: réponse invalide (%w)", err)
	}
	if !parsed.Succeed {
		msg := strings.TrimSpace(parsed.Message)
		if msg == "" {
			msg = "échec d'autorisation Spectrum"
		}
		return "", "", "", fmt.Errorf("photon spectrum: %s", msg)
	}

	lt := strings.ToLower(strings.TrimSpace(parsed.Data.Type))
	switch lt {
	case "shared":
		tk := strings.TrimSpace(parsed.Data.Token)
		if tk == "" {
			return "", "", "", errors.New("photon spectrum: jeton iMessage partagé vide")
		}
		h := defaultSpectrumSharedIMessage
		if p.spectrumIMessageBaseURL != "" {
			h = strings.TrimRight(p.spectrumIMessageBaseURL, "/")
		}
		lineType, host, token = "shared", h, tk

	case "dedicated":
		if len(parsed.Data.Auth) == 0 {
			return "", "", "", errors.New("photon spectrum: aucune ligne iMessage dédiée active sur ce projet")
		}
		ids := make([]string, 0, len(parsed.Data.Auth))
		for id, tk := range parsed.Data.Auth {
			if strings.TrimSpace(tk) != "" {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			return "", "", "", errors.New("photon spectrum: aucun jeton de ligne dédiée valide")
		}
		sort.Strings(ids)
		chosen := ids[0]
		h := "https://" + chosen + ".imsg.photon.codes"
		if p.spectrumIMessageBaseURL != "" {
			h = strings.TrimRight(p.spectrumIMessageBaseURL, "/")
		}
		lineType, host, token = "dedicated", h, parsed.Data.Auth[chosen]

	default:
		return "", "", "", fmt.Errorf("photon spectrum: type de ligne iMessage inconnu (%q)", parsed.Data.Type)
	}

	ttlSec := parsed.Data.ExpiresIn * 80 / 100
	if ttlSec < 30 {
		ttlSec = 30
	}
	p.mu.Lock()
	p.specType = lineType
	p.specHost = host
	p.specToken = token
	p.specExpiry = time.Now().Add(time.Duration(ttlSec) * time.Second)
	p.mu.Unlock()

	return lineType, host, token, nil
}

func (p *PhotonNotifier) resolveSpectrumChatGUID(ctx context.Context, lineType, host, token string) (string, error) {
	rec := strings.TrimSpace(p.recipient)
	if strings.Contains(rec, ";") {
		return rec, nil
	}
	if lineType == "dedicated" {
		reqProto := encodeCreateChatRequest([]string{rec}, 1) // 1 = CHAT_SERVICE_TYPE_IMESSAGE
		endpoint := strings.TrimRight(host, "/") + "/photon.imessage.v1.ChatService/CreateChat"
		respProto, grpcStatus, grpcMsg, err := p.doSingleGRPCCall(ctx, endpoint, token, "", reqProto)
		if err == nil && (grpcStatus == "" || grpcStatus == "0") {
			if guid := decodeCreateChatResponseGUID(respProto); guid != "" {
				return guid, nil
			}
		} else if err != nil {
			return "", fmt.Errorf("photon spectrum: création de la discussion iMessage impossible : %w", err)
		} else if grpcStatus != "" && grpcStatus != "0" {
			return "", fmt.Errorf("photon spectrum: création discussion gRPC %s (%s)", grpcStatus, humanizeGRPCError(grpcStatus, grpcMsg))
		}
	}
	return normalizeDMChatGUID(rec), nil
}

func normalizeDMChatGUID(recipient string) string {
	r := strings.TrimSpace(recipient)
	if strings.Contains(r, ";") {
		return r
	}
	return "iMessage;-;" + r
}

func (p *PhotonNotifier) postSpectrumGRPC(ctx context.Context, host, token, idemKey string, reqProto []byte) error {
	refreshedAuth := false
	return retryWithBackoff(ctx, p.backoffs, func(_ int) (bool, error) {
		endpoint := strings.TrimRight(host, "/") + "/photon.imessage.v1.MessageService/SendTextMessage"
		_, grpcStatus, grpcMsg, err := p.doSingleGRPCCall(ctx, endpoint, token, idemKey, reqProto)
		if err != nil {
			return ctx.Err() == nil, fmt.Errorf("photon spectrum gRPC échoué : %w", err)
		}
		if grpcStatus == "" || grpcStatus == "0" {
			return false, nil
		}
		if grpcStatus == "16" && !refreshedAuth {
			refreshedAuth = true
			p.clearSpectrumTokenCache()
			_, newHost, newTok, tokErr := p.getSpectrumIMessageToken(ctx, true)
			if tokErr == nil {
				token = newTok
				if newHost != "" {
					host = newHost
				}
				return true, fmt.Errorf("photon spectrum: jeton expiré (%s)", humanizeGRPCError(grpcStatus, grpcMsg))
			}
		}
		return isRetryableGRPCStatus(grpcStatus), fmt.Errorf("photon spectrum (gRPC %s) : %s", grpcStatus, humanizeGRPCError(grpcStatus, grpcMsg))
	})
}

func (p *PhotonNotifier) doSingleGRPCCall(ctx context.Context, endpoint, token, idemKey string, reqProto []byte) ([]byte, string, string, error) {
	frame := frameGRPC(reqProto)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(frame))
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "MeshWatch/1.0")
	if idemKey != "" {
		req.Header.Set("x-idempotency-key", idemKey)
	}

	resp, err := p.grpcClient.Do(req)
	if err != nil {
		return nil, "", "", err
	}
	rawResp, readErr := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, "", "", readErr
	}

	// Trailers are populated only after draining resp.Body; fall back to Header for Trailers-Only replies.
	grpcStatus := strings.TrimSpace(resp.Trailer.Get("Grpc-Status"))
	if grpcStatus == "" {
		grpcStatus = strings.TrimSpace(resp.Header.Get("Grpc-Status"))
	}
	rawMsg := strings.TrimSpace(resp.Trailer.Get("Grpc-Message"))
	if rawMsg == "" {
		rawMsg = strings.TrimSpace(resp.Header.Get("Grpc-Message"))
	}
	grpcMsg, err := url.PathUnescape(rawMsg)
	if err != nil {
		grpcMsg = rawMsg
	}

	if resp.StatusCode != http.StatusOK && grpcStatus == "" {
		return nil, "", "", fmt.Errorf("HTTP %d (%s)", resp.StatusCode, formatPhotonProblem(resp.StatusCode, rawResp))
	}

	payload, _ := unframeGRPC(rawResp)
	return payload, grpcStatus, grpcMsg, nil
}

func isRetryableGRPCStatus(code string) bool {
	switch strings.TrimSpace(code) {
	case "4", "8", "14": // DEADLINE_EXCEEDED, RESOURCE_EXHAUSTED, UNAVAILABLE
		return true
	default:
		return false
	}
}

func humanizeGRPCError(code, msg string) string {
	clean := strings.TrimSpace(msg)
	switch strings.TrimSpace(code) {
	case "3":
		return fallbackText(clean, "destinataire ou paramètre iMessage invalide")
	case "5":
		return fallbackText(clean, "adresse introuvable sur iMessage")
	case "7":
		return fallbackText(clean, "autorisation refusée pour ce destinataire")
	case "14":
		return fallbackText(clean, "serveur iMessage Photon temporairement indisponible")
	case "16":
		return fallbackText(clean, "jeton d'accès iMessage refusé ou expiré")
	default:
		return fallbackText(clean, "erreur gRPC "+code)
	}
}

func fallbackText(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

/* ---------------- ZERO-DEPENDENCY PROTO3 / gRPC WIRE HELPERS ---------------- */

func frameGRPC(protoMsg []byte) []byte {
	frame := make([]byte, 5+len(protoMsg))
	frame[0] = 0 // uncompressed
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(protoMsg)))
	copy(frame[5:], protoMsg)
	return frame
}

func unframeGRPC(frame []byte) ([]byte, bool) {
	if len(frame) < 5 {
		return nil, false
	}
	msgLen := binary.BigEndian.Uint32(frame[1:5])
	if int(5+msgLen) > len(frame) {
		return nil, false
	}
	return frame[5 : 5+msgLen], true
}

func appendProtoVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func appendProtoStringField(dst []byte, fieldNum uint64, val string) []byte {
	if val == "" {
		return dst
	}
	dst = appendProtoVarint(dst, (fieldNum<<3)|2)
	dst = appendProtoVarint(dst, uint64(len(val)))
	return append(dst, val...)
}

func appendProtoVarintField(dst []byte, fieldNum uint64, val uint64) []byte {
	if val == 0 {
		return dst
	}
	dst = appendProtoVarint(dst, (fieldNum<<3)|0)
	return appendProtoVarint(dst, val)
}

func encodeSendTextMessageRequest(chatGUID, text, clientMsgID string) []byte {
	var b []byte
	b = appendProtoStringField(b, 1, chatGUID)
	b = appendProtoStringField(b, 2, text)
	b = appendProtoStringField(b, 100, clientMsgID)
	return b
}

func encodeCreateChatRequest(addresses []string, service uint64) []byte {
	var b []byte
	for _, addr := range addresses {
		b = appendProtoStringField(b, 1, addr)
	}
	b = appendProtoVarintField(b, 2, service)
	return b
}

func decodeCreateChatResponseGUID(data []byte) string {
	chatBytes, ok := readProtoFieldBytes(data, 1)
	if !ok {
		return ""
	}
	guidBytes, ok := readProtoFieldBytes(chatBytes, 1)
	if !ok {
		return ""
	}
	return string(guidBytes)
}

func readProtoFieldBytes(data []byte, targetField uint64) ([]byte, bool) {
	pos := 0
	for pos < len(data) {
		tag, n := binary.Uvarint(data[pos:])
		if n <= 0 {
			return nil, false
		}
		pos += n
		fieldNum := tag >> 3
		wireType := tag & 0x7

		switch wireType {
		case 0: // varint
			_, vn := binary.Uvarint(data[pos:])
			if vn <= 0 {
				return nil, false
			}
			pos += vn
		case 1: // 64-bit
			pos += 8
		case 2: // length-delimited
			l, ln := binary.Uvarint(data[pos:])
			if ln <= 0 {
				return nil, false
			}
			pos += ln
			if l > uint64(len(data)-pos) {
				return nil, false
			}
			val := data[pos : pos+int(l)]
			pos += int(l)
			if fieldNum == targetField {
				return val, true
			}
		case 5: // 32-bit
			pos += 4
		default:
			return nil, false
		}
	}
	return nil, false
}

/* ---------------- PHOTON PROXY MODE ---------------- */

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

/* ---------------- PHOTON BETA 2.0 CLOUD API ---------------- */

// sendBeta2Cloud targets Photon 2.0 Cloud API (`https://api.photon.codes/v1`):
//
//	POST /projects/{projectId}/messages
//	Authorization: Bearer <pho_sk_...>
//	Idempotency-Key: <stable key>
//	Photon-Version: 2026-07-01
func (p *PhotonNotifier) sendBeta2Cloud(ctx context.Context, alert Alert, text string) error {
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
			return "", "", errors.New("photon cloud: aucune ligne iMessage agent trouvée sur ce projet (assignez une ligne sur app.beta.photon.codes)")
		}
	}

	spaceID := cachedSpace
	if spaceID == "" {
		if p.recipient == "" {
			return "", "", errors.New("photon cloud: destinataire (numéro E.164 ou email iMessage) requis")
		}
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
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, formatPhotonProblem(resp.StatusCode, respBody))
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return err
		}
	}
	return nil
}

/* ---------------- CUSTOM WEBHOOK & SHARED HELPERS ---------------- */

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
		return isRetryableStatus(resp.StatusCode), fmt.Errorf("photon returned HTTP %d: %s", resp.StatusCode, formatPhotonProblem(resp.StatusCode, respBody))
	})
}

func formatPhotonProblem(status int, rawBody []byte) string {
	var parsed struct {
		Title   string `json:"title"`
		Detail  string `json:"detail"`
		Message string `json:"message"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rawBody, &parsed); err == nil {
		var parts []string
		if parsed.Detail != "" {
			parts = append(parts, parsed.Detail)
		} else if parsed.Message != "" {
			parts = append(parts, parsed.Message)
		} else if parsed.Title != "" {
			parts = append(parts, parsed.Title)
		}
		if parsed.Code != "" && !strings.Contains(strings.ToLower(strings.Join(parts, " ")), strings.ToLower(parsed.Code)) {
			parts = append(parts, parsed.Code)
		}
		if len(parts) > 0 {
			return strings.Join(parts, " : ")
		}
	}
	txt := strings.TrimSpace(string(rawBody))
	if txt != "" {
		return txt
	}
	return fmt.Sprintf("HTTP %d", status)
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
