# SPEC.md — MeshWatch (Supervision Mesh P2P sur Nostr + Uptime Kuma)

## 1. Objectif & Contraintes strictes

Construire MeshWatch, un agent de supervision décentralisé en Go déployé en conteneur Docker. Chaque participant héberge une instance chez lui pour superviser son propre LAN et échanger des heartbeats chiffrés avec ses pairs via des relais Nostr publics.

### Contraintes non négociables

- **Zéro port entrant** : Aucun port ne doit être ouvert sur la box/pare-feu de qui que ce soit. 100 % du trafic WAN est sortant (WSS port 443 vers les relais Nostr, HTTPS sortant vers ntfy/Photon).
- **Isolation stricte du LAN** : Un pair distant ne peut jamais exécuter de sonde, scanner le LAN ou interroger un service local. Chaque agent exécute ses propres sondes en local et ne diffuse que des résumés d'état JSON chiffrés.
- **Empreinte minimale** : Un seul binaire Go statique (`CGO_ENABLED=0`), image Docker multi-stage basée sur `scratch` ou `gcr.io/distroless/static-debian12`, consommation RAM visée inférieure à 30 Mo.
- **Pas de reverse proxy embarqué** : Ne pas inclure de serveur web exposé ou de proxy TLS dans l'agent.

## 2. Architecture globale

```text
[LAN Local]                                      [Internet - Trafic 100% Sortant]
  ├── NAS Synology (SNMPv2c/v3) ──┐
  ├── Docker (/var/run/docker.sock)│
  ├── Serveur Linux (node_exporter)├─► [MeshWatch Agent (Go)] ══(WSS 443 / AES-256-GCM)══► Relais Nostr (x3-4)
  ├── Serveur Win (windows_exporter)│          │                                                   ▲
  └── Services HTTP / TLS / TCP ──┘          │ (LAN Docker interne)                                │
                                             ▼                                           (Pairs abonnés)
                                    [Uptime Kuma (Push)]                                           │
                                             │                                                     ▼
                                             └──► Alertes (ntfy / Photon iMessage) ◄── [MeshWatch Pote A/B/C]
```

## 3. Stack technique & Arborescence

- **Langage** : Go 1.23+
- **Bibliothèques recommandées** :
  - Nostr : `github.com/nbd-wtf/go-nostr`
  - SNMP : `github.com/gosnmp/gosnmp`
  - Docker : API HTTP locale sur socket Unix (std `net/http` avec `UnixDialer` ou `github.com/docker/docker/client`) — privilégier la légèreté.
  - Config : `gopkg.in/yaml.v3`
  - Logs : `log/slog` (format JSON ou texte configurable).

```text
meshwatch/
├── cmd/meshwatch/
│   └── main.go                 # CLI: "run" (démon) et "keygen" (génération clés Nostr + PSK)
├── internal/
│   ├── config/
│   │   └── config.go           # Parsing YAML + validation stricte au démarrage
│   ├── crypto/
│   │   └── cipher.go           # HKDF-SHA256 + AES-256-GCM + dérivé de tag de groupe
│   ├── transport/
│   │   └── nostr.go            # Pool de relais WSS, reconnexion auto, déduplication d'events
│   ├── probes/
│   │   ├── probe.go            # Interface Probe + Scheduler concurrent
│   │   ├── http.go             # HTTP status, latency, keyword, expiration TLS
│   │   ├── tcp.go              # Check TCP simple
│   │   ├── docker.go           # Socket Docker / socket-proxy (running, health, restarts)
│   │   ├── synology.go         # SNMP Synology (OIDs 1.3.6.1.4.1.6574.*)
│   │   └── exporter.go         # Scraping métriques Prometheus (node_exporter & windows_exporter)
│   ├── quorum/
│   │   └── engine.go           # Suivi d'état des pairs, Auto-Mute, élection du notificateur
│   ├── kuma/
│   │   └── pusher.go           # Client HTTP Push vers Uptime Kuma local
│   └── notify/
│       ├── notifier.go         # Interface Notifier
│       ├── ntfy.go             # Connecteur ntfy
│       └── photon.go           # Connecteur Gateway Photon iMessage
├── Dockerfile
├── docker-compose.yml
├── config.example.yaml
└── go.mod
```

## 4. Spécification du protocole Nostr & Sécurité

### 4.1 Chiffrement & Confidentialité

- **Clé de groupe (`group_psk`)** : 32 octets aléatoires encodés en hex/base64, partagés hors bande entre les potes.
- **Clé de chiffrement** : Dérivée de `group_psk` via HKDF-SHA256 (salt fixe applicatif `"meshwatch-v1-enc"`).
- **Tag de routage (`#t`)** : `hex(SHA256("meshwatch-v1-topic:" + group_psk))[:16]`. Permet de s'abonner uniquement aux événements du groupe sur des relais publics sans révéler son nom.
- **Chiffrement du champ `content`** : `base64(nonce_12_bytes || AES-256-GCM(plaintext_json))`.

### 4.2 Format des événements Nostr

- **Kind** : `24242` (événement éphémère NIP-01/NIP-16, non persisté sur disque par les relais).
- **Tags** : `[["t", "<group_topic_hash>"]]`.
- **Validation obligatoire à la réception** :
  - Vérifier la signature Schnorr Nostr (`ev.CheckSignature()`).
  - Vérifier que `ev.PubKey` figure dans `allowed_peers` de la config.
  - Vérifier `abs(now - ev.CreatedAt) <= 60s` (anti-rejeu).
  - Dédupliquer par `ev.ID` (car reçu depuis 3 à 4 relais simultanément).
  - Déchiffrer `content` en AES-256-GCM (rejet silencieux si échec).

### 4.3 Payloads JSON (après déchiffrement)

**Type 1 — Heartbeat périodique** (toutes les `heartbeat_interval`, défaut `30s`) :

```json
{
  "type": "heartbeat",
  "node_name": "mon-homelab",
  "ts": 1764060000,
  "uptime_sec": 84210,
  "overall_ok": true,
  "probes": [
    { "id": "syno-ds920", "kind": "synology", "ok": true, "summary": "RAID OK, 36°C, Vol1 64%" },
    { "id": "docker-core", "kind": "docker", "ok": true, "summary": "18/18 up" },
    { "id": "win-srv-01", "kind": "windows", "ok": false, "summary": "Service VeeamBackup stopped" }
  ]
}
```

**Type 2 — Revendication d'alerte (Anti-Alert Storm)** :

```json
{
  "type": "alert_claim",
  "target_pubkey": "<hex_pubkey_du_pair_down>",
  "incident_id": "<target_pubkey>:<timestamp_bucket_60s>",
  "reason": "peer_timeout"
}
```

## 5. Spécification des Sondes (`internal/probes`)

Toutes les sondes implémentent :

```go
type ProbeResult struct {
    ID      string `json:"id"`
    Kind    string `json:"kind"`
    OK      bool   `json:"ok"`
    Summary string `json:"summary"`
    Latency int64  `json:"latency_ms,omitempty"`
}
```

- **Synology SNMP (`synology`)** :
  - Support SNMPv2c (`community`) et SNMPv3 (`user`, `auth_proto`, `auth_pass`, `priv_proto`, `priv_pass`).
  - OIDs à interroger :
    - System status : `.1.3.6.1.4.1.6574.1.1.0` (`1` = Normal, `2` = Failed).
    - Température système : `.1.3.6.1.4.1.6574.1.2.0` (seuil configurable, défaut `60°C`).
    - Statut ventilateurs (system/power) : `.1.3.6.1.4.1.6574.1.4.1.0`, `.1.3.6.1.4.1.6574.1.4.2.0` (`1` = Normal).
    - Walk RAID status : `.1.3.6.1.4.1.6574.3.1.1.4` (`1` = Normal, tout autre code = dégradé/rebuilding/crashed).
    - Walk Disk status : `.1.3.6.1.4.1.6574.2.1.1.5` (`1` = Normal).
- **Docker (`docker`)** :
  - Connexion sur `/var/run/docker.sock` (ou URL `tcp://docker-socket-proxy:2375`).
  - Liste les conteneurs configurés (ou tous ceux ayant un label ex. `meshwatch.enable=true`).
  - Passe en `OK: false` si un conteneur surveillé n'est pas `running` ou a un healthcheck `unhealthy`.
- **Linux (`node_exporter`) & Windows (`windows_exporter`)** :
  - Requête HTTP GET sur `/metrics` en LAN (ex. `http://192.168.1.20:9100/metrics` ou `:9182/metrics`).
  - Parsing léger des métriques clés : % utilisation RAM, % espace libre disques configurés, et (pour Windows) état des services listés (`windows_service_state{name="...",state="running"} == 1`).
- **HTTP / TLS / SNMP générique / TCP** :
  - `http` : vérifie `expected_status` (défaut `200`), `contains` (optionnel), et expiration du certificat TLS (`tls_min_days`, défaut 14j).
  - `tcp` : `net.DialTimeout` vers `host:port`.
  - `snmp_oid` : vérification générique d'un OID arbitraire contre une valeur attendue ou un seuil min/max.

## 6. Moteur de Quorum, Auto-Mute & Pont Uptime Kuma

### 6.1 Auto-Mute (Protection coupure fibre locale)

- Avant toute décision d'alerte, vérifier la connectivité WAN via TCP Dial (timeout 3s) vers au moins 2 cibles externes (`1.1.1.1:443`, `9.9.9.9:443`).
- Si toutes échouent → le nœud local passe en état `muted = true` : il suspend les alertes sortantes et ne déclare aucun pair down.

### 6.2 Pont Uptime Kuma (`internal/kuma`)

- Pour chaque pair ayant une `kuma_push_url` dans la config :
  - À réception d'un heartbeat valide : envoyer `GET <kuma_push_url>?status=<up|down>&msg=<résumé_url_encodé>&ping=<ms>`.
  - Si `overall_ok == true` → `status=up`. Si une sonde interne du pair échoue → `status=down` avec le détail de la sonde en erreur dans `msg`.
  - Si le pair cesse d'émettre (coupure fibre/courant), l'agent ne fait plus d'appel HTTP → le Dead Man's Switch d'Uptime Kuma déclenche le passage en rouge automatiquement.

### 6.3 Élection du notificateur (Anti-Alert Storm dès 3 nœuds)

- Un pair est considéré DOWN si aucun heartbeat n'a été reçu depuis `peer_timeout` (défaut `90s`), ou si une de ses sondes passe de `ok: true` à `ok: false`.
- Pour éviter que N pairs envoient N notifications :
  - Construire la liste des `pubkey` de tous les pairs considérés ONLINE + sa propre `pubkey`.
  - Trier cette liste par ordre lexicographique croissant.
  - **Rang 0** : publie immédiatement un `alert_claim` sur Nostr et déclenche les notifiers (ntfy / Photon).
  - **Rang 1** : attend 15 secondes ; si aucun `alert_claim` valide pour cet `incident_id` n'est reçu, il prend le relais et notifie.
  - **Rang >= 2** : attend 30 secondes (même logique de fallback).
- Même logique pour les notifications de rétablissement (`RESOLVED`).

## 7. Connecteurs de Notification (`internal/notify`)

### 7.1 ntfy

- Requête POST vers `<server_url>/<topic>`.
- Headers : `Title`, `Priority` (`urgent` pour DOWN, `default` pour RESOLVED), `Tags` (`rotating_light` / `white_check_mark`), `Authorization: Bearer <token>` si configuré.

### 7.2 Gateway Photon iMessage

- Requête POST HTTP configurable vers l'endpoint du gateway Photon (ex. `POST <photon_url>/api/v1/message` ou endpoint défini en config) avec header `Authorization: Bearer <api_key>`.
- Payload JSON configurable : `{ "recipient": "<phone_or_chat_guid>", "message": "<texte_alerte>" }`.
- Retry 3 fois avec backoff exponentiel (2s, 5s, 10s) en cas d'erreur réseau 5xx/timeout.

## 8. Configuration & Déploiement

### `config.example.yaml`

```yaml
node:
  name: "mon-homelab"
  private_key_hex: "REMPLACER_VIA_KEYGEN"
  group_psk_hex: "REMPLACER_VIA_KEYGEN"
  heartbeat_interval: 30s
  peer_timeout: 90s

nostr:
  relays:
    - "wss://relay.damus.io"
    - "wss://nos.lol"
    - "wss://relay.primal.net"
    - "wss://relay.nostr.band"

auto_mute:
  targets: ["1.1.1.1:443", "9.9.9.9:443"]

peers:
  - name: "ami-nord"
    pubkey_hex: "PUBKEY_HEX_DU_POTE"
    kuma_push_url: "http://uptime-kuma:3001/api/push/XXXXXXXX"

probes:
  - id: "syno-nas"
    kind: "synology"
    interval: 60s
    host: "192.168.1.20"
    snmp_version: "2c"
    community: "public"
    max_temp_c: 55

  - id: "docker-local"
    kind: "docker"
    interval: 30s
    socket: "/var/run/docker.sock"
    containers: ["jellyfin", "traefik", "homeassistant"]

  - id: "srv-linux"
    kind: "node_exporter"
    interval: 60s
    url: "http://192.168.1.10:9100/metrics"
    max_disk_percent: 90
    max_ram_percent: 92

  - id: "srv-windows"
    kind: "windows_exporter"
    interval: 60s
    url: "http://192.168.1.15:9182/metrics"
    services: ["W32Time", "VeeamBackupSvc"]
    max_disk_percent: 90

  - id: "web-public"
    kind: "http"
    interval: 30s
    url: "https://mon-domaine.fr"
    expected_status: 200
    tls_min_days: 14

notifications:
  ntfy:
    enabled: true
    url: "https://ntfy.sh/mon-topic-secret-meshwatch"
    token: ""
  photon_imessage:
    enabled: true
    url: "https://ton-gateway-photon.example/send"
    token: "TON_TOKEN_PHOTON"
    recipient: "+33600000000"
```

### `docker-compose.yml`

```yaml
services:
  uptime-kuma:
    image: louislam/uptime-kuma:2
    container_name: meshwatch-kuma
    restart: unless-stopped
    volumes:
      - ./data/kuma:/app/data
    networks:
      - meshwatch-net
    # Exposer uniquement sur localhost ou via ton reverse proxy existant si besoin

  meshwatch:
    build: .
    container_name: meshwatch-agent
    restart: unless-stopped
    read_only: true
    security_opt:
      - no-new-privileges:true
    volumes:
      - ./config.yaml:/etc/meshwatch/config.yaml:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - meshwatch-net
    command: ["run", "--config", "/etc/meshwatch/config.yaml"]

networks:
  meshwatch-net:
    driver: bridge
```

## 9. Plan d'exécution phasé (à suivre dans l'ordre)

### Phase 1 — Socle Go, CLI keygen, Config & Crypto

- Initialiser `go.mod`, structure de dossiers et parsing `config.yaml` avec validation stricte au démarrage.
- Implémenter `meshwatch keygen` (génère et affiche `private_key_hex`, `pubkey_hex`, et un `group_psk_hex` de 32 octets).
- Implémenter `internal/crypto` (HKDF + AES-256-GCM + tag `#t`).
- **Critère de validation** : Tests unitaires Go passant sur chiffrement/déchiffrement, rejet d'une mauvaise PSK et validation de config.

### Phase 2 — Transport Nostr Multi-Relais

- Implémenter `internal/transport/nostr.go` : connexion concurrente aux relais WSS, reconnexion automatique avec backoff, publication d'événements `kind: 24242`, abonnement filtré sur `#t`, vérification signature + whitelist `allowed_peers` + fenêtre anti-rejeu 60s + déduplication par EventID.
- **Critère de validation** : Test d'intégration local avec un relais Nostr mock en mémoire (ou 2 instances locales sur un relais public de test) confirmant l'échange chiffré de heartbeats.

### Phase 3 — Sondes de supervision (`internal/probes`)

- Implémenter le scheduler concurrent (chaque sonde tourne sur son propre `time.Ticker` avec `context.WithTimeout` pour ne jamais bloquer le heartbeat).
- Implémenter dans l'ordre : `http` (avec check TLS), `tcp`, `docker`, `synology` (SNMP), `node_exporter`, `windows_exporter`.
- **Critère de validation** : Tests unitaires avec serveurs HTTP mockés (faux `/metrics` Prometheus, faux endpoint HTTP/TLS) et mock du parser SNMP Synology.

### Phase 4 — Moteur de Quorum, Auto-Mute & Pont Uptime Kuma

- Implémenter le suivi d'état des pairs, le `CheckAutoMute()`, le pusher HTTP vers Uptime Kuma et la machine à états d'élection (`alert_claim` + délais par rang).
- **Critère de validation** : Tests unitaires simulant 3 nœuds (dont 1 qui tombe) prouvant qu'un seul nœud notifie, puis simulant la perte du nœud de rang 0 prouvant le failover du rang 1 après 15s, et testant l'Auto-Mute.

### Phase 5 — Connecteurs ntfy & Photon iMessage

- Implémenter les deux notifiers avec formatage lisible (nom du nœud, sonde fautive, résumé, horodatage) et retry HTTP.
- Ajouter une sous-commande `meshwatch test-notify --config config.yaml` pour valider ntfy et Photon sans attendre une vraie panne.
- **Critère de validation** : Tests unitaires sur `httptest.Server` vérifiant headers, payloads et retries.

### Phase 6 — Packaging Docker & Documentation

- Écrire le `Dockerfile` multi-stage (`golang:1.23-alpine` → `gcr.io/distroless/static-debian12:nonroot`).
- Finaliser `docker-compose.yml`, `config.example.yaml` et un `README.md` expliquant en 5 étapes comment générer les clés, échanger les `pubkey_hex` entre potes et lancer la stack.
- **Critère de validation** : `go test -race ./...` passe à 100 %, `docker build` réussit et l'image finale fait moins de 25 Mo.
