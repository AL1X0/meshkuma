<div align="center">

<picture>
  <img src="assets/banner.svg" alt="MeshWatch — Supervision Mesh P2P décentralisée sur Nostr" width="100%">
</picture>

<br/>

[![CI](https://github.com/AL1X0/meshkuma/actions/workflows/ci.yml/badge.svg)](https://github.com/AL1X0/meshkuma/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Docker Image](https://img.shields.io/badge/Docker-11.3%20MB%20distroless-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![Zero Inbound Ports](https://img.shields.io/badge/Ports%20entrants-0%20(100%25%20sortant)-10B981)](#sécurité--protocole-nostr)
[![License: MIT](https://img.shields.io/badge/License-MIT-a855f7.svg)](LICENSE)

**Supervisez vos homelabs entre amis — sans ouvrir aucun port, sans VPS central, et avec chiffrement de bout en bout.**

[Console Web](#console-web-locale-opt-in) · [Architecture](#architecture) · [Fonctionnalités](#fonctionnalités-clés) · [Sondes](#sondes-supportées) · [Démarrage rapide](#démarrage-rapide-en-5-étapes) · [Sécurité](#sécurité--protocole-nostr) · [CLI](#commandes-cli)

</div>

---

## Pourquoi MeshWatch ?

Quand votre fibre tombe ou que votre serveur domestique plante, **votre propre outil de supervision local tombe avec lui** et ne peut plus vous prévenir. Louer un VPS juste pour monitorer son homelab ajoute un coût, de la maintenance et un point central.

**MeshWatch** résout ce problème en créant un **maillage P2P de supervision 100 % autonome entre amis** :

- Chacun héberge **un seul conteneur Docker Go** (**11,5 Mo**, `~11 Mo` de RAM) dans son propre LAN — aucune base de données externe, aucun outil tiers à maintenir.
- Chaque agent exécute **localement** ses sondes (Synology SNMP, Proxmox VE API, Docker, Linux `node_exporter`, Windows `windows_exporter`, HTTP/TLS, TCP, SNMP générique) et conserve un **historique de disponibilité + journal des incidents intégré**.
- Il publie périodiquement un résumé JSON **chiffré en AES-256-GCM** via des **relais Nostr publics** (`kind: 24242`, éphémères, jamais stockés sur disque).
- Les pairs abonnés reçoivent ces heartbeats, affichent la santé et la disponibilité de chaque ami dans leur interface, et élisent automatiquement **un seul notificateur** (`ntfy` / **Photon iMessage**) en cas de panne — fini les tempêtes d'alertes !

---

## Console Web locale (opt-in)

Désactivée par défaut pour préserver une surface d'attaque nulle, MeshWatch embarque (`//go:embed`) une **interface simple, guidée et 100 % pilotable au clic** (zéro fichier YAML à éditer) activable en local via `--ui 127.0.0.1:8080` :

- **Accueil clair & historique intégré** : état immédiat de vos services, barres de disponibilité temps réel, topologie visuelle en direct, santé de vos amis et journal d'activité récente.
- **Découverte Docker en 1 clic** : lit `/var/run/docker.sock` pour lister tous les conteneurs de la machine hôte et les cocher/décocher par simple interrupteur.
- **Scanner de réseau local (RFC1918) avec barre de recherche** : détecte automatiquement sur votre LAN vos NAS Synology, serveurs Linux/Windows et applications web locales (Jellyfin, Immich, Proxmox, Home Assistant…) et propose de les surveiller en un clic.
- **Invitations amis en 1 copier-coller (`MW1-...`)** : partagez un seul code d'invitation regroupant nom, clé publique et secret du groupe — zéro manipulation manuelle de clés hexadécimales.
- **Alertes guidées (`ntfy` + Photon Cloud / HTTP Proxy)** : génération automatique d'un canal privé `ntfy`, support officiel de Photon Cloud (`api.photon.codes/v1`) et Photon HTTP Proxy (`imessage-swagger.photon.codes`), et bouton de test direct.
- **Mise à jour en un clic** : attend que le build CI/GHCR soit réellement publié, télécharge le tag exact et remplace le conteneur en sécurité avec rollback automatique.

### Vue d'ensemble (avec alerte de mise à jour intégrée)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screenshots/overview-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/screenshots/overview-light.png">
  <img src="assets/screenshots/overview-light.png" alt="MeshWatch Console — Accueil temps réel" width="100%">
</picture>

<details>
<summary>Voir les deux thèmes (Clair &amp; Sombre) côte à côte</summary>
<br/>

| Thème clair (Pierre &amp; Cobalt) | Thème sombre (Encre marine) |
| :---: | :---: |
| <img src="assets/screenshots/overview-light.png" alt="Accueil thème clair" width="100%"> | <img src="assets/screenshots/overview-dark.png" alt="Accueil thème sombre" width="100%"> |

</details>

### Découverte en 1 clic (Docker &amp; Réseau local) et vue mobile

| Scan Docker de la machine hôte | Scan automatique du réseau local (LAN) |
| :---: | :---: |
| <img src="assets/screenshots/discover-docker.png" alt="Découverte des conteneurs Docker en 1 clic" width="100%"> | <img src="assets/screenshots/discover-lan-dark.png" alt="Scan du réseau local et ajout en 1 clic" width="100%"> |

<div align="center">
  <img src="assets/screenshots/mobile-light.png" alt="MeshWatch Console — Vue mobile responsive" width="320">
  <br/>
  <sub>Interface mobile responsive (390×844) : mise à jour directe, synthèse 2×2 et réseau d'entraide.</sub>
</div>

### Activer la console web locale

```bash
meshwatch run --config config.yaml --ui 127.0.0.1:8080 --ui-token "mon-jeton-local"
```

Avec Docker Compose, décommentez `ports` (`127.0.0.1:8080:8080`) et `MESHWATCH_UI_ADDR` / `MESHWATCH_UI_TOKEN` dans [docker-compose.yml](docker-compose.yml) : toutes vos modifications s'enregistrent et s'activent automatiquement depuis le navigateur.

---

## Architecture

```mermaid
flowchart LR
    subgraph LAN["LAN Local (100 % isolé — 0 port entrant)"]
        SYNO["NAS Synology<br/>SNMPv2c / v3"]
        DOCK["Docker<br/>socket / proxy"]
        LIN["Serveur Linux<br/>node_exporter"]
        WIN["Serveur Windows<br/>windows_exporter"]
        WEB["Services HTTP / TLS / TCP"]

        AGENT["MeshWatch Agent<br/>(Go · distroless 11.5 MB<br/>Interface Web & Historique intégrés)"]

        SYNO --> AGENT
        DOCK --> AGENT
        LIN --> AGENT
        WIN --> AGENT
        WEB --> AGENT
    end

    subgraph WAN["Internet (100 % trafic sortant — WSS 443 / HTTPS)"]
        RELAYS(("Relais Nostr publics<br/>x3 · kind 24242<br/>AES-256-GCM"))
        ALERTS["Alertes<br/>ntfy · Photon iMessage"]
    end

    subgraph PEERS["Pairs de confiance (Ami A / B / C)"]
        PEER_A["MeshWatch Ami A<br/>Rang 0 (immédiat)"]
        PEER_B["MeshWatch Ami B<br/>Rang 1 (fallback 15s)"]
    end

    AGENT ==>|"WSS 443 sortant"| RELAYS
    RELAYS ==> PEER_A
    RELAYS ==> PEER_B
    PEER_A -->|"alert_claim + notif"| ALERTS
    PEER_B -.->|"failover si Rang 0 muet"| ALERTS
```

---

## Fonctionnalités clés

| Capacité | Description |
| :--- | :--- |
| **Zéro port entrant** | 100 % du trafic WAN est sortant (`WSS 443` vers les relais Nostr, `HTTPS` vers `ntfy`/Photon). Aucune règle NAT/pare-feu à ouvrir. |
| **100 % autonome (1 conteneur)** | Interface web embarquée, découverte Docker & LAN, barres d'historique de disponibilité et journal d'incidents intégrés — aucun serveur tiers requis. |
| **Isolation stricte du LAN** | Un pair distant ne peut jamais scanner votre LAN ni exécuter de sonde chez vous : seuls des résumés d'état JSON chiffrés sortent. |
| **Chiffrement E2E & Anti-Rejeu** | Dérivation `HKDF-SHA256`, `AES-256-GCM` (nonce 12 octets), tag de routage `#t` opaque, signatures Schnorr vérifiées, whitelist `peers`, fenêtre `±60s` et déduplication multi-relais. |
| **Auto-Mute (protection coupure fibre)** | Vérifie la connectivité WAN par dial TCP (`1.1.1.1:443`, `9.9.9.9:443`, timeout 3 s) avant toute alerte. Si votre connexion locale tombe, le nœud se met en sourdine (`muted = true`) pour éviter tout faux positif. |
| **Quorum Anti-Alert Storm** | Élection déterministe par ordre lexicographique des `pubkey` en ligne + `alert_claim` sur Nostr : **Rang 0** notifie immédiatement, **Rang 1** attend `15s` en failover, **Rang ≥ 2** attend `30s`. Même logique pour les `RESOLVED`. |
| **Alertes `ntfy` & Photon iMessage** | Formatage clair (nœud, sonde, résumé, horodatage UTC) avec 3 retries exponentiels (`2s`, `5s`, `10s`), support officiel Photon Cloud (`api.photon.codes/v1`) et Photon HTTP Proxy (`imessage-swagger.photon.codes`). |
| **Empreinte minimale** | Binaire Go statique (`CGO_ENABLED=0`), image `gcr.io/distroless/static-debian12:nonroot` de **11,5 Mo**, système de fichiers en lecture seule (`read_only: true`). |

---

## Sondes supportées

Toutes les sondes tournent de manière concurrente sur leur propre `time.Ticker` avec `context.WithTimeout` pour ne jamais bloquer l'envoi des heartbeats :

| Type (`kind`) | Protocole / Source | Ce qui est vérifié |
| :--- | :--- | :--- |
| `synology` | SNMPv2c & SNMPv3 (`gosnmp`) | État système (`.6574.1.1.0`), température (`.6574.1.2.0`, seuil `max_temp_c`), ventilateurs système/alim (`.6574.1.4.1.0`, `.2.0`), walk RAID (`.6574.3.1.1.3`) et walk Disques (`.6574.2.1.1.5`). |
| `proxmox` | REST API Proxmox VE (`/api2/json/cluster/resources`) | Statut des nœuds, CPU (`max_cpu_percent`), RAM (`max_ram_percent`), stockages (`max_disk_percent`, `disks`) et état des VM/LXC critiques (`vms`) via `PVEAPIToken`. |
| `docker` | Unix socket ou `tcp://docker-socket-proxy:2375` | Conteneurs nommés ou filtrés par label (`meshwatch.enable=true`), état `running`, healthcheck `unhealthy` et seuil `max_restarts`. Client HTTP natif léger (sans SDK Docker lourd). |
| `node_exporter` | HTTP `/metrics` (Linux) | % utilisation RAM (`max_ram_percent`) et % occupation des disques réels (`max_disk_percent`, ignore automatiquement `tmpfs`/`overlay`/`proc`…). |
| `windows_exporter` | HTTP `/metrics` (Windows) | % utilisation RAM, % disques logiques (`C:`, etc.) et état temps réel des services Windows configurés (`windows_service_state{state="running"} == 1`). |
| `http` | HTTP / HTTPS | Code de statut attendu (`expected_status`), présence d'un mot-clé (`contains`), latence et expiration du certificat TLS (`tls_min_days`, défaut 14 jours). |
| `tcp` | TCP Dial | Disponibilité d'un port `host:port` et latence de connexion. |
| `snmp_oid` | SNMPv2c & SNMPv3 | Vérification générique d'un OID arbitraire (valeur exacte `expected_value` ou bornes numériques `min_value` / `max_value`). |

---

## Démarrage rapide en 5 étapes

### 1. Cloner le dépôt et générer vos clés

Chaque participant génère sa propre identité Nostr. **Un seul** membre du groupe génère le secret partagé `group_psk_hex` :

```bash
git clone https://github.com/AL1X0/meshkuma.git
cd meshkuma

docker compose build meshwatch
docker compose run --rm meshwatch keygen
```

Sortie exemple :

```yaml
# MeshWatch credentials — keep private_key_hex and group_psk_hex secret!
private_key_hex: "942ee29043fc3c33...b1e430d7995f284e"
pubkey_hex:      "cb134535c48b6b61...04e673b0593f05e"  # À partager avec vos pairs
group_psk_hex:   "cd5fd5391077c946...c5b3a9c0980b538"  # Secret de groupe (partagé hors bande)
topic_tag:       "36901d9e879c59b0"                    # Tag Nostr #t dérivé automatiquement
```

### 2. Échanger les clés entre amis (hors bande)

Partagez via Signal / iMessage / en personne :
1. Le **même** `group_psk_hex` pour tout le groupe.
2. Votre `pubkey_hex` publique (**ne partagez jamais `private_key_hex`**).

### 3. Créer et éditer `config.yaml` (en YAML ou via la console `--ui`)

```bash
cp config.example.yaml config.yaml
chmod 600 config.yaml
```

Complétez [config.example.yaml](config.example.yaml) (ou configurez-le visuellement via `--ui 127.0.0.1:8080`) avec :
- Votre `node.name`, votre `private_key_hex` et le `group_psk_hex` du groupe.
- La liste `peers` avec le nom et la `pubkey_hex` de chaque ami (ou directement en 1 clic via le code d'invitation `MW1-...` dans l'onglet **Mes amis**).
- Vos sondes locales (`probes`) et vos canaux d'alerte (`notifications.ntfy` / `notifications.photon_imessage`).

> **Note sur `/var/run/docker.sock` en mode `nonroot`**  
> Le conteneur tourne en utilisateur non privilégié (`distroless:nonroot`). Si vous utilisez la sonde `docker` sur le socket hôte, décommentez `group_add` dans [docker-compose.yml](docker-compose.yml) avec le GID du groupe `docker` (`stat -c '%g' /var/run/docker.sock`), ou pointez vers un `docker-socket-proxy` en lecture seule (`tcp://docker-socket-proxy:2375`).

### 4. Valider vos notifications avant déploiement

```bash
docker compose run --rm meshwatch test-notify --config /etc/meshwatch/config.yaml
```

Vous devez recevoir immédiatement une notification de test sur `ntfy` et/ou **Photon iMessage**.

### 5. Lancer la stack

```bash
docker compose up -d
docker compose logs -f meshwatch
```

---

## Sécurité & Protocole Nostr

```text
group_psk (32 bytes random)
  ├── HKDF-SHA256(salt="meshwatch-v1-enc", info="meshwatch-v1-aes256gcm") ─► AES-256-GCM Key
  └── hex(SHA256("meshwatch-v1-topic:" || group_psk))[:16]                ─► Nostr #t Tag
```

Chaque événement publié sur les relais publics respecte strictement :

- **Kind** : `24242` (événement éphémère NIP-01/NIP-16, non persisté par les relais).
- **Tags** : `[["t", "<topic_tag>"]]` (aucun nom de groupe ni liste d'amis exposés dans les filtres `REQ`).
- **Content** : `base64(nonce_12_bytes || AES-256-GCM(json_payload))`.
- **Pipeline de validation à la réception** :
  1. Vérification du `kind == 24242`.
  2. Vérification de l'ID SHA-256 et de la signature Schnorr (`ev.CheckID()` + `ev.CheckSignature()`).
  3. Contrôle strict de la whitelist `peers` (`ev.PubKey`).
  4. Fenêtre anti-rejeu `|now - ev.CreatedAt| <= 60s`.
  5. Déduplication par `ev.ID` (cache borné avec TTL).
  6. Déchiffrement authentifié `AES-256-GCM` (rejet silencieux en cas d'échec).

---

## Commandes CLI

| Commande | Description |
| :--- | :--- |
| `meshwatch keygen` | Génère une paire de clés Nostr (`private_key_hex`, `pubkey_hex`), un `group_psk_hex` de 32 octets et affiche le `topic_tag` dérivé. |
| `meshwatch run --config config.yaml` | Démarre le démon de supervision en mode pur CLI (zéro port en écoute). |
| `meshwatch run --config config.yaml --ui 127.0.0.1:8080 [--ui-token SECRET]` | Démarre l'agent avec la **console web locale embarquée** (`//go:embed`, opt-in) et rechargement à chaud (`hot-reload`). |
| `meshwatch test-notify --config config.yaml` | Envoie une alerte de test sur tous les connecteurs activés (`ntfy`, `photon_imessage`). |

---

## Développement & Tests

```bash
# Lancer l'analyse statique et toute la suite de tests avec race detector
go vet ./...
go test -race -count=1 -v ./...

# Compiler le binaire statique
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o meshwatch ./cmd/meshwatch

# Construire et inspecter l'image Docker multi-stage
docker build -t meshwatch:latest .
docker images meshwatch:latest
```

### Structure du dépôt

```text
.
├── assets/
│   ├── banner.svg          # Bannière du dépôt
│   ├── icon.svg            # Icône vectorielle MeshWatch
│   └── screenshots/        # Captures haute définition de la console web locale
├── cmd/meshwatch/          # CLI (run, keygen, test-notify), hot-reload & setup mode
├── internal/
│   ├── config/             # Parsing YAML strict & validation
│   ├── crypto/             # HKDF-SHA256, AES-256-GCM, dérivation #t & keygen
│   ├── transport/          # Pool Nostr multi-relais WSS, reconnexion auto, anti-rejeu, dédup
│   ├── probes/             # Scheduler concurrent, historique intégré + sondes locales
│   ├── quorum/             # Auto-Mute WAN, suivi des pairs, historique, élection (alert_claim)
│   ├── discover/           # Découverte Docker (/var/run/docker.sock) & scanner LAN RFC1918
│   ├── updater/            # Vérification CI/GHCR & mise à jour Docker en 1 clic avec rollback
│   ├── notify/             # Connecteurs ntfy & Photon iMessage (Cloud / Proxy / Webhook)
│   └── webui/              # Interface web locale opt-in (API REST + assets //go:embed)
├── Dockerfile              # Multi-stage golang:1.23-alpine → distroless/static-debian12:nonroot
├── docker-compose.yml      # Conteneur MeshWatch autonome (read_only, no-new-privileges)
├── config.example.yaml     # Exemple complet de configuration
└── SPEC.md                 # Spécification technique détaillée
```

---

## Licence

Distribué sous licence [MIT](LICENSE).
