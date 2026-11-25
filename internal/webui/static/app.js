(() => {
  const PROBE_KINDS = [
    { value: "synology", label: "NAS Synology (SNMP)" },
    { value: "docker", label: "Conteneurs Docker" },
    { value: "node_exporter", label: "Serveur Linux (node_exporter)" },
    { value: "windows_exporter", label: "Serveur Windows (windows_exporter)" },
    { value: "http", label: "Service HTTP / TLS" },
    { value: "tcp", label: "Port TCP" },
    { value: "snmp_oid", label: "OID SNMP générique" }
  ];

  const state = {
    token: sessionStorage.getItem("mw_ui_token") || "",
    activeTab: "overview",
    status: null,
    config: null,
    rawYAML: "",
    yamlEditedDirectly: false,
    configPath: "",
    writable: true,
    dirty: false,
    selectedProbeIndex: 0,
    pollHandle: null
  };

  const $ = (id) => document.getElementById(id);

  function initTheme() {
    const saved = localStorage.getItem("mw_theme");
    const theme = saved === "dark" ? "dark" : "light";
    applyTheme(theme);
    document.querySelectorAll("[data-theme-choice]").forEach((btn) => {
      btn.addEventListener("click", () => {
        applyTheme(btn.dataset.themeChoice);
      });
    });
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("mw_theme", theme);
    document.querySelectorAll("[data-theme-choice]").forEach((btn) => {
      const active = btn.dataset.themeChoice === theme;
      btn.classList.toggle("is-active", active);
      btn.setAttribute("aria-checked", String(active));
    });
    if (state.status) {
      renderTopology(state.status);
    }
  }

  function setDirty(flag) {
    state.dirty = flag;
    const btn = $("save-btn");
    if (btn) {
      btn.classList.toggle("has-dirty", flag);
    }
  }

  function showFeedback(kind, message) {
    const bar = $("feedback-bar");
    bar.className = "feedback-bar";
    if (kind === "ok") bar.classList.add("is-ok");
    if (kind === "err") bar.classList.add("is-err");
    if (kind === "warn") bar.classList.add("is-warn");
    bar.textContent = message;
    bar.hidden = false;
  }

  function clearFeedback() {
    $("feedback-bar").hidden = true;
  }

  async function apiFetch(path, options = {}) {
    const headers = Object.assign({}, options.headers || {});
    if (state.token) {
      headers["Authorization"] = "Bearer " + state.token;
    }
    if (options.body !== undefined && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    const resp = await fetch(path, Object.assign({}, options, { headers }));
    let data = {};
    try {
      data = await resp.json();
    } catch (_) {
      data = {};
    }
    if (resp.status === 401) {
      showAuthGate("Jeton invalide ou expiré.");
      throw new Error("Non authentifié");
    }
    return { ok: resp.ok, status: resp.status, data };
  }

  function showAuthGate(errorMsg) {
    $("auth-gate").hidden = false;
    const errEl = $("auth-error");
    if (errorMsg) {
      errEl.textContent = errorMsg;
      errEl.hidden = false;
    } else {
      errEl.hidden = true;
    }
    $("auth-token-input").focus();
  }

  function hideAuthGate() {
    $("auth-gate").hidden = true;
    $("auth-error").hidden = true;
  }

  function switchTab(tab) {
    state.activeTab = tab;
    document.querySelectorAll(".nav-tab").forEach((btn) => {
      const active = btn.dataset.tab === tab;
      btn.classList.toggle("is-active", active);
      btn.setAttribute("aria-selected", String(active));
    });
    document.querySelectorAll(".view-panel").forEach((panel) => {
      const active = panel.dataset.panel === tab;
      panel.classList.toggle("is-active", active);
      panel.hidden = !active;
    });
    if (tab === "yaml" && !state.yamlEditedDirectly) {
      syncYAMLPreviewFromConfig();
    }
  }

  function escapeHTML(str) {
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function shortKey(hex) {
    if (!hex) return "Non définie";
    if (hex.length <= 16) return hex;
    return hex.slice(0, 8) + "..." + hex.slice(-6);
  }

  function formatDurationSec(sec) {
    const s = Math.max(0, Math.floor(sec || 0));
    if (s < 60) return s + "s";
    const m = Math.floor(s / 60);
    if (m < 60) return m + "m " + (s % 60) + "s";
    const h = Math.floor(m / 60);
    if (h < 24) return h + "h " + (m % 60) + "m";
    const d = Math.floor(h / 24);
    return d + "j " + (h % 24) + "h";
  }

  function formatRelativeTime(iso) {
    if (!iso) return "Jamais vu";
    const diff = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
    if (diff < 5) return "À l'instant";
    if (diff < 60) return "Il y a " + diff + "s";
    if (diff < 3600) return "Il y a " + Math.floor(diff / 60) + " min";
    return "Il y a " + Math.floor(diff / 3600) + "h";
  }

  function probeKindLabel(kind) {
    const match = PROBE_KINDS.find((k) => k.value === kind);
    return match ? match.label : kind;
  }

  /* ---------------- OVERVIEW RENDERING ---------------- */

  function renderStatus(st) {
    state.status = st;

    const setupNotice = $("setup-notice");
    if (st.mode === "setup") {
      setupNotice.hidden = false;
      $("setup-notice-detail").textContent =
        st.setup_error || "Aucune configuration valide détectée. Générez vos clés puis cliquez sur Enregistrer.";
    } else {
      setupNotice.hidden = true;
    }

    $("ov-node-name").textContent = st.node_name || "Nouveau nœud MeshWatch";
    $("ov-subtitle").textContent =
      st.mode === "setup"
        ? "Mode initialisation : configurez votre identité Nostr et vos sondes pour démarrer."
        : "Supervision P2P sur Nostr sans port entrant. Fichier : " + (st.config_path || "mémoire");

    const dot = $("ov-status-dot");
    const statusText = $("ov-status-text");
    dot.className = "status-dot";
    if (st.mode === "setup") {
      dot.classList.add("is-warn");
      statusText.textContent = "Configuration requise";
    } else if (st.muted) {
      dot.classList.add("is-warn");
      statusText.textContent = "Sourdine WAN active";
    } else if (!st.overall_ok) {
      dot.classList.add("is-err");
      statusText.textContent = "Sonde locale en alerte";
    } else {
      dot.classList.add("is-ok");
      statusText.textContent = "Nœud opérationnel";
    }

    const probes = st.probes || [];
    const okProbes = probes.filter((p) => p.ok).length;
    $("metric-probes").textContent = okProbes + " / " + probes.length;
    $("metric-probes-sub").textContent =
      probes.length === 0
        ? "Aucune sonde active"
        : okProbes === probes.length
          ? "Toutes les sondes répondent"
          : (probes.length - okProbes) + " sonde(s) en erreur";

    const peers = st.peers || [];
    const onlinePeers = peers.filter((p) => p.online).length;
    $("metric-peers").textContent = onlinePeers + " / " + peers.length;
    $("metric-peers-sub").textContent =
      peers.length === 0
        ? "Ajoutez la clé publique d'un ami"
        : onlinePeers === peers.length
          ? "Tous les pairs émettent"
          : (peers.length - onlinePeers) + " pair(s) silencieux";

    const relays = st.relays || [];
    const connRelays = relays.filter((r) => r.connected).length;
    $("metric-relays").textContent = connRelays + " / " + relays.length;
    $("metric-topic").textContent = st.topic_tag ? "#t " + st.topic_tag : "Tag #t en attente";

    $("metric-wan").textContent = st.muted ? "Sourdine" : "Joignable";
    $("ov-uptime").textContent = "Disponibilité locale : " + formatDurationSec(st.uptime_sec);

    if (st.pubkey_hex) $("id-pubkey").value = st.pubkey_hex;
    if (st.topic_tag) $("id-topic-tag").value = st.topic_tag;

    renderOverviewProbes(probes);
    renderOverviewPeers(peers);
    renderTopology(st);
  }

  function renderOverviewProbes(probes) {
    const tbody = $("ov-probes-body");
    if (!probes.length) {
      tbody.innerHTML =
        '<tr><td colspan="5" class="empty-row">Aucune sonde configurée. Ouvrez l\'onglet Sondes pour surveiller votre LAN.</td></tr>';
      return;
    }
    tbody.innerHTML = probes
      .map((p) => {
        const stateClass = p.ok ? "is-ok" : "is-err";
        const stateLabel = p.ok ? "Opérationnel" : "En panne";
        const lat = p.latency_ms !== undefined && p.latency_ms !== null ? p.latency_ms + " ms" : "0 ms";
        return (
          "<tr>" +
          '<td class="cell-primary">' + escapeHTML(p.id) + "</td>" +
          "<td>" + escapeHTML(probeKindLabel(p.kind)) + "</td>" +
          '<td><span class="status-cell ' + stateClass + '"><span class="status-dot ' + stateClass + '"></span>' + stateLabel + "</span></td>" +
          "<td>" + escapeHTML(p.summary || "") + "</td>" +
          '<td class="num-col tabular">' + escapeHTML(lat) + "</td>" +
          "</tr>"
        );
      })
      .join("");
  }

  function renderOverviewPeers(peers) {
    const tbody = $("ov-peers-body");
    if (!peers.length) {
      tbody.innerHTML =
        '<tr><td colspan="5" class="empty-row">Aucun pair configuré. Ajoutez vos amis dans l\'onglet Pairs et Kuma.</td></tr>';
      return;
    }
    tbody.innerHTML = peers
      .map((p) => {
        let stateClass = "is-muted";
        let stateLabel = "En attente";
        if (p.timed_out) {
          stateClass = "is-err";
          stateLabel = "Hors ligne";
        } else if (p.online && !p.overall_ok) {
          stateClass = "is-warn";
          stateLabel = "Sonde en alerte";
        } else if (p.online) {
          stateClass = "is-ok";
          stateLabel = "En ligne";
        }

        const failing = (p.probes || []).filter((pr) => !pr.ok);
        const subLine = failing.length
          ? '<span class="cell-secondary">' + escapeHTML(failing.map((f) => f.id + ": " + f.summary).join("; ")) + "</span>"
          : p.node_name && p.node_name !== p.name
            ? '<span class="cell-secondary">' + escapeHTML(p.node_name) + "</span>"
            : "";

        const kumaCell = p.kuma_push_url ? "Push configuré" : "Non configuré";

        return (
          "<tr>" +
          '<td><span class="cell-primary">' + escapeHTML(p.name) + "</span>" + subLine + "</td>" +
          '<td class="mono-inline">' + escapeHTML(shortKey(p.pubkey_hex)) + "</td>" +
          '<td><span class="status-cell ' + stateClass + '"><span class="status-dot ' + stateClass + '"></span>' + stateLabel + "</span></td>" +
          '<td class="tabular">' + escapeHTML(formatRelativeTime(p.last_seen)) + "</td>" +
          "<td>" + escapeHTML(kumaCell) + "</td>" +
          "</tr>"
        );
      })
      .join("");
  }

  function renderTopology(st) {
    const svg = $("topology-svg");
    const cs = getComputedStyle(document.documentElement);
    const cSurface = cs.getPropertyValue("--surface").trim();
    const cSubtle = cs.getPropertyValue("--surface-subtle").trim();
    const cBorder = cs.getPropertyValue("--border-strong").trim();
    const cText = cs.getPropertyValue("--text").trim();
    const cMuted = cs.getPropertyValue("--text-muted").trim();
    const cAccent = cs.getPropertyValue("--accent").trim();
    const cOk = cs.getPropertyValue("--ok").trim();
    const cErr = cs.getPropertyValue("--err").trim();
    const cWarn = cs.getPropertyValue("--warn").trim();

    const relays = st.relays || [];
    const peers = st.peers || [];
    const probes = st.probes || [];
    const okProbes = probes.filter((p) => p.ok).length;
    const connRelays = relays.filter((r) => r.connected).length;

    const peerCount = Math.max(peers.length, 1);
    const viewH = Math.max(250, 72 + peerCount * 68);
    svg.setAttribute("viewBox", "0 0 960 " + viewH);

    const midY = Math.round(viewH / 2);
    const localColor = st.mode === "setup" ? cWarn : st.overall_ok ? cOk : cErr;
    const relayColor = connRelays > 0 ? cAccent : cMuted;

    let out = "";

    // Subtle precision grid
    out += '<g stroke="' + cBorder + '" stroke-opacity="0.22" stroke-width="1">';
    for (let x = 120; x < 960; x += 120) {
      out += '<line x1="' + x + '" y1="0" x2="' + x + '" y2="' + viewH + '"/>';
    }
    out += "</g>";

    // Link: Local node -> Nostr relays
    out +=
      '<path d="M 270 ' + midY + " C 325 " + midY + ", 330 " + midY + ", 375 " + midY +
      '" fill="none" stroke="' + relayColor + '" stroke-width="2.2" ' +
      (connRelays === 0 ? 'stroke-dasharray="5 5"' : "") + "/>";

    // Links + Peer nodes on the right
    const peerStartY = peerCount === 1 ? midY : Math.round((viewH - (peerCount - 1) * 68) / 2);
    if (peers.length === 0) {
      out +=
        '<path d="M 585 ' + midY + " C 635 " + midY + ", 645 " + midY + ", 690 " + midY +
        '" fill="none" stroke="' + cBorder + '" stroke-width="1.8" stroke-dasharray="5 5"/>';
      out +=
        '<g class="topo-node" data-topo-tab="peers">' +
        '<rect x="690" y="' + (midY - 30) + '" width="234" height="60" rx="8" fill="' + cSubtle + '" stroke="' + cBorder + '" stroke-dasharray="4 4" stroke-width="1.3"/>' +
        '<text x="710" y="' + (midY - 4) + '" fill="' + cText + '" font-size="15" font-weight="600">Aucun pair configuré</text>' +
        '<text x="710" y="' + (midY + 15) + '" fill="' + cMuted + '" font-size="13">Cliquer pour ajouter un pair</text>' +
        "</g>";
    } else {
      peers.forEach((peer, i) => {
        const py = peerStartY + i * 68;
        let pColor = cMuted;
        let pState = "En attente";
        if (peer.timed_out) {
          pColor = cErr;
          pState = "Hors ligne";
        } else if (peer.online && !peer.overall_ok) {
          pColor = cWarn;
          pState = "Sonde en alerte";
        } else if (peer.online) {
          pColor = cOk;
          pState = "En ligne";
        }
        out +=
          '<path d="M 585 ' + midY + " C 638 " + midY + ", 638 " + py + ", 690 " + py +
          '" fill="none" stroke="' + pColor + '" stroke-width="2" ' +
          (!peer.online ? 'stroke-dasharray="5 5"' : "") + "/>";
        out +=
          '<g class="topo-node" data-topo-tab="peers">' +
          '<rect x="690" y="' + (py - 26) + '" width="234" height="52" rx="8" fill="' + cSurface + '" stroke="' + cBorder + '" stroke-width="1.4"/>' +
          '<circle cx="710" cy="' + py + '" r="5" fill="' + pColor + '"/>' +
          '<text x="725" y="' + (py - 3) + '" fill="' + cText + '" font-size="15" font-weight="600">' + escapeHTML(peer.name.slice(0, 22)) + "</text>" +
          '<text x="725" y="' + (py + 15) + '" fill="' + cMuted + '" font-size="13">' + escapeHTML(pState) + " · " + escapeHTML((peer.pubkey_hex || "").slice(0, 10)) + "</text>" +
          "</g>";
      });
    }

    // Center hub: Nostr relays
    out +=
      '<g class="topo-node" data-topo-tab="network">' +
      '<rect x="375" y="' + (midY - 46) + '" width="210" height="92" rx="10" fill="' + cSubtle + '" stroke="' + relayColor + '" stroke-width="1.6"/>' +
      '<text x="480" y="' + (midY - 14) + '" text-anchor="middle" fill="' + cText + '" font-size="15" font-weight="700">Relais Nostr WSS</text>' +
      '<text x="480" y="' + (midY + 8) + '" text-anchor="middle" fill="' + cMuted + '" font-size="13">' + connRelays + " sur " + relays.length + " connectés</text>" +
      '<text x="480" y="' + (midY + 28) + '" text-anchor="middle" fill="' + cMuted + '" font-family="JetBrains Mono, monospace" font-size="13">' + escapeHTML(st.topic_tag ? "#t " + st.topic_tag : "AES-256-GCM") + "</text>" +
      "</g>";

    // Left node: Local agent
    out +=
      '<g class="topo-node" data-topo-tab="probes">' +
      '<rect x="36" y="' + (midY - 46) + '" width="234" height="92" rx="10" fill="' + cSurface + '" stroke="' + localColor + '" stroke-width="1.8"/>' +
      '<circle cx="58" cy="' + (midY - 17) + '" r="5.5" fill="' + localColor + '"/>' +
      '<text x="73" y="' + (midY - 12) + '" fill="' + cText + '" font-size="15" font-weight="700">' + escapeHTML((st.node_name || "Nœud local").slice(0, 20)) + "</text>" +
      '<text x="54" y="' + (midY + 10) + '" fill="' + cMuted + '" font-size="13">' + okProbes + " / " + probes.length + " sondes opérationnelles</text>" +
      '<text x="54" y="' + (midY + 30) + '" fill="' + cMuted + '" font-size="13">' + (st.muted ? "Auto-Mute WAN actif" : "Trafic 100 % sortant") + "</text>" +
      "</g>";

    svg.innerHTML = out;
    svg.querySelectorAll("[data-topo-tab]").forEach((node) => {
      node.addEventListener("click", () => switchTab(node.dataset.topoTab));
    });
  }

  /* ---------------- CONFIG FORM RENDERING ---------------- */

  function populateFormsFromConfig() {
    const cfg = state.config;
    if (!cfg) return;

    $("cfg-node-name").value = cfg.node.name || "";
    $("cfg-hb-interval").value = cfg.node.heartbeat_interval || "30s";
    $("cfg-peer-timeout").value = cfg.node.peer_timeout || "90s";
    $("cfg-privkey").value = cfg.node.private_key_hex || "";
    $("cfg-psk").value = cfg.node.group_psk_hex || "";
    if (cfg.node.pubkey_hex) $("id-pubkey").value = cfg.node.pubkey_hex;

    $("cfg-log-level").value = (cfg.logging && cfg.logging.level) || "info";
    $("cfg-log-format").value = (cfg.logging && cfg.logging.format) || "text";

    $("cfg-relays").value = ((cfg.nostr && cfg.nostr.relays) || []).join("\n");
    $("cfg-automute-targets").value = ((cfg.auto_mute && cfg.auto_mute.targets) || []).join("\n");
    $("cfg-automute-timeout").value = (cfg.auto_mute && cfg.auto_mute.timeout) || "3s";

    const ntfy = (cfg.notifications && cfg.notifications.ntfy) || {};
    $("cfg-ntfy-enabled").checked = Boolean(ntfy.enabled);
    $("cfg-ntfy-url").value = ntfy.url || "";
    $("cfg-ntfy-topic").value = ntfy.topic || "";
    $("cfg-ntfy-token").value = ntfy.token || "";

    const photon = (cfg.notifications && cfg.notifications.photon_imessage) || {};
    $("cfg-photon-enabled").checked = Boolean(photon.enabled);
    $("cfg-photon-url").value = photon.url || "";
    $("cfg-photon-recipient").value = photon.recipient || "";
    $("cfg-photon-token").value = photon.token || "";
    $("cfg-photon-rec-field").value = photon.recipient_field || "recipient";
    $("cfg-photon-msg-field").value = photon.message_field || "message";

    if (state.configPath) {
      $("yaml-path-hint").textContent =
        "Fichier cible : " +
        state.configPath +
        (state.writable ? " (écriture directe activée)" : " (lecture seule : rechargement en mémoire et export YAML)");
    }

    renderPeersEditor();
    renderProbesWorkspace();
    $("yaml-editor").value = state.rawYAML || "";
  }

  function readGeneralFieldsIntoConfig() {
    const cfg = state.config;
    if (!cfg) return;
    cfg.node.name = $("cfg-node-name").value.trim();
    cfg.node.heartbeat_interval = $("cfg-hb-interval").value.trim() || "30s";
    cfg.node.peer_timeout = $("cfg-peer-timeout").value.trim() || "90s";
    cfg.node.private_key_hex = $("cfg-privkey").value.trim();
    cfg.node.group_psk_hex = $("cfg-psk").value.trim();

    cfg.logging = {
      level: $("cfg-log-level").value,
      format: $("cfg-log-format").value
    };

    cfg.nostr = {
      relays: $("cfg-relays")
        .value.split("\n")
        .map((s) => s.trim())
        .filter(Boolean)
    };

    cfg.auto_mute = {
      targets: $("cfg-automute-targets")
        .value.split("\n")
        .map((s) => s.trim())
        .filter(Boolean),
      timeout: $("cfg-automute-timeout").value.trim() || "3s"
    };

    cfg.notifications = {
      ntfy: {
        enabled: $("cfg-ntfy-enabled").checked,
        url: $("cfg-ntfy-url").value.trim(),
        topic: $("cfg-ntfy-topic").value.trim(),
        token: $("cfg-ntfy-token").value.trim()
      },
      photon_imessage: {
        enabled: $("cfg-photon-enabled").checked,
        url: $("cfg-photon-url").value.trim(),
        recipient: $("cfg-photon-recipient").value.trim(),
        token: $("cfg-photon-token").value.trim(),
        recipient_field: $("cfg-photon-rec-field").value.trim() || "recipient",
        message_field: $("cfg-photon-msg-field").value.trim() || "message"
      }
    };
  }

  /* ---------------- PEERS EDITOR ---------------- */

  function renderPeersEditor() {
    const peers = (state.config && state.config.peers) || [];
    $("peers-count-label").textContent = peers.length + (peers.length > 1 ? " pairs" : " pair");
    const container = $("peers-list");

    if (!peers.length) {
      container.innerHTML =
        '<div class="editor-empty">Aucun pair ajouté. Cliquez sur Ajouter un pair pour autoriser le homelab d\'un ami.</div>';
      return;
    }

    container.innerHTML = peers
      .map(
        (p, idx) =>
          '<div class="peer-row" data-peer-idx="' + idx + '">' +
          '<label class="field"><span class="field-label">Nom</span>' +
          '<input type="text" data-peer-field="name" value="' + escapeHTML(p.name || "") + '" placeholder="pote-thomas"></label>' +
          '<label class="field"><span class="field-label">Clé publique hex (64 car.)</span>' +
          '<input type="text" class="mono" data-peer-field="pubkey_hex" value="' + escapeHTML(p.pubkey_hex || "") + '" placeholder="a1b2c3..."></label>' +
          '<label class="field"><span class="field-label">URL Push Uptime Kuma (optionnel)</span>' +
          '<input type="url" class="mono" data-peer-field="kuma_push_url" value="' + escapeHTML(p.kuma_push_url || "") + '" placeholder="http://uptime-kuma:3001/api/push/..."></label>' +
          '<button type="button" class="inline-danger" data-remove-peer="' + idx + '">Supprimer</button>' +
          "</div>"
      )
      .join("");

    container.querySelectorAll("[data-peer-field]").forEach((input) => {
      input.addEventListener("input", () => {
        const idx = Number(input.closest("[data-peer-idx]").dataset.peerIdx);
        state.config.peers[idx][input.dataset.peerField] = input.value;
        state.yamlEditedDirectly = false;
        setDirty(true);
      });
    });

    container.querySelectorAll("[data-remove-peer]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const idx = Number(btn.dataset.removePeer);
        state.config.peers.splice(idx, 1);
        state.yamlEditedDirectly = false;
        setDirty(true);
        renderPeersEditor();
      });
    });
  }

  /* ---------------- PROBES EDITOR ---------------- */

  function defaultProbeForKind(kind, count) {
    const base = { id: kind.replace("_", "-") + "-" + (count + 1), kind, interval: "60s", timeout: "10s" };
    switch (kind) {
      case "http":
        return Object.assign(base, { interval: "30s", url: "https://exemple.fr", expected_status: 200, tls_min_days: 14 });
      case "tcp":
        return Object.assign(base, { interval: "30s", host: "192.168.1.10", port: 22 });
      case "docker":
        return Object.assign(base, { interval: "30s", socket: "/var/run/docker.sock", containers: [], label: "meshwatch.enable=true" });
      case "synology":
        return Object.assign(base, { host: "192.168.1.43", port: 161, snmp_version: "2c", community: "public", max_temp_c: 55 });
      case "snmp_oid":
        return Object.assign(base, { host: "192.168.1.50", port: 161, snmp_version: "2c", community: "public", oid: ".1.3.6.1.2.1.1.3.0", expected_value: "1" });
      case "node_exporter":
        return Object.assign(base, { url: "http://192.168.1.10:9100/metrics", max_disk_percent: 90, max_ram_percent: 92 });
      case "windows_exporter":
        return Object.assign(base, { url: "http://192.168.1.15:9182/metrics", services: ["W32Time"], max_disk_percent: 90, max_ram_percent: 92 });
      default:
        return base;
    }
  }

  function renderProbesWorkspace() {
    const probes = (state.config && state.config.probes) || [];
    if (state.selectedProbeIndex >= probes.length) {
      state.selectedProbeIndex = Math.max(0, probes.length - 1);
    }

    const listEl = $("probe-list");
    const editorEl = $("probe-editor");

    if (!probes.length) {
      listEl.innerHTML = '<div class="editor-empty">Aucune sonde configurée.</div>';
      editorEl.innerHTML =
        '<div class="editor-empty">Cliquez sur Ajouter une sonde pour surveiller un NAS Synology, Docker, un serveur Linux/Windows ou un service HTTP/TLS.</div>';
      return;
    }

    listEl.innerHTML = probes
      .map((p, idx) => {
        const selected = idx === state.selectedProbeIndex ? " is-selected" : "";
        return (
          '<button type="button" class="probe-list-item' + selected + '" data-select-probe="' + idx + '">' +
          '<span class="probe-item-id">' + escapeHTML(p.id || "Sonde sans identifiant") + "</span>" +
          '<span class="probe-item-meta">' + escapeHTML(probeKindLabel(p.kind)) + " · " + escapeHTML(p.interval || "60s") + "</span>" +
          "</button>"
        );
      })
      .join("");

    listEl.querySelectorAll("[data-select-probe]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.selectedProbeIndex = Number(btn.dataset.selectProbe);
        renderProbesWorkspace();
      });
    });

    const p = probes[state.selectedProbeIndex];
    editorEl.innerHTML = buildProbeFormHTML(p);
    bindProbeFormEvents(state.selectedProbeIndex);
  }

  function buildProbeFormHTML(p) {
    const kindOptions = PROBE_KINDS.map(
      (k) => '<option value="' + k.value + '"' + (p.kind === k.value ? " selected" : "") + ">" + escapeHTML(k.label) + "</option>"
    ).join("");

    let specific = "";
    switch (p.kind) {
      case "http":
        specific =
          '<label class="field span-2"><span class="field-label">URL à vérifier</span>' +
          '<input type="url" class="mono" data-pf="url" value="' + escapeHTML(p.url || "") + '" placeholder="https://mon-domaine.fr"></label>' +
          '<label class="field"><span class="field-label">Code HTTP attendu</span>' +
          '<input type="number" data-pf="expected_status" data-type="int" value="' + escapeHTML(p.expected_status || 200) + '"></label>' +
          '<label class="field"><span class="field-label">Expiration TLS min. (jours)</span>' +
          '<input type="number" data-pf="tls_min_days" data-type="intptr" value="' + escapeHTML(p.tls_min_days != null ? p.tls_min_days : 14) + '"></label>' +
          '<label class="field"><span class="field-label">Mot-clé attendu (optionnel)</span>' +
          '<input type="text" data-pf="contains" value="' + escapeHTML(p.contains || "") + '" placeholder="OK"></label>' +
          '<div class="field"><span class="field-label">Certificat auto-signé LAN</span>' +
          '<label class="switch-control"><input type="checkbox" data-pf="insecure_skip_verify" data-type="bool"' + (p.insecure_skip_verify ? " checked" : "") + '><span class="switch-track"></span><span class="switch-text">Ignorer la vérification TLS</span></label></div>';
        break;

      case "tcp":
        specific =
          '<label class="field"><span class="field-label">Hôte ou IP</span>' +
          '<input type="text" class="mono" data-pf="host" value="' + escapeHTML(p.host || "") + '" placeholder="192.168.1.10"></label>' +
          '<label class="field"><span class="field-label">Port TCP</span>' +
          '<input type="number" data-pf="port" data-type="int" value="' + escapeHTML(p.port || "") + '" placeholder="22"></label>' +
          '<label class="field"><span class="field-label">Ou adresse hôte:port</span>' +
          '<input type="text" class="mono" data-pf="address" value="' + escapeHTML(p.address || "") + '" placeholder="192.168.1.10:22"></label>';
        break;

      case "docker":
        specific =
          '<label class="field span-2"><span class="field-label">Socket Unix ou proxy TCP</span>' +
          '<input type="text" class="mono" data-pf="socket" value="' + escapeHTML(p.socket || "/var/run/docker.sock") + '" placeholder="/var/run/docker.sock ou tcp://docker-socket-proxy:2375"></label>' +
          '<label class="field"><span class="field-label">Redémarrages max. (0 = illimité)</span>' +
          '<input type="number" data-pf="max_restarts" data-type="int" value="' + escapeHTML(p.max_restarts || 0) + '"></label>' +
          '<label class="field span-2"><span class="field-label">Conteneurs surveillés (séparés par virgule)</span>' +
          '<input type="text" class="mono" data-pf="containers" data-type="csv" value="' + escapeHTML((p.containers || []).join(", ")) + '" placeholder="jellyfin, traefik, homeassistant"></label>' +
          '<label class="field"><span class="field-label">Filtre par label (si liste vide)</span>' +
          '<input type="text" class="mono" data-pf="label" value="' + escapeHTML(p.label || "") + '" placeholder="meshwatch.enable=true"></label>';
        break;

      case "synology":
      case "snmp_oid": {
        const isV3 = p.snmp_version === "3";
        specific =
          '<label class="field"><span class="field-label">Hôte / IP SNMP</span>' +
          '<input type="text" class="mono" data-pf="host" value="' + escapeHTML(p.host || "") + '" placeholder="192.168.1.43"></label>' +
          '<label class="field"><span class="field-label">Port UDP</span>' +
          '<input type="number" data-pf="port" data-type="int" value="' + escapeHTML(p.port || 161) + '"></label>' +
          '<label class="field"><span class="field-label">Version SNMP</span>' +
          '<select data-pf="snmp_version" data-rerender="1"><option value="2c"' + (!isV3 ? " selected" : "") + '>SNMPv2c</option><option value="3"' + (isV3 ? " selected" : "") + ">SNMPv3</option></select></label>";

        if (!isV3) {
          specific +=
            '<label class="field"><span class="field-label">Communauté SNMPv2c</span>' +
            '<input type="text" class="mono" data-pf="community" value="' + escapeHTML(p.community || "public") + '"></label>';
        } else {
          specific +=
            '<label class="field"><span class="field-label">Utilisateur SNMPv3</span>' +
            '<input type="text" class="mono" data-pf="user" value="' + escapeHTML(p.user || "") + '"></label>' +
            '<label class="field"><span class="field-label">Protocole Auth</span>' +
            '<select data-pf="auth_proto">' +
            ["NONE", "MD5", "SHA", "SHA256", "SHA512"]
              .map((a) => '<option value="' + a + '"' + ((p.auth_proto || "SHA256").toUpperCase() === a ? " selected" : "") + ">" + a + "</option>")
              .join("") +
            "</select></label>" +
            '<label class="field"><span class="field-label">Mot de passe Auth</span>' +
            '<input type="password" class="mono" data-pf="auth_pass" value="' + escapeHTML(p.auth_pass || "") + '"></label>' +
            '<label class="field"><span class="field-label">Protocole Priv</span>' +
            '<select data-pf="priv_proto">' +
            ["NONE", "DES", "AES", "AES192", "AES256"]
              .map((pr) => '<option value="' + pr + '"' + ((p.priv_proto || "AES").toUpperCase() === pr ? " selected" : "") + ">" + pr + "</option>")
              .join("") +
            "</select></label>" +
            '<label class="field"><span class="field-label">Mot de passe Priv</span>' +
            '<input type="password" class="mono" data-pf="priv_pass" value="' + escapeHTML(p.priv_pass || "") + '"></label>';
        }

        if (p.kind === "synology") {
          specific +=
            '<label class="field"><span class="field-label">Température maximale (°C)</span>' +
            '<input type="number" data-pf="max_temp_c" data-type="int" value="' + escapeHTML(p.max_temp_c || 60) + '"></label>';
        } else {
          specific +=
            '<label class="field span-2"><span class="field-label">OID à interroger</span>' +
            '<input type="text" class="mono" data-pf="oid" value="' + escapeHTML(p.oid || "") + '" placeholder=".1.3.6.1.2.1.33.1.4.4.1.5.1"></label>' +
            '<label class="field"><span class="field-label">Valeur exacte attendue</span>' +
            '<input type="text" class="mono" data-pf="expected_value" value="' + escapeHTML(p.expected_value || "") + '"></label>' +
            '<label class="field"><span class="field-label">Seuil minimum</span>' +
            '<input type="number" step="any" data-pf="min_value" data-type="floatptr" value="' + escapeHTML(p.min_value != null ? p.min_value : "") + '"></label>' +
            '<label class="field"><span class="field-label">Seuil maximum</span>' +
            '<input type="number" step="any" data-pf="max_value" data-type="floatptr" value="' + escapeHTML(p.max_value != null ? p.max_value : "") + '"></label>';
        }
        break;
      }

      case "node_exporter":
      case "windows_exporter":
        specific =
          '<label class="field span-2"><span class="field-label">URL de l\'endpoint /metrics</span>' +
          '<input type="url" class="mono" data-pf="url" value="' + escapeHTML(p.url || "") + '" placeholder="http://192.168.1.10:9100/metrics"></label>' +
          '<label class="field"><span class="field-label">Seuil RAM max. (%)</span>' +
          '<input type="number" step="any" data-pf="max_ram_percent" data-type="float" value="' + escapeHTML(p.max_ram_percent || "") + '" placeholder="92"></label>' +
          '<label class="field"><span class="field-label">Seuil disque max. (%)</span>' +
          '<input type="number" step="any" data-pf="max_disk_percent" data-type="float" value="' + escapeHTML(p.max_disk_percent || "") + '" placeholder="90"></label>' +
          '<label class="field span-2"><span class="field-label">Points de montage ou volumes (optionnel, virgules)</span>' +
          '<input type="text" class="mono" data-pf="disks" data-type="csv" value="' + escapeHTML((p.disks || []).join(", ")) + '" placeholder="' + (p.kind === "windows_exporter" ? "C:, D:" : "/, /data") + '"></label>';
        if (p.kind === "windows_exporter") {
          specific +=
            '<label class="field span-full"><span class="field-label">Services Windows requis (séparés par virgule)</span>' +
            '<input type="text" class="mono" data-pf="services" data-type="csv" value="' + escapeHTML((p.services || []).join(", ")) + '" placeholder="W32Time, VeeamBackupSvc"></label>';
        }
        break;
    }

    return (
      '<div class="editor-header">' +
      "<h2>" + escapeHTML(p.id || "Nouvelle sonde") + "</h2>" +
      '<button type="button" class="inline-danger" id="delete-probe-btn">Supprimer cette sonde</button>' +
      "</div>" +
      '<div class="form-grid three-col">' +
      '<label class="field"><span class="field-label">Identifiant unique</span>' +
      '<input type="text" class="mono" data-pf="id" value="' + escapeHTML(p.id || "") + '" placeholder="syno-nas"></label>' +
      '<label class="field"><span class="field-label">Type de sonde</span>' +
      '<select data-pf="kind" data-rerender="1">' + kindOptions + "</select></label>" +
      '<label class="field"><span class="field-label">Intervalle</span>' +
      '<input type="text" class="mono" data-pf="interval" value="' + escapeHTML(p.interval || "60s") + '" placeholder="60s"></label>' +
      '<label class="field"><span class="field-label">Timeout par exécution</span>' +
      '<input type="text" class="mono" data-pf="timeout" value="' + escapeHTML(p.timeout || "10s") + '" placeholder="10s"></label>' +
      specific +
      "</div>"
    );
  }

  function bindProbeFormEvents(idx) {
    const editorEl = $("probe-editor");
    editorEl.querySelectorAll("[data-pf]").forEach((el) => {
      const eventName = el.tagName === "SELECT" || el.type === "checkbox" ? "change" : "input";
      el.addEventListener(eventName, () => {
        const probe = state.config.probes[idx];
        const field = el.dataset.pf;
        const type = el.dataset.type || "string";

        if (field === "kind") {
          const prevID = probe.id;
          state.config.probes[idx] = defaultProbeForKind(el.value, idx);
          if (prevID) state.config.probes[idx].id = prevID;
          state.yamlEditedDirectly = false;
          setDirty(true);
          renderProbesWorkspace();
          return;
        }

        if (type === "bool") {
          probe[field] = el.checked;
        } else if (type === "int") {
          probe[field] = el.value === "" ? 0 : parseInt(el.value, 10) || 0;
        } else if (type === "intptr") {
          probe[field] = el.value === "" ? null : parseInt(el.value, 10);
        } else if (type === "float") {
          probe[field] = el.value === "" ? 0 : parseFloat(el.value) || 0;
        } else if (type === "floatptr") {
          probe[field] = el.value === "" ? null : parseFloat(el.value);
        } else if (type === "csv") {
          probe[field] = el.value
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean);
        } else {
          probe[field] = el.value;
        }

        state.yamlEditedDirectly = false;
        setDirty(true);

        if (el.dataset.rerender === "1") {
          renderProbesWorkspace();
        } else if (field === "id" || field === "interval") {
          const item = $("probe-list").querySelector('[data-select-probe="' + idx + '"]');
          if (item) {
            item.querySelector(".probe-item-id").textContent = probe.id || "Sonde sans identifiant";
            item.querySelector(".probe-item-meta").textContent = probeKindLabel(probe.kind) + " · " + (probe.interval || "60s");
          }
          const h2 = editorEl.querySelector(".editor-header h2");
          if (h2 && field === "id") h2.textContent = probe.id || "Nouvelle sonde";
        }
      });
    });

    const delBtn = $("delete-probe-btn");
    if (delBtn) {
      delBtn.addEventListener("click", () => {
        state.config.probes.splice(idx, 1);
        state.yamlEditedDirectly = false;
        setDirty(true);
        renderProbesWorkspace();
      });
    }
  }

  /* ---------------- ACTIONS ---------------- */

  async function syncYAMLPreviewFromConfig() {
    readGeneralFieldsIntoConfig();
    try {
      const { ok, data } = await apiFetch("/api/validate", {
        method: "POST",
        body: JSON.stringify({ config: state.config })
      });
      if (ok && data.yaml) {
        state.rawYAML = data.yaml;
        $("yaml-editor").value = data.yaml;
      }
    } catch (_) {
      // Keep current YAML text if validation fails while editing.
    }
  }

  async function saveConfiguration() {
    clearFeedback();
    const saveBtn = $("save-btn");
    saveBtn.disabled = true;
    saveBtn.textContent = "Enregistrement...";

    try {
      let body;
      if (state.activeTab === "yaml" && state.yamlEditedDirectly) {
        body = JSON.stringify({ yaml: $("yaml-editor").value });
      } else {
        readGeneralFieldsIntoConfig();
        body = JSON.stringify({ config: state.config });
      }

      const { ok, data } = await apiFetch("/api/config", { method: "PUT", body });
      if (!ok) {
        const msg = (data.errors && data.errors.join(" | ")) || data.error || "Configuration invalide";
        showFeedback("err", "Validation refusée : " + msg);
        return;
      }

      state.config = data.config;
      state.rawYAML = data.yaml;
      state.yamlEditedDirectly = false;
      setDirty(false);
      populateFormsFromConfig();

      if (data.persisted) {
        showFeedback("ok", "Configuration enregistrée et agent MeshWatch rechargé.");
      } else {
        showFeedback(
          "warn",
          "Agent rechargé en mémoire, mais le fichier est en lecture seule (" +
            (data.persist_error || "droits insuffisants") +
            "). Téléchargez config.yaml dans l'onglet YAML."
        );
      }
      await fetchStatus();
    } catch (err) {
      showFeedback("err", "Erreur lors de l'enregistrement : " + err.message);
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = "Enregistrer";
    }
  }

  async function validateYAMLDirect() {
    clearFeedback();
    try {
      const { ok, data } = await apiFetch("/api/validate", {
        method: "POST",
        body: JSON.stringify({ yaml: $("yaml-editor").value })
      });
      if (!ok) {
        const msg = (data.errors && data.errors.join(" | ")) || data.error || "YAML invalide";
        showFeedback("err", "Erreurs détectées : " + msg);
        return;
      }
      state.config = data.config;
      state.rawYAML = $("yaml-editor").value;
      populateFormsFromConfig();
      $("yaml-editor").value = state.rawYAML;
      showFeedback("ok", "Configuration YAML valide (pubkey " + shortKey(data.pubkey_hex) + ", tag #" + data.topic_tag + ").");
    } catch (err) {
      showFeedback("err", "Erreur de validation : " + err.message);
    }
  }

  async function runKeygen(goToPeers) {
    clearFeedback();
    try {
      const { ok, data } = await apiFetch("/api/keygen", { method: "POST", body: "{}" });
      if (!ok) {
        showFeedback("err", data.error || "Échec de génération des clés");
        return;
      }
      state.config.node.private_key_hex = data.private_key_hex;
      state.config.node.pubkey_hex = data.pubkey_hex;
      if (!state.config.node.group_psk_hex) {
        state.config.node.group_psk_hex = data.group_psk_hex;
      } else if (confirm("Remplacer aussi la clé secrète de groupe (group_psk_hex) ? Choisissez Annuler pour conserver le PSK de vos amis.")) {
        state.config.node.group_psk_hex = data.group_psk_hex;
      }
      $("cfg-privkey").value = state.config.node.private_key_hex;
      $("cfg-psk").value = state.config.node.group_psk_hex;
      $("id-pubkey").value = data.pubkey_hex;
      $("id-topic-tag").value = data.topic_tag;
      state.yamlEditedDirectly = false;
      setDirty(true);
      if (goToPeers) switchTab("peers");
      showFeedback("ok", "Nouvelles clés générées localement. Cliquez sur Enregistrer pour activer l'agent.");
    } catch (err) {
      showFeedback("err", "Erreur keygen : " + err.message);
    }
  }

  async function runTestNotify() {
    clearFeedback();
    readGeneralFieldsIntoConfig();
    const btn = $("test-notify-btn");
    const out = $("test-notify-output");
    btn.disabled = true;
    btn.textContent = "Envoi en cours...";

    try {
      const { ok, data } = await apiFetch("/api/test-notify", {
        method: "POST",
        body: JSON.stringify({
          node_name: state.config.node.name,
          notifications: state.config.notifications
        })
      });
      if (!ok) {
        showFeedback("err", data.error || "Échec du test de notification");
        out.hidden = true;
        return;
      }
      const rows = (data.results || [])
        .map((r) => {
          const cls = r.ok ? "is-ok" : "is-err";
          const label = r.ok ? "Reçu (" + r.latency_ms + " ms)" : "Échec : " + r.error;
          return (
            '<div class="test-output-line">' +
            '<span class="cell-primary">' + escapeHTML(r.channel) + "</span>" +
            '<span class="status-cell ' + cls + '"><span class="status-dot ' + cls + '"></span>' + escapeHTML(label) + "</span>" +
            "</div>"
          );
        })
        .join("");
      out.innerHTML = rows;
      out.hidden = false;
      showFeedback(data.ok ? "ok" : "err", data.ok ? "Test de notification réussi." : "Au moins un canal a échoué.");
    } catch (err) {
      showFeedback("err", "Erreur test-notify : " + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Tester les notifications";
    }
  }

  async function runCheckWAN() {
    const btn = $("check-wan-btn");
    btn.disabled = true;
    try {
      const { ok, data } = await apiFetch("/api/check-automute", { method: "POST", body: "{}" });
      if (!ok) {
        showFeedback("warn", data.error || "Vérification WAN indisponible en mode initialisation");
        return;
      }
      showFeedback(
        data.muted ? "warn" : "ok",
        data.muted
          ? "Aucune cible WAN joignable : Auto-Mute activé."
          : "Connectivité WAN confirmée (" + (data.targets || []).join(", ") + ")."
      );
      await fetchStatus();
    } catch (err) {
      showFeedback("err", err.message);
    } finally {
      btn.disabled = false;
    }
  }

  /* ---------------- BOOTSTRAP & POLLING ---------------- */

  async function fetchStatus() {
    try {
      const { ok, data } = await apiFetch("/api/status");
      if (ok) renderStatus(data);
    } catch (_) {
      // Handled by apiFetch on 401; ignore transient poll errors during reload.
    }
  }

  async function loadInitialData() {
    const [cfgRes, stRes] = await Promise.all([apiFetch("/api/config"), apiFetch("/api/status")]);
    if (cfgRes.ok) {
      state.config = cfgRes.data.config;
      state.rawYAML = cfgRes.data.yaml || "";
      state.configPath = cfgRes.data.config_path || "";
      state.writable = Boolean(cfgRes.data.writable);
      populateFormsFromConfig();
    }
    if (stRes.ok) {
      renderStatus(stRes.data);
    }
    if (state.pollHandle) clearInterval(state.pollHandle);
    state.pollHandle = setInterval(fetchStatus, 5000);
  }

  function bindGlobalEvents() {
    document.querySelectorAll(".nav-tab").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.tab));
    });
    document.querySelectorAll("[data-goto]").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.goto));
    });

    $("save-btn").addEventListener("click", saveConfiguration);
    $("quick-setup-btn").addEventListener("click", () => runKeygen(true));
    $("keygen-btn").addEventListener("click", () => runKeygen(false));
    $("test-notify-btn").addEventListener("click", runTestNotify);
    $("check-wan-btn").addEventListener("click", runCheckWAN);
    $("validate-yaml-btn").addEventListener("click", validateYAMLDirect);

    $("add-probe-btn").addEventListener("click", () => {
      if (!state.config.probes) state.config.probes = [];
      state.config.probes.push(defaultProbeForKind("http", state.config.probes.length));
      state.selectedProbeIndex = state.config.probes.length - 1;
      state.yamlEditedDirectly = false;
      setDirty(true);
      renderProbesWorkspace();
    });

    $("add-peer-btn").addEventListener("click", () => {
      if (!state.config.peers) state.config.peers = [];
      state.config.peers.push({ name: "", pubkey_hex: "", kuma_push_url: "" });
      state.yamlEditedDirectly = false;
      setDirty(true);
      renderPeersEditor();
    });

    // Mark dirty on general form inputs
    [
      "cfg-node-name",
      "cfg-hb-interval",
      "cfg-peer-timeout",
      "cfg-privkey",
      "cfg-psk",
      "cfg-log-level",
      "cfg-log-format",
      "cfg-relays",
      "cfg-automute-targets",
      "cfg-automute-timeout",
      "cfg-ntfy-enabled",
      "cfg-ntfy-url",
      "cfg-ntfy-topic",
      "cfg-ntfy-token",
      "cfg-photon-enabled",
      "cfg-photon-url",
      "cfg-photon-recipient",
      "cfg-photon-token",
      "cfg-photon-rec-field",
      "cfg-photon-msg-field"
    ].forEach((id) => {
      const el = $(id);
      if (!el) return;
      const evt = el.tagName === "SELECT" || el.type === "checkbox" ? "change" : "input";
      el.addEventListener(evt, () => {
        state.yamlEditedDirectly = false;
        setDirty(true);
      });
    });

    $("yaml-editor").addEventListener("input", () => {
      state.yamlEditedDirectly = true;
      setDirty(true);
    });

    $("sync-from-forms-btn").addEventListener("click", async () => {
      state.yamlEditedDirectly = false;
      await syncYAMLPreviewFromConfig();
      showFeedback("ok", "YAML régénéré depuis les formulaires.");
    });

    $("copy-yaml-btn").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText($("yaml-editor").value);
        showFeedback("ok", "YAML copié dans le presse-papiers.");
      } catch (_) {
        showFeedback("warn", "Impossible de copier automatiquement.");
      }
    });

    $("download-yaml-btn").addEventListener("click", () => {
      const blob = new Blob([$("yaml-editor").value], { type: "text/yaml;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "config.yaml";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    });

    document.querySelectorAll("[data-copy]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const input = $(btn.dataset.copy);
        if (!input || !input.value) return;
        try {
          await navigator.clipboard.writeText(input.value);
          const prev = btn.textContent;
          btn.textContent = "Copié";
          setTimeout(() => {
            btn.textContent = prev;
          }, 1400);
        } catch (_) {}
      });
    });

    document.querySelectorAll("[data-toggle-secret]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const input = $(btn.dataset.toggleSecret);
        if (!input) return;
        const hidden = input.type === "password";
        input.type = hidden ? "text" : "password";
        btn.textContent = hidden ? "Masquer" : "Afficher";
      });
    });

    $("auth-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      state.token = $("auth-token-input").value.trim();
      const check = await fetch("/api/auth/check", {
        headers: state.token ? { Authorization: "Bearer " + state.token } : {}
      }).then((r) => r.json());
      if (check.authenticated) {
        sessionStorage.setItem("mw_ui_token", state.token);
        hideAuthGate();
        await loadInitialData();
      } else {
        showAuthGate("Jeton refusé.");
      }
    });
  }

  async function boot() {
    initTheme();
    bindGlobalEvents();
    try {
      const check = await fetch("/api/auth/check", {
        headers: state.token ? { Authorization: "Bearer " + state.token } : {}
      }).then((r) => r.json());
      if (check.auth_required && !check.authenticated) {
        showAuthGate("");
        return;
      }
      await loadInitialData();
    } catch (err) {
      showFeedback("err", "Impossible de joindre l'agent MeshWatch : " + err.message);
    }
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
