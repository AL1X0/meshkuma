(() => {
  const PROBE_KINDS = [
    { value: "synology", label: "NAS Synology" },
    { value: "docker", label: "Applications Docker" },
    { value: "node_exporter", label: "Serveur Linux" },
    { value: "windows_exporter", label: "Serveur Windows" },
    { value: "http", label: "Site ou application web" },
    { value: "tcp", label: "Port réseau (TCP)" },
    { value: "snmp_oid", label: "Capteur SNMP personnalisé" }
  ];

  const state = {
    token: sessionStorage.getItem("mw_ui_token") || "",
    activeTab: "home",
    activeSubTab: "docker",
    status: null,
    config: null,
    rawYAML: "",
    yamlEditedDirectly: false,
    configPath: "",
    writable: true,
    dirty: false,
    selectedProbeIndex: 0,
    dockerContainers: [],
    dockerSelected: new Set(),
    dockerScannedOnce: false,
    dockerSocket: "/var/run/docker.sock",
    lanItems: [],
    lanScanSummary: "",
    updateInfo: null,
    pollHandle: null
  };

  const $ = (id) => document.getElementById(id);

  function initTheme() {
    const saved = localStorage.getItem("mw_theme");
    const theme = saved === "dark" ? "dark" : "light";
    applyTheme(theme);
    document.querySelectorAll("[data-theme-choice]").forEach((btn) => {
      btn.addEventListener("click", () => applyTheme(btn.dataset.themeChoice));
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
    if (state.status) renderTopology(state.status);
  }

  function setDirty(flag) {
    state.dirty = flag;
    const btn = $("save-btn");
    if (btn) btn.classList.toggle("has-dirty", flag);
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
    if (state.token) headers["Authorization"] = "Bearer " + state.token;
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
      showAuthGate("Code d'accès invalide ou expiré.");
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
    if (tab === "discover" && state.activeSubTab === "docker" && !state.dockerScannedOnce) {
      runDockerScan();
    }
  }

  function switchSubTab(sub) {
    state.activeSubTab = sub;
    document.querySelectorAll(".sub-tab").forEach((btn) => {
      const active = btn.dataset.subtab === sub;
      btn.classList.toggle("is-active", active);
      btn.setAttribute("aria-selected", String(active));
    });
    document.querySelectorAll(".sub-panel").forEach((panel) => {
      const active = panel.dataset.subpanel === sub;
      panel.classList.toggle("is-active", active);
      panel.hidden = !active;
    });
    if (sub === "docker" && !state.dockerScannedOnce) {
      runDockerScan();
    }
    if (sub === "managed") {
      renderProbesWorkspace();
    }
  }

  function escapeHTML(str) {
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function formatDurationSec(sec) {
    const s = Math.max(0, Math.floor(sec || 0));
    if (s < 60) return s + "s";
    const m = Math.floor(s / 60);
    if (m < 60) return m + " min";
    const h = Math.floor(m / 60);
    if (h < 24) return h + "h " + (m % 60) + "m";
    const d = Math.floor(h / 24);
    return d + "j " + (h % 24) + "h";
  }

  function formatRelativeTime(iso) {
    if (!iso) return "Jamais reçu";
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

  /* ---------------- ACCUEIL ---------------- */

  function renderStatus(st) {
    state.status = st;

    const setupNotice = $("setup-notice");
    if (st.mode === "setup") {
      setupNotice.hidden = false;
      $("setup-notice-detail").textContent =
        "Cliquez sur Créer mon identité pour démarrer automatiquement votre supervision privée.";
    } else {
      setupNotice.hidden = true;
    }

    const probes = st.probes || [];
    const okProbes = probes.filter((p) => p.ok).length;
    const failedProbes = probes.length - okProbes;

    const peers = st.peers || [];
    const onlinePeers = peers.filter((p) => p.online).length;

    const relays = st.relays || [];
    const connRelays = relays.filter((r) => r.connected).length;

    if (st.mode === "setup") {
      $("ov-headline").textContent = "Prêt à démarrer";
      $("ov-subtitle").textContent = "Générez votre identité puis scannez vos conteneurs Docker ou votre réseau local.";
    } else if (st.muted) {
      $("ov-headline").textContent = "Connexion Internet interrompue";
      $("ov-subtitle").textContent = "Les alertes sont temporairement mises en sourdine pour éviter tout faux positif.";
    } else if (failedProbes > 0) {
      $("ov-headline").textContent =
        failedProbes === 1 ? "1 service demande votre attention" : failedProbes + " services demandent votre attention";
      $("ov-subtitle").textContent = (st.node_name || "Votre serveur") + " surveille " + probes.length + " service(s) en local.";
    } else if (probes.length === 0) {
      $("ov-headline").textContent = (st.node_name || "Votre maison") + " est connecté";
      $("ov-subtitle").textContent = "Ajoutez vos premiers appareils ou conteneurs Docker dans l'onglet Découvrir.";
    } else {
      $("ov-headline").textContent = "Tout fonctionne sur " + (st.node_name || "votre homelab");
      $("ov-subtitle").textContent = "Vos " + probes.length + " services répondent normalement. Zéro port entrant ouvert.";
    }

    $("metric-probes").textContent = okProbes + " / " + probes.length;
    $("metric-probes-sub").textContent =
      probes.length === 0
        ? "Cliquez sur Ajouter un appareil"
        : failedProbes === 0
          ? "Tous les services répondent"
          : failedProbes + " problème(s) détecté(s)";

    $("metric-peers").textContent = onlinePeers + " / " + peers.length;
    $("metric-peers-sub").textContent =
      peers.length === 0
        ? "Ajoutez un ami pour vous entraider"
        : onlinePeers === peers.length
          ? "Tous vos amis sont en ligne"
          : (peers.length - onlinePeers) + " ami(s) silencieux";

    $("metric-relays").textContent = connRelays + " / " + relays.length;
    $("metric-relays-sub").textContent = connRelays > 0 ? "Échanges chiffrés actifs" : "Reconnexion en cours";

    $("metric-wan").textContent = st.muted ? "Coupée" : "Connectée";
    $("ov-uptime").textContent = "En marche depuis " + formatDurationSec(st.uptime_sec);

    if (st.pubkey_hex) $("id-pubkey").value = st.pubkey_hex;
    if (st.topic_tag) $("id-topic-tag").value = st.topic_tag;
    if (st.version) {
      $("settings-version-label").textContent = st.version + (st.commit ? " (" + st.commit + ")" : "");
    }

    renderHomeProbes(probes);
    renderHomePeers(peers);
    renderTopology(st);
  }

  function renderHomeProbes(probes) {
    const tbody = $("ov-probes-body");
    if (!probes.length) {
      tbody.innerHTML =
        '<tr><td colspan="5" class="empty-row">Aucun service surveillé pour le moment. Ouvrez Découvrir pour scanner Docker ou votre réseau en un clic.</td></tr>';
      return;
    }
    tbody.innerHTML = probes
      .map((p) => {
        const cls = p.ok ? "is-ok" : "is-err";
        const label = p.ok ? "Tout va bien" : "En panne";
        const lat = p.latency_ms != null ? p.latency_ms + " ms" : "0 ms";
        return (
          "<tr>" +
          '<td class="cell-primary">' + escapeHTML(p.id) + "</td>" +
          "<td>" + escapeHTML(probeKindLabel(p.kind)) + "</td>" +
          '<td><span class="status-cell ' + cls + '"><span class="status-dot ' + cls + '"></span>' + label + "</span></td>" +
          "<td>" + escapeHTML(p.summary || "") + "</td>" +
          '<td class="num-col tabular">' + escapeHTML(lat) + "</td>" +
          "</tr>"
        );
      })
      .join("");
  }

  function renderHomePeers(peers) {
    const tbody = $("ov-peers-body");
    if (!peers.length) {
      tbody.innerHTML =
        '<tr><td colspan="4" class="empty-row">Aucun ami ajouté. Rendez-vous dans Mes amis pour partager votre code et vous surveiller mutuellement.</td></tr>';
      return;
    }
    tbody.innerHTML = peers
      .map((p) => {
        let cls = "is-muted";
        let label = "En attente";
        if (p.timed_out) {
          cls = "is-err";
          label = "Injoignable";
        } else if (p.online && !p.overall_ok) {
          cls = "is-warn";
          label = "Un service en alerte";
        } else if (p.online) {
          cls = "is-ok";
          label = "Tout va bien";
        }

        const failing = (p.probes || []).filter((pr) => !pr.ok);
        const subLine = failing.length
          ? '<span class="cell-secondary">' + escapeHTML(failing.map((f) => f.id + ": " + f.summary).join("; ")) + "</span>"
          : "";

        return (
          "<tr>" +
          '<td><span class="cell-primary">' + escapeHTML(p.name) + "</span>" + subLine + "</td>" +
          '<td><span class="status-cell ' + cls + '"><span class="status-dot ' + cls + '"></span>' + label + "</span></td>" +
          '<td class="tabular">' + escapeHTML(formatRelativeTime(p.last_seen)) + "</td>" +
          "<td>" + (p.kuma_push_url ? "Synchronisé" : "Non lié") + "</td>" +
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
    const viewH = Math.max(240, 70 + peerCount * 68);
    svg.setAttribute("viewBox", "0 0 960 " + viewH);

    const midY = Math.round(viewH / 2);
    const localColor = st.mode === "setup" ? cWarn : st.overall_ok ? cOk : cErr;
    const relayColor = connRelays > 0 ? cAccent : cMuted;

    let out = "";
    out += '<g stroke="' + cBorder + '" stroke-opacity="0.2" stroke-width="1">';
    for (let x = 120; x < 960; x += 120) {
      out += '<line x1="' + x + '" y1="0" x2="' + x + '" y2="' + viewH + '"/>';
    }
    out += "</g>";

    out +=
      '<path d="M 272 ' + midY + " C 325 " + midY + ", 330 " + midY + ", 375 " + midY +
      '" fill="none" stroke="' + relayColor + '" stroke-width="2.2" ' +
      (connRelays === 0 ? 'stroke-dasharray="5 5"' : "") + "/>";

    const peerStartY = peerCount === 1 ? midY : Math.round((viewH - (peerCount - 1) * 68) / 2);
    if (peers.length === 0) {
      out +=
        '<path d="M 585 ' + midY + " C 635 " + midY + ", 645 " + midY + ", 690 " + midY +
        '" fill="none" stroke="' + cBorder + '" stroke-width="1.8" stroke-dasharray="5 5"/>';
      out +=
        '<g class="topo-node" data-topo-tab="friends">' +
        '<rect x="690" y="' + (midY - 30) + '" width="234" height="60" rx="10" fill="' + cSubtle + '" stroke="' + cBorder + '" stroke-dasharray="4 4" stroke-width="1.3"/>' +
        '<text x="710" y="' + (midY - 4) + '" fill="' + cText + '" font-size="15" font-weight="600">Inviter un ami</text>' +
        '<text x="710" y="' + (midY + 16) + '" fill="' + cMuted + '" font-size="13">Cliquer pour ajouter un proche</text>' +
        "</g>";
    } else {
      peers.forEach((peer, i) => {
        const py = peerStartY + i * 68;
        let pColor = cMuted;
        let pState = "En attente";
        if (peer.timed_out) {
          pColor = cErr;
          pState = "Injoignable";
        } else if (peer.online && !peer.overall_ok) {
          pColor = cWarn;
          pState = "Alerte détectée";
        } else if (peer.online) {
          pColor = cOk;
          pState = "Tout va bien";
        }
        out +=
          '<path d="M 585 ' + midY + " C 638 " + midY + ", 638 " + py + ", 690 " + py +
          '" fill="none" stroke="' + pColor + '" stroke-width="2" ' +
          (!peer.online ? 'stroke-dasharray="5 5"' : "") + "/>";
        out +=
          '<g class="topo-node" data-topo-tab="friends">' +
          '<rect x="690" y="' + (py - 26) + '" width="234" height="52" rx="10" fill="' + cSurface + '" stroke="' + cBorder + '" stroke-width="1.4"/>' +
          '<circle cx="710" cy="' + py + '" r="5" fill="' + pColor + '"/>' +
          '<text x="725" y="' + (py - 3) + '" fill="' + cText + '" font-size="15" font-weight="600">' + escapeHTML(peer.name.slice(0, 22)) + "</text>" +
          '<text x="725" y="' + (py + 15) + '" fill="' + cMuted + '" font-size="13">' + escapeHTML(pState) + "</text>" +
          "</g>";
      });
    }

    out +=
      '<g class="topo-node" data-topo-tab="settings">' +
      '<rect x="375" y="' + (midY - 44) + '" width="210" height="88" rx="10" fill="' + cSubtle + '" stroke="' + relayColor + '" stroke-width="1.6"/>' +
      '<text x="480" y="' + (midY - 12) + '" text-anchor="middle" fill="' + cText + '" font-size="15" font-weight="700">Relais chiffrés</text>' +
      '<text x="480" y="' + (midY + 10) + '" text-anchor="middle" fill="' + cMuted + '" font-size="13">' + connRelays + " sur " + relays.length + " connectés</text>" +
      '<text x="480" y="' + (midY + 29) + '" text-anchor="middle" fill="' + cMuted + '" font-size="13">Chiffrement privé E2E</text>' +
      "</g>";

    out +=
      '<g class="topo-node" data-topo-tab="discover">' +
      '<rect x="36" y="' + (midY - 44) + '" width="236" height="88" rx="10" fill="' + cSurface + '" stroke="' + localColor + '" stroke-width="1.8"/>' +
      '<circle cx="58" cy="' + (midY - 15) + '" r="5.5" fill="' + localColor + '"/>' +
      '<text x="73" y="' + (midY - 10) + '" fill="' + cText + '" font-size="15" font-weight="700">' + escapeHTML((st.node_name || "Chez vous").slice(0, 20)) + "</text>" +
      '<text x="54" y="' + (midY + 12) + '" fill="' + cMuted + '" font-size="13">' + okProbes + " / " + probes.length + " services actifs</text>" +
      '<text x="54" y="' + (midY + 31) + '" fill="' + cMuted + '" font-size="13">' + (st.muted ? "Connexion WAN coupée" : "Aucun port entrant") + "</text>" +
      "</g>";

    svg.innerHTML = out;
    svg.querySelectorAll("[data-topo-tab]").forEach((node) => {
      node.addEventListener("click", () => switchTab(node.dataset.topoTab));
    });
  }

  /* ---------------- DÉCOUVRIR : DOCKER & LAN ---------------- */

  async function loadDiscoverInfo() {
    try {
      const { ok, data } = await apiFetch("/api/discover/info");
      if (ok) {
        if (data.default_subnet && !$("lan-subnet-input").value) {
          $("lan-subnet-input").value = data.default_subnet;
        }
        if (data.docker_socket) state.dockerSocket = data.docker_socket;
      }
    } catch (_) {}
  }

  async function runDockerScan() {
    const btn = $("scan-docker-btn");
    const meta = $("docker-scan-meta");
    btn.disabled = true;
    meta.textContent = "Scan des conteneurs Docker en cours...";
    try {
      const { ok, data } = await apiFetch("/api/discover/docker", {
        method: "POST",
        body: JSON.stringify({ socket: state.dockerSocket })
      });
      if (!ok) {
        meta.textContent = "Impossible de lire Docker : " + (data.error || "socket inaccessible");
        $("docker-containers-list").innerHTML =
          '<div class="editor-empty">Vérifiez que /var/run/docker.sock est monté avec les droits de lecture (group_add dans Docker Compose).</div>';
        return;
      }
      state.dockerScannedOnce = true;
      state.dockerContainers = data.containers || [];
      state.dockerSelected = new Set(
        state.dockerContainers.filter((c) => c.monitored).map((c) => c.name)
      );
      const runningCount = state.dockerContainers.filter((c) => c.running).length;
      meta.textContent =
        state.dockerContainers.length +
        " conteneur(s) trouvé(s) sur cette machine (" +
        runningCount +
        " actif(s), " +
        state.dockerSelected.size +
        " sélectionné(s)).";
      renderDockerContainers();
    } catch (err) {
      meta.textContent = "Erreur lors du scan Docker : " + err.message;
    } finally {
      btn.disabled = false;
    }
  }

  function renderDockerContainers() {
    const query = ($("docker-filter-input").value || "").trim().toLowerCase();
    const list = $("docker-containers-list");
    const filtered = state.dockerContainers.filter(
      (c) => !query || c.name.toLowerCase().includes(query) || (c.image || "").toLowerCase().includes(query)
    );

    if (!filtered.length) {
      list.innerHTML = '<div class="editor-empty">Aucun conteneur ne correspond à votre recherche.</div>';
      return;
    }

    list.innerHTML = filtered
      .map((c) => {
        const checked = state.dockerSelected.has(c.name) ? " checked" : "";
        let cls = "is-muted";
        let stateLabel = "Arrêté";
        if (c.running && c.health === "unhealthy") {
          cls = "is-err";
          stateLabel = "En erreur";
        } else if (c.running) {
          cls = "is-ok";
          stateLabel = c.health === "healthy" ? "Actif (sain)" : "Actif";
        }
        const portsStr = c.ports && c.ports.length ? " · ports " + c.ports.slice(0, 4).join(", ") : "";
        return (
          '<div class="discover-row">' +
          '<div class="discover-main">' +
          '<div class="discover-title">' + escapeHTML(c.name) + "</div>" +
          '<div class="discover-sub">' + escapeHTML(c.image || "") + escapeHTML(portsStr) + "</div>" +
          "</div>" +
          '<div class="discover-right">' +
          '<span class="status-cell ' + cls + '"><span class="status-dot ' + cls + '"></span>' + stateLabel + "</span>" +
          '<label class="switch-control">' +
          '<input type="checkbox" data-docker-toggle="' + escapeHTML(c.name) + '"' + checked + ">" +
          '<span class="switch-track"></span>' +
          '<span class="switch-text">Surveiller</span>' +
          "</label>" +
          "</div>" +
          "</div>"
        );
      })
      .join("");

    list.querySelectorAll("[data-docker-toggle]").forEach((cb) => {
      cb.addEventListener("change", () => {
        const name = cb.dataset.dockerToggle;
        if (cb.checked) state.dockerSelected.add(name);
        else state.dockerSelected.delete(name);
        updateApplyDockerButton();
      });
    });
    updateApplyDockerButton();
  }

  function updateApplyDockerButton() {
    const count = state.dockerSelected.size;
    $("apply-docker-btn").textContent = "Appliquer (" + count + ")";
  }

  async function applyDockerSelection() {
    const selected = Array.from(state.dockerSelected).sort();
    if (!state.config.probes) state.config.probes = [];

    let idx = state.config.probes.findIndex((p) => p.kind === "docker");
    if (selected.length === 0) {
      if (idx >= 0) state.config.probes.splice(idx, 1);
    } else if (idx >= 0) {
      state.config.probes[idx].containers = selected;
      state.config.probes[idx].label = "";
      if (!state.config.probes[idx].socket) state.config.probes[idx].socket = state.dockerSocket;
    } else {
      state.config.probes.push({
        id: "docker-local",
        kind: "docker",
        interval: "30s",
        timeout: "10s",
        socket: state.dockerSocket,
        containers: selected
      });
    }

    state.yamlEditedDirectly = false;
    await saveConfiguration("Surveillance Docker mise à jour (" + selected.length + " conteneur(s)).");
    state.dockerContainers.forEach((c) => {
      c.monitored = state.dockerSelected.has(c.name);
    });
  }

  async function runLANScan() {
    const btn = $("scan-lan-btn");
    const meta = $("lan-scan-meta");
    const subnet = ($("lan-subnet-input").value || "").trim() || "192.168.1.0/24";
    btn.disabled = true;
    btn.textContent = "Scan en cours...";
    meta.textContent = "Recherche des NAS Synology, serveurs et applications web sur " + subnet + " (quelques secondes)...";

    try {
      const { ok, data } = await apiFetch("/api/discover/lan", {
        method: "POST",
        body: JSON.stringify({ subnet })
      });
      if (!ok) {
        meta.textContent = "Scan impossible : " + (data.error || "plage invalide");
        return;
      }
      state.lanItems = data.items || [];
      const sec = ((data.duration_ms || 0) / 1000).toFixed(1);
      state.lanScanSummary =
        state.lanItems.length +
        " service(s) détecté(s) sur " +
        data.subnet +
        " (" +
        data.scanned_ips +
        " adresses vérifiées en " +
        sec +
        "s).";
      meta.textContent = state.lanScanSummary;
      renderLANResults();
    } catch (err) {
      meta.textContent = "Erreur lors du scan réseau : " + err.message;
    } finally {
      btn.disabled = false;
      btn.textContent = "Scanner mon réseau";
    }
  }

  function renderLANResults() {
    const list = $("lan-results-list");
    const meta = $("lan-scan-meta");
    if (!state.lanItems.length) {
      if (state.lanScanSummary) {
        list.innerHTML =
          '<div class="editor-empty">Aucun appareil détecté sur cette plage. Vérifiez le sous-réseau (ex. 192.168.1.0/24 ou 192.168.0.0/24).</div>';
      }
      return;
    }

    const query = ($("lan-filter-input").value || "").trim().toLowerCase();
    const filtered = state.lanItems
      .map((item, idx) => ({ item, idx }))
      .filter(({ item }) => {
        if (!query) return true;
        const haystack = [
          item.name,
          item.ip,
          item.category,
          item.category_label,
          item.summary,
          item.port != null ? String(item.port) : "",
          item.suggested_probe && item.suggested_probe.url ? item.suggested_probe.url : ""
        ]
          .join(" ")
          .toLowerCase();
        return haystack.includes(query);
      });

    if (state.lanScanSummary) {
      meta.textContent = query
        ? filtered.length + " sur " + state.lanItems.length + " service(s) affiché(s) · " + state.lanScanSummary
        : state.lanScanSummary;
    }

    if (!filtered.length) {
      list.innerHTML = '<div class="editor-empty">Aucun appareil ne correspond à votre recherche.</div>';
      return;
    }

    list.innerHTML = filtered
      .map(({ item, idx }) => {
        const actionHTML = item.already_monitored
          ? '<span class="status-cell is-ok"><span class="status-dot is-ok"></span>Déjà surveillé</span>'
          : '<button type="button" class="btn-primary" data-add-discovered="' + idx + '">Surveiller</button>';
        return (
          '<div class="discover-row">' +
          '<div class="discover-main">' +
          '<div class="discover-title">' + escapeHTML(item.name) + ' <span class="mono-inline">' + escapeHTML(item.ip) + "</span></div>" +
          '<div class="discover-sub">' + escapeHTML(item.category_label) + " · " + escapeHTML(item.summary) + "</div>" +
          "</div>" +
          '<div class="discover-right">' + actionHTML + "</div>" +
          "</div>"
        );
      })
      .join("");

    list.querySelectorAll("[data-add-discovered]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const idx = Number(btn.dataset.addDiscovered);
        const item = state.lanItems[idx];
        if (!item) return;
        btn.disabled = true;
        btn.textContent = "Ajout...";

        if (!state.config.probes) state.config.probes = [];
        const probe = Object.assign({}, item.suggested_probe);
        // Ensure unique probe ID
        const existingIDs = new Set(state.config.probes.map((p) => p.id));
        let candidate = probe.id || "service";
        let n = 2;
        while (existingIDs.has(candidate)) {
          candidate = probe.id + "-" + n;
          n++;
        }
        probe.id = candidate;

        state.config.probes.push(probe);
        state.yamlEditedDirectly = false;
        const ok = await saveConfiguration(item.name + " a été ajouté à votre surveillance.");
        if (ok) {
          item.already_monitored = true;
          renderLANResults();
        } else {
          state.config.probes.pop();
          btn.disabled = false;
          btn.textContent = "Surveiller";
        }
      });
    });
  }

  /* ---------------- UPDATES ---------------- */

  async function checkUpdates(force) {
    const btn = $("check-update-btn");
    if (btn && force) {
      btn.disabled = true;
      btn.textContent = "Vérification...";
    }
    try {
      const { ok, data } = await apiFetch("/api/update/check" + (force ? "?force=1" : ""));
      if (!ok) {
        $("settings-update-headline").textContent = "Vérification indisponible pour le moment";
        $("settings-update-detail").textContent = data.error || "Impossible de joindre GitHub.";
        $("settings-update-btn").hidden = true;
        return;
      }
      state.updateInfo = data;
      renderUpdateState(data);
    } catch (_) {
    } finally {
      if (btn && force) {
        btn.disabled = false;
        btn.textContent = "Vérifier les mises à jour";
      }
    }
  }

  function renderUpdateState(info) {
    $("settings-version-label").textContent =
      (info.current_version || "dev") + (info.current_commit ? " (" + info.current_commit + ")" : "");

    const banner = $("update-banner");
    const settingsBtn = $("settings-update-btn");

    if (info.update_available) {
      banner.hidden = false;
      $("update-banner-title").textContent = "Nouvelle version disponible : " + info.latest_version;
      $("update-banner-desc").textContent =
        info.release_name || "Des améliorations et correctifs sont prêts à être installés.";
      $("update-now-btn").textContent = info.can_auto_update ? "Mettre à jour maintenant" : "Voir la mise à jour";

      $("settings-update-headline").textContent = "Version " + info.latest_version + " disponible";
      $("settings-update-detail").textContent = info.can_auto_update
        ? "Cliquez sur Mettre à jour maintenant pour télécharger l'image " + info.image + " et redémarrer automatiquement."
        : "Mise à jour manuelle requise : docker compose pull && docker compose up -d";
      settingsBtn.hidden = false;
      settingsBtn.textContent = info.can_auto_update ? "Mettre à jour maintenant" : "Ouvrir sur GitHub";
    } else {
      banner.hidden = true;
      $("settings-update-headline").textContent = "Votre MeshWatch est à jour";
      $("settings-update-detail").textContent =
        "Dernière version publiée : " + (info.latest_version || info.current_version) + ".";
      settingsBtn.hidden = true;
    }
  }

  async function triggerUpdate() {
    const info = state.updateInfo;
    if (!info) return;
    if (!info.can_auto_update) {
      if (info.release_url) window.open(info.release_url, "_blank", "noopener");
      showFeedback("warn", "Exécutez sur l'hôte : docker compose pull && docker compose up -d");
      return;
    }

    if (!confirm("Télécharger " + info.latest_version + " et redémarrer MeshWatch maintenant ?")) {
      return;
    }

    $("updating-overlay").hidden = false;
    $("updating-message").textContent =
      "Téléchargement de " + info.image + " et redémarrage automatique du conteneur. Ne fermez pas cet onglet...";

    try {
      const { ok, data } = await apiFetch("/api/update/apply", {
        method: "POST",
        body: JSON.stringify({ image: info.image })
      });
      if (!ok) {
        $("updating-overlay").hidden = true;
        showFeedback("err", "Mise à jour échouée : " + (data.error || "erreur Docker"));
        return;
      }

      // Poll until the restarted updated container comes back online.
      const prevVersion = info.current_version + ":" + info.current_commit;
      const started = Date.now();
      const pollReconnect = async () => {
        if (Date.now() - started > 120000) {
          $("updating-overlay").hidden = true;
          showFeedback("warn", "Le redémarrage prend plus de temps que prévu. Actualisez la page.");
          return;
        }
        try {
          const r = await apiFetch("/api/status");
          if (r.ok) {
            const cur = (r.data.version || "") + ":" + (r.data.commit || "");
            if (cur !== prevVersion || Date.now() - started > 6000) {
              window.location.reload();
              return;
            }
          }
        } catch (_) {}
        setTimeout(pollReconnect, 1800);
      };
      setTimeout(pollReconnect, 2500);
    } catch (err) {
      $("updating-overlay").hidden = true;
      showFeedback("err", "Erreur de mise à jour : " + err.message);
    }
  }

  /* ---------------- CONFIG FORMS ---------------- */

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
        "Fichier : " + state.configPath + (state.writable ? " (sauvegarde directe active)" : " (lecture seule)");
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
      relays: $("cfg-relays").value.split("\n").map((s) => s.trim()).filter(Boolean)
    };
    cfg.auto_mute = {
      targets: $("cfg-automute-targets").value.split("\n").map((s) => s.trim()).filter(Boolean),
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

  /* ---------------- AMIS ---------------- */

  function renderPeersEditor() {
    const peers = (state.config && state.config.peers) || [];
    $("peers-count-label").textContent = peers.length + (peers.length > 1 ? " amis" : " ami");
    const container = $("peers-list");

    if (!peers.length) {
      container.innerHTML =
        '<div class="editor-empty">Vous n\'avez pas encore ajouté d\'ami. Cliquez sur Ajouter un ami pour coller son code d\'invitation.</div>';
      return;
    }

    container.innerHTML = peers
      .map(
        (p, idx) =>
          '<div class="peer-row" data-peer-idx="' + idx + '">' +
          '<label class="field"><span class="field-label">Prénom ou surnom</span>' +
          '<input type="text" data-peer-field="name" value="' + escapeHTML(p.name || "") + '" placeholder="Homelab Nord"></label>' +
          '<label class="field"><span class="field-label">Code ami (clé publique)</span>' +
          '<input type="text" class="mono" data-peer-field="pubkey_hex" value="' + escapeHTML(p.pubkey_hex || "") + '" placeholder="Collez son code ami"></label>' +
          '<label class="field"><span class="field-label">Lien Push Uptime Kuma (optionnel)</span>' +
          '<input type="url" class="mono" data-peer-field="kuma_push_url" value="' + escapeHTML(p.kuma_push_url || "") + '" placeholder="http://uptime-kuma:3001/api/push/..."></label>' +
          '<button type="button" class="inline-danger" data-remove-peer="' + idx + '">Retirer</button>' +
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
        state.config.peers.splice(Number(btn.dataset.removePeer), 1);
        state.yamlEditedDirectly = false;
        setDirty(true);
        renderPeersEditor();
      });
    });
  }

  /* ---------------- SONDES MANUELLES SIMPLIFIÉES ---------------- */

  function defaultProbeForKind(kind, count) {
    const base = { id: kind.replace("_", "-") + "-" + (count + 1), kind, interval: "60s", timeout: "10s" };
    switch (kind) {
      case "http":
        return Object.assign(base, { interval: "30s", url: "https://", expected_status: 200, tls_min_days: 14 });
      case "tcp":
        return Object.assign(base, { interval: "30s", host: "192.168.1.10", port: 22 });
      case "docker":
        return Object.assign(base, { interval: "30s", socket: state.dockerSocket, containers: [] });
      case "synology":
        return Object.assign(base, { host: "192.168.1.20", port: 161, snmp_version: "2c", community: "public", max_temp_c: 55 });
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
      listEl.innerHTML = '<div class="editor-empty">Aucun service configuré.</div>';
      editorEl.innerHTML =
        '<div class="editor-empty">Utilisez Docker local ou Réseau local pour ajouter des appareils en un clic, ou choisissez un type ci-dessus.</div>';
      return;
    }

    listEl.innerHTML = probes
      .map((p, idx) => {
        const sel = idx === state.selectedProbeIndex ? " is-selected" : "";
        return (
          '<button type="button" class="probe-list-item' + sel + '" data-select-probe="' + idx + '">' +
          '<span class="probe-item-id">' + escapeHTML(p.id || "Service sans nom") + "</span>" +
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

    editorEl.innerHTML = buildProbeFormHTML(probes[state.selectedProbeIndex]);
    bindProbeFormEvents(state.selectedProbeIndex);
  }

  function buildProbeFormHTML(p) {
    const kindOptions = PROBE_KINDS.map(
      (k) => '<option value="' + k.value + '"' + (p.kind === k.value ? " selected" : "") + ">" + escapeHTML(k.label) + "</option>"
    ).join("");

    let simpleFields = "";
    let advancedFields = "";

    switch (p.kind) {
      case "http":
        simpleFields =
          '<label class="field span-2"><span class="field-label">Adresse web (URL)</span>' +
          '<input type="url" class="mono" data-pf="url" value="' + escapeHTML(p.url || "") + '" placeholder="https://mon-service.fr"></label>';
        advancedFields =
          '<label class="field"><span class="field-label">Code HTTP attendu</span>' +
          '<input type="number" data-pf="expected_status" data-type="int" value="' + escapeHTML(p.expected_status || 200) + '"></label>' +
          '<label class="field"><span class="field-label">Alerte certificat TLS (jours min.)</span>' +
          '<input type="number" data-pf="tls_min_days" data-type="intptr" value="' + escapeHTML(p.tls_min_days != null ? p.tls_min_days : 14) + '"></label>' +
          '<label class="field"><span class="field-label">Mot-clé attendu dans la page</span>' +
          '<input type="text" data-pf="contains" value="' + escapeHTML(p.contains || "") + '" placeholder="Optionnel"></label>' +
          '<div class="field"><span class="field-label">Certificat auto-signé local</span>' +
          '<label class="switch-control"><input type="checkbox" data-pf="insecure_skip_verify" data-type="bool"' + (p.insecure_skip_verify ? " checked" : "") + '><span class="switch-track"></span><span class="switch-text">Accepter auto-signé</span></label></div>';
        break;

      case "tcp":
        simpleFields =
          '<label class="field"><span class="field-label">Adresse IP ou nom</span>' +
          '<input type="text" class="mono" data-pf="host" value="' + escapeHTML(p.host || "") + '" placeholder="192.168.1.10"></label>' +
          '<label class="field"><span class="field-label">Port</span>' +
          '<input type="number" data-pf="port" data-type="int" value="' + escapeHTML(p.port || 22) + '"></label>';
        break;

      case "docker":
        simpleFields =
          '<label class="field span-2"><span class="field-label">Conteneurs surveillés (virgules)</span>' +
          '<input type="text" class="mono" data-pf="containers" data-type="csv" value="' + escapeHTML((p.containers || []).join(", ")) + '" placeholder="jellyfin, traefik, immich_server"></label>';
        advancedFields =
          '<label class="field"><span class="field-label">Socket Docker</span>' +
          '<input type="text" class="mono" data-pf="socket" value="' + escapeHTML(p.socket || "/var/run/docker.sock") + '"></label>' +
          '<label class="field"><span class="field-label">Filtre label (si liste vide)</span>' +
          '<input type="text" class="mono" data-pf="label" value="' + escapeHTML(p.label || "") + '"></label>' +
          '<label class="field"><span class="field-label">Redémarrages max.</span>' +
          '<input type="number" data-pf="max_restarts" data-type="int" value="' + escapeHTML(p.max_restarts || 0) + '"></label>';
        break;

      case "synology":
      case "snmp_oid": {
        const isV3 = p.snmp_version === "3";
        simpleFields =
          '<label class="field"><span class="field-label">Adresse IP du NAS / appareil</span>' +
          '<input type="text" class="mono" data-pf="host" value="' + escapeHTML(p.host || "") + '" placeholder="192.168.1.20"></label>';
        if (p.kind === "synology") {
          simpleFields +=
            '<label class="field"><span class="field-label">Température max. (°C)</span>' +
            '<input type="number" data-pf="max_temp_c" data-type="int" value="' + escapeHTML(p.max_temp_c || 55) + '"></label>';
        } else {
          simpleFields +=
            '<label class="field"><span class="field-label">OID SNMP</span>' +
            '<input type="text" class="mono" data-pf="oid" value="' + escapeHTML(p.oid || "") + '"></label>';
        }
        advancedFields =
          '<label class="field"><span class="field-label">Version SNMP</span>' +
          '<select data-pf="snmp_version" data-rerender="1"><option value="2c"' + (!isV3 ? " selected" : "") + '>SNMPv2c</option><option value="3"' + (isV3 ? " selected" : "") + ">SNMPv3</option></select></label>" +
          '<label class="field"><span class="field-label">Port UDP</span>' +
          '<input type="number" data-pf="port" data-type="int" value="' + escapeHTML(p.port || 161) + '"></label>';
        if (!isV3) {
          advancedFields +=
            '<label class="field"><span class="field-label">Communauté SNMP</span>' +
            '<input type="text" class="mono" data-pf="community" value="' + escapeHTML(p.community || "public") + '"></label>';
        } else {
          advancedFields +=
            '<label class="field"><span class="field-label">Utilisateur SNMPv3</span>' +
            '<input type="text" class="mono" data-pf="user" value="' + escapeHTML(p.user || "") + '"></label>' +
            '<label class="field"><span class="field-label">Auth proto</span>' +
            '<select data-pf="auth_proto">' + ["NONE", "MD5", "SHA", "SHA256", "SHA512"].map((a) => '<option value="' + a + '"' + ((p.auth_proto || "SHA256").toUpperCase() === a ? " selected" : "") + ">" + a + "</option>").join("") + "</select></label>" +
            '<label class="field"><span class="field-label">Mot de passe Auth</span>' +
            '<input type="password" class="mono" data-pf="auth_pass" value="' + escapeHTML(p.auth_pass || "") + '"></label>' +
            '<label class="field"><span class="field-label">Priv proto</span>' +
            '<select data-pf="priv_proto">' + ["NONE", "DES", "AES", "AES192", "AES256"].map((pr) => '<option value="' + pr + '"' + ((p.priv_proto || "AES").toUpperCase() === pr ? " selected" : "") + ">" + pr + "</option>").join("") + "</select></label>" +
            '<label class="field"><span class="field-label">Mot de passe Priv</span>' +
            '<input type="password" class="mono" data-pf="priv_pass" value="' + escapeHTML(p.priv_pass || "") + '"></label>';
        }
        if (p.kind === "snmp_oid") {
          advancedFields +=
            '<label class="field"><span class="field-label">Valeur attendue</span>' +
            '<input type="text" class="mono" data-pf="expected_value" value="' + escapeHTML(p.expected_value || "") + '"></label>' +
            '<label class="field"><span class="field-label">Min</span>' +
            '<input type="number" step="any" data-pf="min_value" data-type="floatptr" value="' + escapeHTML(p.min_value != null ? p.min_value : "") + '"></label>' +
            '<label class="field"><span class="field-label">Max</span>' +
            '<input type="number" step="any" data-pf="max_value" data-type="floatptr" value="' + escapeHTML(p.max_value != null ? p.max_value : "") + '"></label>';
        }
        break;
      }

      case "node_exporter":
      case "windows_exporter":
        simpleFields =
          '<label class="field span-2"><span class="field-label">Adresse des métriques (/metrics)</span>' +
          '<input type="url" class="mono" data-pf="url" value="' + escapeHTML(p.url || "") + '" placeholder="http://192.168.1.10:9100/metrics"></label>';
        if (p.kind === "windows_exporter") {
          simpleFields +=
            '<label class="field span-2"><span class="field-label">Services Windows à surveiller (virgules)</span>' +
            '<input type="text" class="mono" data-pf="services" data-type="csv" value="' + escapeHTML((p.services || []).join(", ")) + '" placeholder="W32Time, VeeamBackupSvc"></label>';
        }
        advancedFields =
          '<label class="field"><span class="field-label">Alerte disque max. (%)</span>' +
          '<input type="number" step="any" data-pf="max_disk_percent" data-type="float" value="' + escapeHTML(p.max_disk_percent || 90) + '"></label>' +
          '<label class="field"><span class="field-label">Alerte RAM max. (%)</span>' +
          '<input type="number" step="any" data-pf="max_ram_percent" data-type="float" value="' + escapeHTML(p.max_ram_percent || 92) + '"></label>' +
          '<label class="field span-2"><span class="field-label">Disques spécifiques (optionnel)</span>' +
          '<input type="text" class="mono" data-pf="disks" data-type="csv" value="' + escapeHTML((p.disks || []).join(", ")) + '"></label>';
        break;
    }

    return (
      '<div class="editor-header">' +
      "<h2>" + escapeHTML(p.id || "Nouveau service") + "</h2>" +
      '<button type="button" class="inline-danger" id="delete-probe-btn">Supprimer</button>' +
      "</div>" +
      '<div class="form-grid two-col">' +
      '<label class="field"><span class="field-label">Nom du service</span>' +
      '<input type="text" class="mono" data-pf="id" value="' + escapeHTML(p.id || "") + '"></label>' +
      '<label class="field"><span class="field-label">Catégorie</span>' +
      '<select data-pf="kind" data-rerender="1">' + kindOptions + "</select></label>" +
      simpleFields +
      "</div>" +
      '<details class="advanced-fold"><summary>Options avancées (fréquence, seuils, sécurité)</summary>' +
      '<div class="form-grid two-col fold-body">' +
      '<label class="field"><span class="field-label">Vérifier toutes les</span>' +
      '<input type="text" class="mono" data-pf="interval" value="' + escapeHTML(p.interval || "60s") + '"></label>' +
      '<label class="field"><span class="field-label">Temps limite</span>' +
      '<input type="text" class="mono" data-pf="timeout" value="' + escapeHTML(p.timeout || "10s") + '"></label>' +
      advancedFields +
      "</div></details>"
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

        if (type === "bool") probe[field] = el.checked;
        else if (type === "int") probe[field] = el.value === "" ? 0 : parseInt(el.value, 10) || 0;
        else if (type === "intptr") probe[field] = el.value === "" ? null : parseInt(el.value, 10);
        else if (type === "float") probe[field] = el.value === "" ? 0 : parseFloat(el.value) || 0;
        else if (type === "floatptr") probe[field] = el.value === "" ? null : parseFloat(el.value);
        else if (type === "csv") probe[field] = el.value.split(",").map((s) => s.trim()).filter(Boolean);
        else probe[field] = el.value;

        state.yamlEditedDirectly = false;
        setDirty(true);

        if (el.dataset.rerender === "1") {
          renderProbesWorkspace();
        } else if (field === "id" || field === "interval") {
          const item = $("probe-list").querySelector('[data-select-probe="' + idx + '"]');
          if (item) {
            item.querySelector(".probe-item-id").textContent = probe.id || "Service sans nom";
            item.querySelector(".probe-item-meta").textContent = probeKindLabel(probe.kind) + " · " + (probe.interval || "60s");
          }
          const h2 = editorEl.querySelector(".editor-header h2");
          if (h2 && field === "id") h2.textContent = probe.id || "Nouveau service";
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

  /* ---------------- SAVE & ACTIONS ---------------- */

  async function saveConfiguration(customSuccessMsg) {
    clearFeedback();
    const saveBtn = $("save-btn");
    saveBtn.disabled = true;
    saveBtn.textContent = "Enregistrement...";

    try {
      let body;
      if (state.yamlEditedDirectly) {
        body = JSON.stringify({ yaml: $("yaml-editor").value });
      } else {
        readGeneralFieldsIntoConfig();
        body = JSON.stringify({ config: state.config });
      }

      const { ok, data } = await apiFetch("/api/config", { method: "PUT", body });
      if (!ok) {
        const msg = (data.errors && data.errors.join(" | ")) || data.error || "Configuration invalide";
        showFeedback("err", "Vérifiez vos paramètres : " + msg);
        return false;
      }

      state.config = data.config;
      state.rawYAML = data.yaml;
      state.yamlEditedDirectly = false;
      setDirty(false);
      populateFormsFromConfig();

      if (data.persisted) {
        showFeedback("ok", customSuccessMsg || "Modifications enregistrées et activées.");
      } else {
        showFeedback(
          "warn",
          "Activé en mémoire, mais le fichier est en lecture seule. Téléchargez config.yaml dans Réglages."
        );
      }
      await fetchStatus();
      return true;
    } catch (err) {
      showFeedback("err", "Erreur d'enregistrement : " + err.message);
      return false;
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = "Enregistrer";
    }
  }

  async function runKeygen(goToFriends) {
    clearFeedback();
    try {
      const { ok, data } = await apiFetch("/api/keygen", { method: "POST", body: "{}" });
      if (!ok) {
        showFeedback("err", data.error || "Impossible de générer les clés");
        return;
      }
      state.config.node.private_key_hex = data.private_key_hex;
      state.config.node.pubkey_hex = data.pubkey_hex;
      if (!state.config.node.group_psk_hex) {
        state.config.node.group_psk_hex = data.group_psk_hex;
      } else if (confirm("Créer aussi un nouveau mot de passe de groupe ? Annulez pour garder celui partagé avec vos amis.")) {
        state.config.node.group_psk_hex = data.group_psk_hex;
      }
      $("cfg-privkey").value = state.config.node.private_key_hex;
      $("cfg-psk").value = state.config.node.group_psk_hex;
      $("id-pubkey").value = data.pubkey_hex;
      $("id-topic-tag").value = data.topic_tag;
      state.yamlEditedDirectly = false;
      setDirty(true);
      if (goToFriends) switchTab("friends");
      showFeedback("ok", "Identité générée. Cliquez sur Enregistrer pour l'activer.");
    } catch (err) {
      showFeedback("err", err.message);
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
        showFeedback("err", data.error || "Activez au moins ntfy ou Photon avant de tester.");
        out.hidden = true;
        return;
      }
      out.innerHTML = (data.results || [])
        .map((r) => {
          const cls = r.ok ? "is-ok" : "is-err";
          const label = r.ok ? "Reçu (" + r.latency_ms + " ms)" : "Échec : " + r.error;
          return (
            '<div class="test-output-line">' +
            '<span class="cell-primary">' + escapeHTML(r.channel === "ntfy" ? "Téléphone (ntfy)" : "iMessage (Photon)") + "</span>" +
            '<span class="status-cell ' + cls + '"><span class="status-dot ' + cls + '"></span>' + escapeHTML(label) + "</span>" +
            "</div>"
          );
        })
        .join("");
      out.hidden = false;
      showFeedback(data.ok ? "ok" : "err", data.ok ? "Alerte de test envoyée avec succès." : "Un canal n'a pas répondu.");
    } catch (err) {
      showFeedback("err", err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Envoyer une alerte de test";
    }
  }

  async function runCheckWAN() {
    const btn = $("check-wan-btn");
    btn.disabled = true;
    try {
      const { ok, data } = await apiFetch("/api/check-automute", { method: "POST", body: "{}" });
      if (!ok) {
        showFeedback("warn", data.error || "Enregistrez d'abord votre configuration.");
        return;
      }
      showFeedback(
        data.muted ? "warn" : "ok",
        data.muted ? "Internet injoignable : sourdine automatique activée." : "Connexion Internet fonctionnelle."
      );
      await fetchStatus();
    } catch (err) {
      showFeedback("err", err.message);
    } finally {
      btn.disabled = false;
    }
  }

  /* ---------------- BOOTSTRAP ---------------- */

  async function fetchStatus() {
    try {
      const { ok, data } = await apiFetch("/api/status");
      if (ok) renderStatus(data);
    } catch (_) {}
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
    if (stRes.ok) renderStatus(stRes.data);

    loadDiscoverInfo();
    checkUpdates(false);

    if (state.pollHandle) clearInterval(state.pollHandle);
    state.pollHandle = setInterval(fetchStatus, 5000);
  }

  function bindGlobalEvents() {
    document.querySelectorAll(".nav-tab").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.tab));
    });
    document.querySelectorAll(".sub-tab").forEach((btn) => {
      btn.addEventListener("click", () => switchSubTab(btn.dataset.subtab));
    });
    document.querySelectorAll("[data-goto]").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.goto));
    });

    $("save-btn").addEventListener("click", () => saveConfiguration());
    $("quick-setup-btn").addEventListener("click", () => runKeygen(true));
    $("keygen-btn").addEventListener("click", () => runKeygen(false));
    $("test-notify-btn").addEventListener("click", runTestNotify);
    $("check-wan-btn").addEventListener("click", runCheckWAN);

    $("scan-docker-btn").addEventListener("click", runDockerScan);
    $("apply-docker-btn").addEventListener("click", applyDockerSelection);
    $("docker-filter-input").addEventListener("input", renderDockerContainers);
    $("docker-select-running-btn").addEventListener("click", () => {
      state.dockerContainers.filter((c) => c.running).forEach((c) => state.dockerSelected.add(c.name));
      renderDockerContainers();
    });

    $("scan-lan-btn").addEventListener("click", runLANScan);
    $("lan-filter-input").addEventListener("input", renderLANResults);
    $("lan-subnet-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        runLANScan();
      }
    });

    $("check-update-btn").addEventListener("click", () => checkUpdates(true));
    $("update-now-btn").addEventListener("click", triggerUpdate);
    $("settings-update-btn").addEventListener("click", triggerUpdate);

    $("add-probe-btn").addEventListener("click", () => {
      if (!state.config.probes) state.config.probes = [];
      const kind = $("quick-add-kind").value || "http";
      state.config.probes.push(defaultProbeForKind(kind, state.config.probes.length));
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

    $("copy-invite-btn").addEventListener("click", async () => {
      const pub = $("id-pubkey").value;
      if (!pub) return;
      try {
        await navigator.clipboard.writeText(pub);
        showFeedback("ok", "Votre code ami a été copié dans le presse-papiers.");
      } catch (_) {}
    });

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

    $("yaml-details").addEventListener("toggle", async (e) => {
      if (e.target.open && !state.yamlEditedDirectly) {
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
        } catch (_) {}
      }
    });

    $("validate-yaml-btn").addEventListener("click", async () => {
      clearFeedback();
      const { ok, data } = await apiFetch("/api/validate", {
        method: "POST",
        body: JSON.stringify({ yaml: $("yaml-editor").value })
      });
      if (!ok) {
        showFeedback("err", (data.errors && data.errors.join(" | ")) || data.error || "YAML invalide");
        return;
      }
      state.config = data.config;
      state.rawYAML = $("yaml-editor").value;
      populateFormsFromConfig();
      $("yaml-editor").value = state.rawYAML;
      showFeedback("ok", "Configuration YAML valide.");
    });

    $("sync-from-forms-btn").addEventListener("click", async () => {
      readGeneralFieldsIntoConfig();
      state.yamlEditedDirectly = false;
      const { ok, data } = await apiFetch("/api/validate", {
        method: "POST",
        body: JSON.stringify({ config: state.config })
      });
      if (ok && data.yaml) {
        state.rawYAML = data.yaml;
        $("yaml-editor").value = data.yaml;
        showFeedback("ok", "YAML mis à jour.");
      }
    });

    $("copy-yaml-btn").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText($("yaml-editor").value);
        showFeedback("ok", "YAML copié.");
      } catch (_) {}
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
        showAuthGate("Code d'accès incorrect.");
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
      showFeedback("err", "Impossible de joindre MeshWatch : " + err.message);
    }
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
