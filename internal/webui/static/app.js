(() => {
  "use strict";

  const PROBE_KINDS = [
    { value: "http", label: "Site ou app web" },
    { value: "synology", label: "NAS Synology" },
    { value: "proxmox", label: "Serveur Proxmox VE" },
    { value: "windows_winrm", label: "Windows / Hyper-V" },
    { value: "linux_ssh", label: "Serveur Linux (SSH)" },
    { value: "docker", label: "Conteneurs Docker" },
    { value: "tcp", label: "Appareil du réseau" },
    { value: "node_exporter", label: "Linux (node_exporter)" },
    { value: "windows_exporter", label: "Windows (windows_exporter)" },
    { value: "snmp_oid", label: "Capteur SNMP" }
  ];

  const TCP_PORT_PRESETS = [
    { port: 22, label: "SSH / Serveur (port 22)" },
    { port: 80, label: "Interface web HTTP (port 80)" },
    { port: 443, label: "Interface web HTTPS (port 443)" },
    { port: 5000, label: "NAS Synology DSM (port 5000)" },
    { port: 5001, label: "NAS Synology HTTPS (port 5001)" },
    { port: 8096, label: "Jellyfin (port 8096)" },
    { port: 8123, label: "Home Assistant (port 8123)" },
    { port: 445, label: "Partage fichiers SMB (port 445)" },
    { port: 3389, label: "Bureau à distance RDP (port 3389)" }
  ];

  const state = {
    token: sessionStorage.getItem("mw_ui_token") || "",
    activeTab: "home",
    activeSubTab: "docker",
    status: null,
    config: null,
    savedConfigSnapshot: null,
    rawYAML: "",
    configPath: "",
    writable: true,
    dirty: false,
    onboardingDismissed: localStorage.getItem("mw_hide_onboarding") === "1",
    dockerContainers: [],
    dockerSelected: new Set(),
    dockerScannedOnce: false,
    dockerSocket: "/var/run/docker.sock",
    lanItems: [],
    lanScanSummary: "",
    updateInfo: null,
    parsedInvite: null,
    modalProbeIndex: -1,
    modalProbeDraft: null,
    modalOnSaved: null,
    modalFriendIndex: -1,
    toastTimer: null,
    pollHandle: null
  };

  const $ = (id) => document.getElementById(id);

  /* ---------------- THEME & HELPERS ---------------- */

  function initTheme() {
    const saved = localStorage.getItem("mw_theme");
    applyTheme(saved === "dark" ? "dark" : "light");
    document.querySelectorAll("[data-theme-choice]").forEach((btn) => {
      btn.addEventListener("click", () => applyTheme(btn.dataset.themeChoice));
    });
    window.addEventListener("scroll", () => {
      const tb = $("topbar");
      if (tb) tb.classList.toggle("is-scrolled", window.scrollY > 8);
    }, { passive: true });
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

  function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  function setDirty(flag) {
    state.dirty = flag;
    const bar = $("unsaved-bar");
    if (bar) bar.hidden = !flag;
  }

  function showToast(kind, message, durationMs) {
    const bar = $("toast-bar");
    if (!bar) return;
    if (state.toastTimer) clearTimeout(state.toastTimer);
    bar.className = "toast-bar";
    if (kind === "ok") bar.classList.add("is-ok");
    if (kind === "err") bar.classList.add("is-err");
    if (kind === "warn") bar.classList.add("is-warn");
    bar.textContent = message;
    bar.hidden = false;
    state.toastTimer = setTimeout(() => {
      bar.hidden = true;
    }, durationMs || (kind === "err" ? 6500 : 4200));
  }

  function escapeHTML(str) {
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  async function copyTextToClipboard(text, fallbackInput) {
    if (!text) return false;
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch (_) {}
    }
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "0";
    ta.style.left = "-9999px";
    ta.style.fontSize = "16px";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, text.length);
    let copied = false;
    try {
      copied = document.execCommand("copy");
    } catch (_) {
      copied = false;
    }
    ta.remove();
    if (!copied && fallbackInput && fallbackInput.type !== "password") {
      try {
        fallbackInput.focus();
        fallbackInput.select();
      } catch (_) {}
    }
    return copied;
  }

  function formatDurationSec(sec) {
    const s = Math.max(0, Math.floor(sec || 0));
    if (s < 60) return s + " s";
    const m = Math.floor(s / 60);
    if (m < 60) return m + " min";
    const h = Math.floor(m / 60);
    if (h < 24) return h + " h " + (m % 60) + " min";
    const d = Math.floor(h / 24);
    return d + " j " + (h % 24) + " h";
  }

  function formatRelativeTime(iso) {
    if (!iso) return "En attente";
    const diff = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
    if (diff < 5) return "À l'instant";
    if (diff < 60) return "Il y a " + diff + " s";
    if (diff < 3600) return "Il y a " + Math.floor(diff / 60) + " min";
    return "Il y a " + Math.floor(diff / 3600) + " h";
  }

  function probeKindLabel(kind) {
    const match = PROBE_KINDS.find((k) => k.value === kind);
    return match ? match.label : kind;
  }

  function humanizeError(raw) {
    const s = String(raw || "");
    if (/^(WinRM|SSH|Proxmox)\b/.test(s)) return s;
    if (/connection refused/i.test(s)) return "L'appareil a refusé la connexion. Vérifiez que le service est démarré et le port correct.";
    if (/no route to host|network is unreachable/i.test(s)) return "Adresse introuvable sur votre réseau local. Vérifiez l'adresse IP.";
    if (/i\/o timeout|deadline exceeded|timeout/i.test(s)) return "Aucune réponse reçue (délai dépassé). Vérifiez l'adresse IP, le pare-feu ou l'activation SNMP.";
    if (/no such host/i.test(s)) return "Nom de domaine ou d'appareil introuvable.";
    return s;
  }

  function humanizeProbeSummary(p) {
    const s = String((p && p.summary) || "").trim();
    if (!s) return p && p.ok ? "Fonctionne normalement" : "Ne répond pas";

    // Docker summary: e.g. "8/8 up" or "6/8 up; traefik (exited)"
    const dockM = s.match(/^(\d+)\/(\d+)\s+up(?:;\s*(.+))?$/i);
    if (dockM) {
      const up = dockM[1];
      const total = dockM[2];
      if (!dockM[3]) {
        return up === total
          ? up + " sur " + total + " applications actives"
          : up + " sur " + total + " actives";
      }
      return up + "/" + total + " actives : " + dockM[3]
        .replace(/\(exited\)/g, "(arrêté)")
        .replace(/\(unhealthy\)/g, "(en erreur)")
        .replace(/\(missing\)/g, "(introuvable)");
    }

    // Synology summary: "System OK, RAID OK, Disks 2/2 OK, Temp 36°C"
    if (/RAID OK/i.test(s) || /System OK/i.test(s)) {
      return s
        .replace(/System OK/g, "Système OK")
        .replace(/System failed/g, "Système en erreur")
        .replace(/RAID OK/g, "RAID sain")
        .replace(/Disks (\d+)\/\d+ OK/gi, "$1 disques sains")
        .replace(/Disks /g, "Disques ")
        .replace(/Temp /g, "");
    }

    // HTTP TLS
    if (/^HTTP \d+/i.test(s)) {
      return s
        .replace(/TLS OK:\s*(\d+)d/i, "Certificat valide $1 j")
        .replace(/TLS cert expires in /i, "Certificat expire dans ");
    }

    // TCP open
    if (/^TCP .* reachable$/i.test(s) || /^open$/i.test(s)) {
      return "Service joignable sur le réseau";
    }

    // Proxmox API
    if (/^(Node|CPU|RAM|Disque|Stockage|VM\/LXC|Proxmox)|en ligne/i.test(s)) {
      return humanizeError(
        s
          .replace(/\boffline\b/gi, "hors ligne")
          .replace(/\bstopped\b/gi, "arrêtée")
          .replace(/\bpaused\b/gi, "en pause")
          .replace(/\bunavailable\b/gi, "indisponible")
          .replace(/\bunknown\b/gi, "état inconnu")
      );
    }

    return humanizeError(s);
  }

  function normalizeDurationSelect(selectEl, val) {
    if (!selectEl || !val) return;
    const normalized = String(val).trim();
    const map = { "90s": "1m30s", "60s": "1m", "120s": "2m", "180s": "3m", "300s": "5m" };
    const candidate = map[normalized] || normalized;
    let found = false;
    for (let i = 0; i < selectEl.options.length; i++) {
      if (selectEl.options[i].value === candidate) {
        selectEl.selectedIndex = i;
        found = true;
        break;
      }
    }
    if (!found && normalized) {
      const opt = document.createElement("option");
      opt.value = normalized;
      opt.textContent = "Personnalisé (" + normalized + ")";
      selectEl.appendChild(opt);
      selectEl.value = normalized;
    }
  }

  function slugifyID(name, fallback) {
    const clean = String(name || "")
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
    return clean || fallback || "service";
  }

  function ensureUniqueProbeID(base, excludeIdx) {
    const existing = new Set(
      ((state.config && state.config.probes) || [])
        .map((p, i) => (i === excludeIdx ? "" : p.id))
        .filter(Boolean)
    );
    let cand = base || "service";
    let n = 2;
    while (existing.has(cand)) {
      cand = base + "-" + n;
      n++;
    }
    return cand;
  }

  function extractHostFromExporterURL(url, defaultPort) {
    const s = String(url || "").trim();
    if (!s) return "";
    try {
      const u = new URL(s);
      if (u.pathname === "/metrics" && (!u.port || Number(u.port) === defaultPort)) {
        return u.hostname;
      }
    } catch (_) {}
    return s;
  }

  function buildExporterURL(input, defaultPort) {
    const s = String(input || "").trim();
    if (!s) return "";
    if (/^https?:\/\//i.test(s)) return s;
    const hasPort = /:\d+$/.test(s);
    return "http://" + s + (hasPort ? "" : ":" + defaultPort) + "/metrics";
  }

  function extractHostFromProxmoxURL(url) {
    const s = String(url || "").trim();
    if (!s) return "";
    try {
      const u = new URL(s);
      const pathLower = (u.pathname || "").toLowerCase();
      if (u.protocol === "https:" && (!u.port || Number(u.port) === 8006) && (!u.pathname || u.pathname === "/" || pathLower === "/api2/json" || pathLower === "/api2/json/")) {
        return u.hostname;
      }
    } catch (_) {}
    return s;
  }

  function buildProxmoxURL(input) {
    let s = String(input || "").trim();
    if (!s) return "";
    s = s.replace(/\/api2\/json\/?$/i, "").replace(/\/+$/, "");
    if (/^https?:\/\//i.test(s)) return s;
    const hasPort = /:\d+$/.test(s) || /\]:\d+$/.test(s);
    if (s.includes(":") && !s.startsWith("[") && !hasPort) {
      s = "[" + s + "]";
    }
    return "https://" + s + (hasPort ? "" : ":8006");
  }

  /* ---------------- API ---------------- */

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

  /* ---------------- NAVIGATION ---------------- */

  function switchTab(tab, subTab) {
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
    if (tab === "discover") {
      if (subTab) switchSubTab(subTab);
      else if (state.activeSubTab === "docker" && !state.dockerScannedOnce) runDockerScan();
      else if (state.activeSubTab === "managed") renderManagedProbes();
    }
    if (tab === "friends") {
      updateInviteCodeDisplay();
      renderPeersList();
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
    if (sub === "docker" && !state.dockerScannedOnce) runDockerScan();
    if (sub === "managed") renderManagedProbes();
  }

  /* ---------------- ACCUEIL ---------------- */

  function renderStatus(st) {
    state.status = st;

    const setupNotice = $("setup-notice");
    setupNotice.hidden = st.mode !== "setup";

    const probes = st.probes || [];
    const okProbes = probes.filter((p) => p.ok).length;
    const failedProbes = probes.length - okProbes;

    const peers = st.peers || [];
    const onlinePeers = peers.filter((p) => p.online).length;
    const peerAlerts = peers.filter((p) => p.timed_out || (p.online && !p.overall_ok)).length;

    const relays = st.relays || [];
    const connRelays = relays.filter((r) => r.connected).length;

    const hasNotif = Boolean(
      st.notifications && (st.notifications.ntfy_enabled || st.notifications.photon_enabled)
    );

    const heroDot = $("ov-hero-dot");
    heroDot.className = "hero-dot";

    const lastHbStr = st.last_heartbeat_at
      ? "Dernier signal envoyé " + formatRelativeTime(st.last_heartbeat_at).toLowerCase()
      : "En attente du premier signal";

    if (st.mode === "setup") {
      heroDot.classList.add("is-warn");
      $("ov-headline").textContent = "Prêt à démarrer votre supervision";
      $("ov-subtitle").textContent = "Cliquez sur Démarrer en un clic ci-dessus pour créer votre groupe privé.";
    } else if (st.muted) {
      heroDot.classList.add("is-warn");
      $("ov-headline").textContent = "Connexion Internet coupée (alertes en pause)";
      $("ov-subtitle").textContent = "Pour éviter de fausses alertes, MeshWatch suspend l'envoi tant que votre box ne répond plus.";
    } else if (failedProbes > 0) {
      heroDot.classList.add("is-err");
      $("ov-headline").textContent =
        failedProbes === 1 ? "1 appareil demande votre attention" : failedProbes + " appareils demandent votre attention";
      $("ov-subtitle").textContent = (st.node_name || "Chez vous") + " · " + lastHbStr;
    } else if (peerAlerts > 0) {
      heroDot.classList.add("is-warn");
      $("ov-headline").textContent = "Un ami signale une panne";
      $("ov-subtitle").textContent = "Vos appareils fonctionnent bien · " + lastHbStr;
    } else if (probes.length === 0) {
      $("ov-headline").textContent = (st.node_name || "Votre espace") + " est prêt";
      $("ov-subtitle").textContent = "Ajoutez vos premiers appareils dans Mes appareils pour commencer la veille.";
    } else if (onlinePeers > 0) {
      $("ov-headline").textContent = "Tout fonctionne chez vous et chez vos amis";
      $("ov-subtitle").textContent = "Protégé par " + onlinePeers + (onlinePeers > 1 ? " amis en ligne" : " ami en ligne") + " · " + lastHbStr;
    } else {
      $("ov-headline").textContent = "Tout fonctionne sur " + (st.node_name || "votre homelab");
      $("ov-subtitle").textContent = lastHbStr + " · Invitez un ami pour activer l'entraide en cas de coupure.";
    }

    $("metric-probes").textContent = okProbes + " / " + probes.length;
    $("metric-probes-sub").textContent =
      probes.length === 0
        ? "Aucun appareil configuré"
        : failedProbes === 0
          ? "Tous vos appareils répondent"
          : failedProbes + " panne(s) détectée(s)";

    $("metric-peers").textContent = onlinePeers + " / " + peers.length;
    $("metric-peers-sub").textContent =
      peers.length === 0
        ? "Aucun ami configuré"
        : onlinePeers === peers.length
          ? "Vous veillez les uns sur les autres"
          : (peers.length - onlinePeers) + " ami(s) hors ligne";

    $("metric-alerts").textContent = hasNotif ? "Actives" : "À activer";
    $("metric-alerts-sub").textContent = hasNotif ? "Notifications prêtes" : "Aucune configurée";
    $("metric-alerts-action").textContent = hasNotif ? "Tester" : "Configurer";

    $("metric-wan").textContent = st.muted ? "Coupé" : "Connecté";
    $("metric-wan-sub").textContent = st.muted
      ? "Alertes en pause"
      : connRelays + "/" + relays.length + " relais actifs";
    $("ov-uptime").textContent = "Actif depuis " + formatDurationSec(st.uptime_sec);
    $("ov-mutual-explain").textContent = onlinePeers > 0
      ? "Vos appareils sont testés localement sans ouvrir aucun port. Si votre maison ne répond plus, " +
        onlinePeers + (onlinePeers > 1 ? " amis en ligne vous alertent" : " ami en ligne vous alerte") + " sur votre téléphone."
      : "Vos appareils sont testés localement sans ouvrir de port. Ajoutez au moins un ami pour recevoir une alerte si votre box coupe.";

    if (st.pubkey_hex) $("id-pubkey").value = st.pubkey_hex;
    if (st.topic_tag) $("id-topic-tag").value = st.topic_tag;
    if (st.version) {
      $("settings-version-label").textContent = st.version + (st.commit ? " (" + st.commit + ")" : "");
    }

    renderOnboardingChecklist(st);
    renderHomeProbes(probes, st.probe_history || {});
    renderHomePeers(peers);
    renderHomeIncidents(st.incidents || []);
    renderTopology(st);
    if (state.activeTab === "discover" && state.activeSubTab === "managed") renderManagedProbes();
    if (state.activeTab === "friends") renderPeersList();
  }

  function renderOnboardingChecklist(st) {
    const card = $("onboarding-card");
    if (!card) return;
    if (st.mode === "setup" || state.onboardingDismissed) {
      card.hidden = true;
      return;
    }

    const cfgProbes = (state.config && state.config.probes) || [];
    const cfgPeers = (state.config && state.config.peers) || [];
    const hasDevices = cfgProbes.length > 0 || (st.probes && st.probes.length > 0);
    const hasAlerts = Boolean(
      (st.notifications && (st.notifications.ntfy_enabled || st.notifications.photon_enabled)) ||
      (state.config && state.config.notifications && (
        (state.config.notifications.ntfy && state.config.notifications.ntfy.enabled) ||
        (state.config.notifications.photon_imessage && state.config.notifications.photon_imessage.enabled)
      ))
    );
    const hasFriends = cfgPeers.length > 0 || (st.peers && st.peers.length > 0);

    const doneCount = (hasDevices ? 1 : 0) + (hasAlerts ? 1 : 0) + (hasFriends ? 1 : 0);
    if (doneCount === 3) {
      card.hidden = true;
      return;
    }

    card.hidden = false;
    $("onboarding-progress").textContent = doneCount + " sur 3 étapes terminées.";

    const applyStep = (id, done, num) => {
      const btn = $(id);
      const mark = $(id + "-mark");
      btn.classList.toggle("is-done", done);
      mark.textContent = done ? "✓" : String(num);
    };
    applyStep("step-devices", hasDevices, 1);
    applyStep("step-alerts", hasAlerts, 2);
    applyStep("step-friends", hasFriends, 3);
  }

  function renderUptimeStrip(points, isPeer) {
    const slots = 24;
    const list = Array.isArray(points) ? points.slice(-slots) : [];
    const padCount = Math.max(0, slots - list.length);
    let barsHTML = "";
    for (let i = 0; i < padCount; i++) {
      barsHTML += '<span class="uptime-bar" aria-hidden="true"></span>';
    }
    let okCount = 0;
    list.forEach((pt) => {
      let cls = "is-ok";
      if (isPeer) {
        if (pt.state === "down") cls = "is-err";
        else if (pt.state === "warn") cls = "is-warn";
        else okCount++;
      } else {
        if (pt.ok) okCount++;
        else cls = "is-err";
      }
      barsHTML += '<span class="uptime-bar ' + cls + '" aria-hidden="true"></span>';
    });
    const pctText = list.length ? Math.round((okCount / list.length) * 100) + "%" : "100%";
    return (
      '<div class="uptime-strip" title="Disponibilité sur les dernières vérifications">' +
      '<div class="uptime-bars">' + barsHTML + "</div>" +
      '<span class="uptime-pct tabular">' + pctText + "</span>" +
      "</div>"
    );
  }

  function renderHomeProbes(probes, historyMap) {
    const list = $("ov-probes-list");
    if (!probes.length) {
      list.innerHTML =
        '<div class="empty-state">Aucun service surveillé pour le moment. Cliquez sur Ajouter un appareil pour choisir vos applications Docker ou scanner votre réseau.</div>';
      return;
    }
    list.innerHTML = probes
      .map((p) => {
        const cls = p.ok ? "is-ok" : "is-err";
        const label = p.ok ? "Actif" : "En panne";
        const lat = (p.latency_ms != null ? p.latency_ms : 0) + " ms";
        const hist = (historyMap && historyMap[p.id]) || [{ ok: p.ok }];
        return (
          '<div class="surface-row">' +
          '<div class="row-main">' +
          '<div class="row-title-line">' +
          '<span class="status-cell ' + cls + '"><span class="status-dot ' + cls + '"></span>' + label + "</span>" +
          '<span class="row-title">' + escapeHTML(p.id) + "</span>" +
          '<span class="row-kind">' + escapeHTML(probeKindLabel(p.kind)) + "</span>" +
          "</div>" +
          '<div class="row-sub">' + escapeHTML(humanizeProbeSummary(p)) + "</div>" +
          "</div>" +
          '<div class="row-right">' +
          renderUptimeStrip(hist, false) +
          '<span class="row-latency tabular">' + escapeHTML(lat) + "</span>" +
          '<div class="row-actions">' +
          '<button type="button" class="inline-action" data-test-probe-id="' + escapeHTML(p.id) + '">Tester</button>' +
          '<button type="button" class="inline-action" data-edit-probe-id="' + escapeHTML(p.id) + '">Modifier</button>' +
          "</div>" +
          "</div>" +
          "</div>"
        );
      })
      .join("");

    list.querySelectorAll("[data-test-probe-id]").forEach((btn) => {
      btn.addEventListener("click", () => quickTestProbeByID(btn.dataset.testProbeId, btn));
    });
    list.querySelectorAll("[data-edit-probe-id]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.dataset.editProbeId;
        const idx = ((state.config && state.config.probes) || []).findIndex((pr) => pr.id === id);
        if (idx >= 0) openProbeModal(idx);
      });
    });
  }

  function renderHomePeers(peers) {
    const list = $("ov-peers-list");
    if (!peers.length) {
      list.innerHTML =
        '<div class="empty-state">Aucun ami connecté pour le moment. Ouvrez Mes amis pour copier votre code d\'invitation.</div>';
      return;
    }
    list.innerHTML = peers
      .map((p) => {
        let cls = "is-muted";
        let label = "En attente de signal";
        let detail = "Partagez vos codes d'invitation pour relier vos deux installations.";
        const peerProbes = p.probes || [];
        const failing = peerProbes.filter((pr) => !pr.ok);

        if (p.timed_out) {
          cls = "is-err";
          label = "Hors ligne";
          detail = "Aucun signal reçu récemment (" + formatRelativeTime(p.last_seen).toLowerCase() + ").";
        } else if (p.online && failing.length > 0) {
          cls = "is-warn";
          label = failing.length + " service(s) en panne";
          detail = failing.map((f) => f.id + " (" + humanizeProbeSummary(f) + ")").join(" · ");
        } else if (p.online) {
          cls = "is-ok";
          label = "En ligne · Tout va bien";
          detail = peerProbes.length
            ? peerProbes.length + " service(s) actif(s) chez cet ami · Surveillance mutuelle active"
            : "Connexion mutuelle active (aucun service déclaré chez cet ami)";
        }

        return (
          '<div class="surface-row">' +
          '<div class="row-main">' +
          '<div class="row-title-line">' +
          '<span class="status-cell ' + cls + '"><span class="status-dot ' + cls + '"></span>' + escapeHTML(label) + "</span>" +
          '<span class="row-title">' + escapeHTML(p.name) + "</span>" +
          "</div>" +
          '<div class="row-sub">' + escapeHTML(detail) + "</div>" +
          "</div>" +
          '<div class="row-right">' +
          renderUptimeStrip(p.history || [], true) +
          '<span class="band-meta tabular">' + escapeHTML(formatRelativeTime(p.last_seen)) + "</span>" +
          "</div>" +
          "</div>"
        );
      })
      .join("");
  }

  function renderHomeIncidents(incidents) {
    const list = $("ov-incidents-list");
    const countEl = $("incidents-count");
    if (!list) return;
    if (!incidents || !incidents.length) {
      countEl.textContent = "Aucun incident";
      list.innerHTML =
        '<div class="empty-state">Aucune panne enregistrée depuis le démarrage de votre agent.</div>';
      return;
    }
    countEl.textContent = incidents.length + (incidents.length > 1 ? " événements" : " événement");
    list.innerHTML = incidents
      .slice(0, 10)
      .map((ev) => {
        const cls = ev.ok ? "is-ok" : "is-err";
        const label = ev.ok ? "Rétabli" : "Incident";
        const when = formatRelativeTime(new Date((ev.ts || 0) * 1000).toISOString());
        return (
          '<div class="surface-row">' +
          '<div class="row-main">' +
          '<div class="row-title-line">' +
          '<span class="status-cell ' + cls + '"><span class="status-dot ' + cls + '"></span>' + label + "</span>" +
          '<span class="row-title">' + escapeHTML(ev.target || "") + "</span>" +
          "</div>" +
          '<div class="row-sub">' + escapeHTML(ev.summary || "") + "</div>" +
          "</div>" +
          '<div class="row-right">' +
          '<span class="band-meta tabular">' + escapeHTML(when) + "</span>" +
          "</div>" +
          "</div>"
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
    const cAccent = cs.getPropertyValue("--accent-ink").trim();
    const cOk = cs.getPropertyValue("--ok").trim();
    const cErr = cs.getPropertyValue("--err").trim();
    const cWarn = cs.getPropertyValue("--warn").trim();

    const relays = st.relays || [];
    const peers = st.peers || [];
    const probes = st.probes || [];
    const okProbes = probes.filter((p) => p.ok).length;
    const connRelays = relays.filter((r) => r.connected).length;

    const peerCount = Math.max(peers.length, 1);
    const viewH = Math.max(210, 64 + peerCount * 68);
    svg.setAttribute("viewBox", "0 0 960 " + viewH);

    const midY = Math.round(viewH / 2);
    const localColor = st.mode === "setup" ? cWarn : st.overall_ok ? cOk : cErr;
    const relayColor = connRelays > 0 ? cAccent : cMuted;

    let out = "";
    out +=
      '<path d="M 276 ' + midY + " L 372 " + midY +
      '" fill="none" stroke="' + relayColor + '" stroke-width="2.2" ' +
      (connRelays === 0 ? 'stroke-dasharray="5 5"' : "") + "/>";

    const peerStartY = peerCount === 1 ? midY : Math.round((viewH - (peerCount - 1) * 68) / 2);
    if (peers.length === 0) {
      out +=
        '<path d="M 588 ' + midY + " L 684 " + midY +
        '" fill="none" stroke="' + cBorder + '" stroke-width="1.8" stroke-dasharray="5 5"/>';
      out +=
        '<g class="topo-node" data-topo-tab="friends">' +
        '<rect x="684" y="' + (midY - 32) + '" width="244" height="64" rx="12" fill="' + cSubtle + '" stroke="' + cBorder + '" stroke-dasharray="4 4" stroke-width="1.4"/>' +
        '<text x="704" y="' + (midY - 4) + '" fill="' + cText + '" font-size="15" font-weight="700">Inviter un ami</text>' +
        '<text x="704" y="' + (midY + 17) + '" fill="' + cMuted + '" font-size="13">Partager un code en 1 clic</text>' +
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
          pState = "Alerte détectée";
        } else if (peer.online) {
          pColor = cOk;
          pState = "Vous protège";
        }
        out +=
          '<path d="M 588 ' + midY + " C 636 " + midY + ", 636 " + py + ", 684 " + py +
          '" fill="none" stroke="' + pColor + '" stroke-width="2" ' +
          (!peer.online ? 'stroke-dasharray="5 5"' : "") + "/>";
        out +=
          '<g class="topo-node" data-topo-tab="friends">' +
          '<rect x="684" y="' + (py - 28) + '" width="244" height="56" rx="12" fill="' + cSurface + '" stroke="' + cBorder + '" stroke-width="1.4"/>' +
          '<circle cx="705" cy="' + py + '" r="5" fill="' + pColor + '"/>' +
          '<text x="720" y="' + (py - 4) + '" fill="' + cText + '" font-size="15" font-weight="700">' + escapeHTML(peer.name.slice(0, 22)) + "</text>" +
          '<text x="720" y="' + (py + 16) + '" fill="' + cMuted + '" font-size="13">' + escapeHTML(pState) + "</text>" +
          "</g>";
      });
    }

    out +=
      '<g class="topo-node" data-topo-tab="settings">' +
      '<rect x="372" y="' + (midY - 44) + '" width="216" height="88" rx="12" fill="' + cSubtle + '" stroke="' + relayColor + '" stroke-width="1.6"/>' +
      '<text x="480" y="' + (midY - 12) + '" text-anchor="middle" fill="' + cText + '" font-size="15" font-weight="700">Liaison privée</text>' +
      '<text x="480" y="' + (midY + 10) + '" text-anchor="middle" fill="' + cMuted + '" font-size="13">' + connRelays + " sur " + relays.length + " relais actifs</text>" +
      '<text x="480" y="' + (midY + 29) + '" text-anchor="middle" fill="' + cMuted + '" font-size="13">Chiffrement bout en bout</text>' +
      "</g>";

    out +=
      '<g class="topo-node" data-topo-tab="discover">' +
      '<rect x="32" y="' + (midY - 44) + '" width="244" height="88" rx="12" fill="' + cSurface + '" stroke="' + localColor + '" stroke-width="1.8"/>' +
      '<circle cx="54" cy="' + (midY - 15) + '" r="5.5" fill="' + localColor + '"/>' +
      '<text x="69" y="' + (midY - 10) + '" fill="' + cText + '" font-size="15" font-weight="700">' + escapeHTML((st.node_name || "Chez vous").slice(0, 20)) + "</text>" +
      '<text x="50" y="' + (midY + 12) + '" fill="' + cMuted + '" font-size="13">' + okProbes + " / " + probes.length + " appareils actifs</text>" +
      '<text x="50" y="' + (midY + 31) + '" fill="' + cMuted + '" font-size="13">' + (st.muted ? "Internet coupé" : "Aucun port ouvert") + "</text>" +
      "</g>";

    svg.innerHTML = out;
    svg.querySelectorAll("[data-topo-tab]").forEach((node) => {
      node.addEventListener("click", () => switchTab(node.dataset.topoTab));
    });
  }

  /* ---------------- ACTIONS RAPIDES SUR LES APPAREILS ---------------- */

  async function runAllProbesNow() {
    const btn = $("run-all-probes-btn");
    btn.disabled = true;
    btn.textContent = "Vérification...";
    try {
      const { ok, data } = await apiFetch("/api/probes/run", {
        method: "POST",
        body: "{}"
      });
      if (!ok) {
        showToast("warn", data.error || "Vérification impossible pour le moment.");
        return;
      }
      await fetchStatus();
      const count = (data.probes || []).length;
      showToast(
        data.overall_ok ? "ok" : "warn",
        data.overall_ok
          ? count + " appareil(s) vérifiés : tout répond correctement."
          : "Vérification terminée : un appareil signale un problème."
      );
    } catch (err) {
      showToast("err", "Erreur : " + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Tout vérifier";
    }
  }

  async function quickTestProbeByID(probeID, btn) {
    const cfgProbe = ((state.config && state.config.probes) || []).find((pr) => pr.id === probeID);
    if (!cfgProbe) return;
    const prevText = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Test...";
    try {
      const { ok, data } = await apiFetch("/api/probes/test", {
        method: "POST",
        body: JSON.stringify({ probe: cfgProbe })
      });
      if (!ok) {
        showToast("err", probeID + " : " + humanizeError(data.error || "échec du test"));
        return;
      }
      if (data.ok) {
        showToast("ok", probeID + " fonctionne (" + (data.latency_ms || 0) + " ms) · " + humanizeProbeSummary(data));
      } else {
        showToast("err", probeID + " en panne · " + humanizeProbeSummary(data));
      }
    } catch (err) {
      showToast("err", "Erreur test : " + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = prevText;
    }
  }

  /* ---------------- APPAREILS : DOCKER & LAN ---------------- */

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
    meta.textContent = "Recherche des applications Docker en cours...";
    try {
      const { ok, data } = await apiFetch("/api/discover/docker", {
        method: "POST",
        body: JSON.stringify({ socket: state.dockerSocket })
      });
      if (!ok) {
        meta.textContent = "Docker non détecté sur cette machine (" + (data.error || "socket inaccessible") + ").";
        $("docker-containers-list").innerHTML =
          '<div class="empty-state">Si vous utilisez Docker, montez /var/run/docker.sock dans votre docker-compose.yml pour cocher vos applications ici.</div>';
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
        " application(s) trouvée(s) (" +
        runningCount +
        " active(s), " +
        state.dockerSelected.size +
        " cochée(s)).";
      renderDockerContainers();
    } catch (err) {
      meta.textContent = "Erreur lors de la lecture Docker : " + err.message;
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
      list.innerHTML = '<div class="empty-state">Aucune application ne correspond à votre recherche.</div>';
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
          '<div class="surface-row">' +
          '<div class="row-main">' +
          '<div class="row-title-line">' +
          '<span class="status-cell ' + cls + '"><span class="status-dot ' + cls + '"></span>' + stateLabel + "</span>" +
          '<span class="row-title">' + escapeHTML(c.name) + "</span>" +
          "</div>" +
          '<div class="row-sub">' + escapeHTML(c.image || "") + escapeHTML(portsStr) + "</div>" +
          "</div>" +
          '<div class="row-right">' +
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
    $("apply-docker-btn").textContent = "Enregistrer (" + state.dockerSelected.size + ")";
  }

  async function applyDockerSelection() {
    const selected = Array.from(state.dockerSelected).sort();
    if (!state.config.probes) state.config.probes = [];

    const idx = state.config.probes.findIndex((p) => p.kind === "docker");
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

    const ok = await saveConfiguration("Surveillance Docker enregistrée (" + selected.length + " conteneur(s)).");
    if (ok) {
      state.dockerContainers.forEach((c) => {
        c.monitored = state.dockerSelected.has(c.name);
      });
    }
  }

  async function runLANScan() {
    const btn = $("scan-lan-btn");
    const meta = $("lan-scan-meta");
    const subnet = ($("lan-subnet-input").value || "").trim() || "192.168.1.0/24";
    btn.disabled = true;
    btn.textContent = "Scan en cours...";
    meta.textContent = "Recherche des NAS Synology, serveurs et applications web sur " + subnet + "...";

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
        " s).";
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
          '<div class="empty-state">Aucun appareil détecté sur cette plage. Vérifiez le sous-réseau (ex. 192.168.1.0/24 ou 192.168.0.0/24).</div>';
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
      list.innerHTML = '<div class="empty-state">Aucun appareil ne correspond à votre recherche.</div>';
      return;
    }

    list.innerHTML = filtered
      .map(({ item, idx }) => {
        const kind = item.suggested_probe && item.suggested_probe.kind;
        const needsConfig = kind === "proxmox" || kind === "windows_winrm" || kind === "linux_ssh";
        const actionHTML = item.already_monitored
          ? '<span class="status-cell is-ok"><span class="status-dot is-ok"></span>Déjà surveillé</span>'
          : needsConfig
            ? '<button type="button" class="btn-primary" data-configure-discovered="' + idx + '">Configurer</button>'
            : '<button type="button" class="btn-primary" data-add-discovered="' + idx + '">Surveiller</button>';
        return (
          '<div class="surface-row">' +
          '<div class="row-main">' +
          '<div class="row-title-line">' +
          '<span class="row-title">' + escapeHTML(item.name) + "</span>" +
          '<span class="mono-inline">' + escapeHTML(item.ip) + "</span>" +
          "</div>" +
          '<div class="row-sub">' + escapeHTML(item.category_label) + " · " + escapeHTML(item.summary) + "</div>" +
          "</div>" +
          '<div class="row-right">' + actionHTML + "</div>" +
          "</div>"
        );
      })
      .join("");

    list.querySelectorAll("[data-configure-discovered]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const idx = Number(btn.dataset.configureDiscovered);
        const item = state.lanItems[idx];
        if (!item || !item.suggested_probe) return;
        const kind = item.suggested_probe.kind;
        let sub = "Complétez les informations ci-dessous puis testez la connexion.";
        if (kind === "proxmox") sub = "Renseignez votre jeton API Proxmox VE puis testez la connexion.";
        else if (kind === "windows_winrm") sub = "Renseignez vos identifiants Windows puis testez la connexion.";
        else if (kind === "linux_ssh") sub = "Renseignez vos identifiants SSH Linux puis testez la connexion.";
        openProbeModalFromTemplate(
          item.suggested_probe,
          sub,
          () => {
            item.already_monitored = true;
            renderLANResults();
          }
        );
      });
    });

    list.querySelectorAll("[data-add-discovered]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const idx = Number(btn.dataset.addDiscovered);
        const item = state.lanItems[idx];
        if (!item) return;
        btn.disabled = true;
        btn.textContent = "Ajout...";

        if (!state.config.probes) state.config.probes = [];
        const probe = deepClone(item.suggested_probe);
        probe.id = ensureUniqueProbeID(probe.id || slugifyID(item.name, "service"), -1);

        state.config.probes.push(probe);
        const ok = await saveConfiguration(item.name + " est maintenant surveillé.");
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

  /* ---------------- MES SERVICES & MODALE GUIDÉE ---------------- */

  function renderManagedProbes() {
    const probes = (state.config && state.config.probes) || [];
    const subBtn = $("subtab-managed-btn");
    if (subBtn) subBtn.textContent = "Mes services (" + probes.length + ")";

    const list = $("managed-probes-list");
    if (!probes.length) {
      list.innerHTML =
        '<div class="empty-state">Aucun service configuré. Utilisez Applications Docker, Scanner mon réseau ou Ajouter un appareil.</div>';
      return;
    }

    const liveByID = {};
    ((state.status && state.status.probes) || []).forEach((r) => {
      liveByID[r.id] = r;
    });

    list.innerHTML = probes
      .map((p, idx) => {
        const live = liveByID[p.id];
        let cls = "is-muted";
        let stateLabel = "En attente";
        let detail = describeProbeTarget(p);
        if (live) {
          cls = live.ok ? "is-ok" : "is-err";
          stateLabel = live.ok ? "Actif" : "En panne";
          detail += " · " + humanizeProbeSummary(live);
        }
        return (
          '<div class="surface-row">' +
          '<div class="row-main">' +
          '<div class="row-title-line">' +
          '<span class="status-cell ' + cls + '"><span class="status-dot ' + cls + '"></span>' + stateLabel + "</span>" +
          '<span class="row-title">' + escapeHTML(p.id) + "</span>" +
          '<span class="row-kind">' + escapeHTML(probeKindLabel(p.kind)) + "</span>" +
          "</div>" +
          '<div class="row-sub">' + escapeHTML(detail) + "</div>" +
          "</div>" +
          '<div class="row-right">' +
          '<div class="row-actions">' +
          '<button type="button" class="inline-action" data-test-managed="' + escapeHTML(p.id) + '">Tester</button>' +
          '<button type="button" class="inline-action" data-edit-probe="' + idx + '">Modifier</button>' +
          '<button type="button" class="inline-danger" data-delete-probe="' + idx + '">Supprimer</button>' +
          "</div>" +
          "</div>" +
          "</div>"
        );
      })
      .join("");

    list.querySelectorAll("[data-test-managed]").forEach((btn) => {
      btn.addEventListener("click", () => quickTestProbeByID(btn.dataset.testManaged, btn));
    });
    list.querySelectorAll("[data-edit-probe]").forEach((btn) => {
      btn.addEventListener("click", () => openProbeModal(Number(btn.dataset.editProbe)));
    });
    list.querySelectorAll("[data-delete-probe]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const idx = Number(btn.dataset.deleteProbe);
        const target = state.config.probes[idx];
        if (!target) return;
        if (!confirm("Arrêter la surveillance de « " + target.id + " » ?")) return;
        const removed = state.config.probes.splice(idx, 1)[0];
        const ok = await saveConfiguration("« " + removed.id + " » a été retiré de la surveillance.");
        if (!ok) {
          state.config.probes.splice(idx, 0, removed);
        }
      });
    });
  }

  function describeProbeTarget(p) {
    switch (p.kind) {
      case "http":
      case "node_exporter":
      case "windows_exporter":
        return p.url || "";
      case "proxmox":
        return (
          (p.url || "") +
          (p.node ? " · nœud " + p.node : "") +
          (p.vms && p.vms.length ? " · " + p.vms.length + " VM/LXC" : "")
        );
      case "windows_winrm":
        return (
          (p.host || "") +
          ":" +
          (p.port || (p.use_https ? 5986 : 5985)) +
          (p.use_https ? " (WinRM HTTPS)" : " (WinRM)") +
          (p.vms && p.vms.length ? " · " + p.vms.length + " VM Hyper-V" : "")
        );
      case "linux_ssh":
        return (
          (p.host || "") +
          ":" +
          (p.port || 22) +
          " (SSH)" +
          (p.services && p.services.length ? " · " + p.services.length + " service(s)" : "")
        );
      case "synology":
      case "snmp_oid":
        return (p.host || "") + " (SNMP)";
      case "tcp":
        return (p.host || "") + ":" + (p.port || 22);
      case "docker":
        return p.containers && p.containers.length
          ? p.containers.length + " conteneur(s) : " + p.containers.slice(0, 4).join(", ")
          : "Socket Docker local";
      default:
        return "";
    }
  }

  function defaultProbeForKind(kind, count) {
    const base = { id: "", kind, interval: "1m", timeout: "10s" };
    switch (kind) {
      case "http":
        return Object.assign(base, { id: "site-web-" + (count + 1), interval: "30s", url: "https://", expected_status: 200, tls_min_days: 14 });
      case "tcp":
        return Object.assign(base, { id: "appareil-" + (count + 1), interval: "30s", host: "192.168.1.1", port: 22 });
      case "docker":
        return Object.assign(base, { id: "docker-local", interval: "30s", socket: state.dockerSocket, containers: [] });
      case "synology":
        return Object.assign(base, { id: "nas-synology", host: "192.168.1.20", port: 161, snmp_version: "2c", community: "public", max_temp_c: 55 });
      case "proxmox":
        return Object.assign(base, {
          id: "proxmox",
          url: "https://192.168.1.30:8006",
          token_id: "",
          token_secret: "",
          insecure_skip_verify: true,
          max_cpu_percent: 90,
          max_ram_percent: 90,
          max_disk_percent: 90,
          node: "",
          vms: [],
          disks: []
        });
      case "snmp_oid":
        return Object.assign(base, { id: "capteur-snmp-" + (count + 1), host: "192.168.1.50", port: 161, snmp_version: "2c", community: "public", oid: ".1.3.6.1.2.1.1.3.0", expected_value: "1" });
      case "node_exporter":
        return Object.assign(base, { id: "serveur-linux", url: "http://192.168.1.10:9100/metrics", max_disk_percent: 90, max_ram_percent: 92 });
      case "windows_exporter":
        return Object.assign(base, { id: "serveur-windows", url: "http://192.168.1.15:9182/metrics", services: ["W32Time"], max_disk_percent: 90, max_ram_percent: 92 });
      case "windows_winrm":
        return Object.assign(base, {
          id: "windows-host",
          timeout: "15s",
          host: "192.168.1.40",
          port: 5985,
          use_https: false,
          insecure_skip_verify: true,
          user: "Administrator",
          password: "",
          domain: "",
          vms: [],
          services: [],
          disks: [],
          max_cpu_percent: 90,
          max_ram_percent: 90,
          max_disk_percent: 90
        });
      case "linux_ssh":
        return Object.assign(base, {
          id: "linux-ssh",
          timeout: "15s",
          host: "192.168.1.45",
          port: 22,
          user: "monitor",
          password: "",
          ssh_key: "",
          services: [],
          disks: [],
          max_cpu_percent: 90,
          max_ram_percent: 90,
          max_disk_percent: 90
        });
      default:
        return base;
    }
  }

  function openProbeModal(editIndex) {
    state.modalProbeIndex = editIndex;
    state.modalOnSaved = null;
    $("probe-test-result").hidden = true;

    if (editIndex >= 0 && state.config && state.config.probes[editIndex]) {
      state.modalProbeDraft = deepClone(state.config.probes[editIndex]);
      $("probe-modal-title").textContent = "Modifier « " + state.modalProbeDraft.id + " »";
      $("probe-modal-subtitle").textContent = probeKindLabel(state.modalProbeDraft.kind);
      $("probe-modal-picker").hidden = true;
      $("probe-modal-form").hidden = false;
      $("probe-modal-back").hidden = true;
      renderProbeModalFields();
    } else {
      state.modalProbeDraft = null;
      $("probe-modal-title").textContent = "Ajouter un appareil ou service";
      $("probe-modal-subtitle").textContent = "Choisissez simplement ce que vous souhaitez surveiller.";
      $("probe-modal-picker").hidden = false;
      $("probe-modal-form").hidden = true;
      $("probe-modal-back").hidden = false;
    }
    $("probe-modal").hidden = false;
  }

  function openProbeModalFromTemplate(templateProbe, customSubtitle, onSaved) {
    state.modalProbeIndex = -1;
    state.modalOnSaved = typeof onSaved === "function" ? onSaved : null;
    state.modalProbeDraft = deepClone(templateProbe || {});
    state.modalProbeDraft.id = ensureUniqueProbeID(
      state.modalProbeDraft.id || slugifyID(state.modalProbeDraft.kind, "service"),
      -1
    );
    $("probe-modal-title").textContent = "Configurer : " + probeKindLabel(state.modalProbeDraft.kind);
    $("probe-modal-subtitle").textContent = customSubtitle || "Complétez les informations ci-dessous puis testez la connexion.";
    $("probe-modal-picker").hidden = true;
    $("probe-modal-form").hidden = false;
    $("probe-modal-back").hidden = true;
    $("probe-test-result").hidden = true;
    renderProbeModalFields();
    $("probe-modal").hidden = false;
  }

  function closeProbeModal() {
    $("probe-modal").hidden = true;
    state.modalProbeDraft = null;
    state.modalProbeIndex = -1;
    state.modalOnSaved = null;
  }

  function pickProbeKindInModal(kind) {
    if (kind === "docker") {
      closeProbeModal();
      switchTab("discover", "docker");
      return;
    }
    const count = ((state.config && state.config.probes) || []).length;
    state.modalProbeDraft = defaultProbeForKind(kind, count);
    state.modalProbeDraft.id = ensureUniqueProbeID(state.modalProbeDraft.id, -1);
    $("probe-modal-title").textContent = "Ajouter : " + probeKindLabel(kind);
    $("probe-modal-subtitle").textContent = "Renseignez les informations essentielles puis testez la connexion en un clic.";
    $("probe-modal-picker").hidden = true;
    $("probe-modal-form").hidden = false;
    $("probe-modal-back").hidden = false;
    $("probe-test-result").hidden = true;
    renderProbeModalFields();
  }

  function renderProbeModalFields() {
    const p = state.modalProbeDraft;
    if (!p) return;

    let simpleHTML = "";
    let advHTML = "";

    switch (p.kind) {
      case "http":
        simpleHTML =
          '<label class="field span-2"><span class="field-label">Adresse web (URL complète)</span>' +
          '<input type="url" class="mono" data-mp="url" value="' + escapeHTML(p.url || "") + '" placeholder="https://jellyfin.exemple.fr ou http://192.168.1.10:8096" required></label>';
        advHTML =
          '<label class="field"><span class="field-label">Code HTTP attendu</span>' +
          '<input type="number" data-mp="expected_status" data-type="int" value="' + escapeHTML(p.expected_status || 200) + '"></label>' +
          '<label class="field"><span class="field-label">Alerte certificat HTTPS (jours restants)</span>' +
          '<input type="number" data-mp="tls_min_days" data-type="intptr" value="' + escapeHTML(p.tls_min_days != null ? p.tls_min_days : 14) + '"></label>' +
          '<label class="field"><span class="field-label">Texte attendu dans la page (optionnel)</span>' +
          '<input type="text" data-mp="contains" value="' + escapeHTML(p.contains || "") + '"></label>' +
          '<div class="field"><span class="field-label">Certificat local auto-signé</span>' +
          '<label class="switch-control"><input type="checkbox" data-mp="insecure_skip_verify" data-type="bool"' + (p.insecure_skip_verify ? " checked" : "") + '><span class="switch-track"></span><span class="switch-text">Accepter</span></label></div>';
        break;

      case "synology": {
        const isV3 = p.snmp_version === "3";
        simpleHTML =
          '<div class="help-callout">Sur votre NAS Synology : ouvrez <strong>Panneau de configuration → Terminal et SNMP → SNMP</strong>, cochez <strong>Activer le service SNMP</strong> puis <strong>SNMPv2c</strong> (communauté <span class="mono-inline">public</span>).</div>' +
          '<label class="field"><span class="field-label">Adresse IP du NAS</span>' +
          '<input type="text" class="mono" data-mp="host" value="' + escapeHTML(p.host || "") + '" placeholder="192.168.1.20" required></label>' +
          '<label class="field"><span class="field-label">Température d\'alerte (°C)</span>' +
          '<input type="number" data-mp="max_temp_c" data-type="int" value="' + escapeHTML(p.max_temp_c || 55) + '"></label>';
        advHTML =
          '<label class="field"><span class="field-label">Version SNMP</span>' +
          '<select data-mp="snmp_version" data-rerender="1"><option value="2c"' + (!isV3 ? " selected" : "") + '>SNMPv2c (simple)</option><option value="3"' + (isV3 ? " selected" : "") + ">SNMPv3 (chiffré)</option></select></label>" +
          '<label class="field"><span class="field-label">Port SNMP</span>' +
          '<input type="number" data-mp="port" data-type="int" value="' + escapeHTML(p.port || 161) + '"></label>';
        if (!isV3) {
          advHTML +=
            '<label class="field"><span class="field-label">Communauté SNMP</span>' +
            '<input type="text" class="mono" data-mp="community" value="' + escapeHTML(p.community || "public") + '"></label>';
        } else {
          advHTML +=
            '<label class="field"><span class="field-label">Utilisateur SNMPv3</span>' +
            '<input type="text" class="mono" data-mp="user" value="' + escapeHTML(p.user || "") + '"></label>' +
            '<label class="field"><span class="field-label">Protocole Auth</span>' +
            '<select data-mp="auth_proto">' + ["NONE", "MD5", "SHA", "SHA256", "SHA512"].map((a) => '<option value="' + a + '"' + ((p.auth_proto || "SHA256").toUpperCase() === a ? " selected" : "") + ">" + a + "</option>").join("") + "</select></label>" +
            '<label class="field"><span class="field-label">Mot de passe Auth</span>' +
            '<input type="password" class="mono" data-mp="auth_pass" value="' + escapeHTML(p.auth_pass || "") + '"></label>' +
            '<label class="field"><span class="field-label">Protocole Priv</span>' +
            '<select data-mp="priv_proto">' + ["NONE", "DES", "AES", "AES192", "AES256"].map((pr) => '<option value="' + pr + '"' + ((p.priv_proto || "AES").toUpperCase() === pr ? " selected" : "") + ">" + pr + "</option>").join("") + "</select></label>" +
            '<label class="field"><span class="field-label">Mot de passe Priv</span>' +
            '<input type="password" class="mono" data-mp="priv_pass" value="' + escapeHTML(p.priv_pass || "") + '"></label>';
        }
        break;
      }

      case "tcp": {
        const presetMatch = TCP_PORT_PRESETS.some((pr) => pr.port === Number(p.port));
        const presetOpts = TCP_PORT_PRESETS.map(
          (pr) => '<option value="' + pr.port + '"' + (Number(p.port) === pr.port ? " selected" : "") + ">" + escapeHTML(pr.label) + "</option>"
        ).join("");
        simpleHTML =
          '<label class="field"><span class="field-label">Adresse IP ou nom d\'hôte</span>' +
          '<input type="text" class="mono" data-mp="host" value="' + escapeHTML(p.host || "") + '" placeholder="192.168.1.1" required></label>' +
          '<label class="field"><span class="field-label">Service / port à vérifier</span>' +
          '<select id="mp-tcp-preset">' + presetOpts + '<option value="custom"' + (!presetMatch ? " selected" : "") + '>Autre port...</option></select></label>' +
          '<label class="field" id="mp-tcp-port-wrap"' + (presetMatch ? " hidden" : "") + '><span class="field-label">Numéro de port</span>' +
          '<input type="number" data-mp="port" data-type="int" value="' + escapeHTML(p.port || 22) + '"></label>';
        break;
      }

      case "node_exporter":
      case "windows_exporter": {
        const defPort = p.kind === "node_exporter" ? 9100 : 9182;
        const hostVal = extractHostFromExporterURL(p.url, defPort);
        const toolName = p.kind === "node_exporter" ? "node_exporter (port 9100)" : "windows_exporter (port 9182)";
        simpleHTML =
          '<div class="help-callout">Indiquez simplement l\'adresse IP de votre serveur équipé de <strong>' + toolName + '</strong> (MeshWatch complète automatiquement l\'adresse des métriques).</div>' +
          '<label class="field span-2"><span class="field-label">Adresse IP du serveur (ou URL complète)</span>' +
          '<input type="text" class="mono" id="mp-exporter-host" value="' + escapeHTML(hostVal) + '" placeholder="' + (p.kind === "node_exporter" ? "192.168.1.10" : "192.168.1.15") + '" required></label>';
        if (p.kind === "windows_exporter") {
          simpleHTML +=
            '<label class="field span-2"><span class="field-label">Services Windows essentiels (optionnel, séparés par des virgules)</span>' +
            '<input type="text" class="mono" data-mp="services" data-type="csv" value="' + escapeHTML((p.services || []).join(", ")) + '" placeholder="W32Time, VeeamBackupSvc"></label>';
        }
        advHTML =
          '<label class="field"><span class="field-label">Alerte espace disque plein (%)</span>' +
          '<input type="number" step="any" data-mp="max_disk_percent" data-type="float" value="' + escapeHTML(p.max_disk_percent || 90) + '"></label>' +
          '<label class="field"><span class="field-label">Alerte mémoire RAM (%)</span>' +
          '<input type="number" step="any" data-mp="max_ram_percent" data-type="float" value="' + escapeHTML(p.max_ram_percent || 92) + '"></label>' +
          '<label class="field span-2"><span class="field-label">Disques spécifiques à suivre (optionnel)</span>' +
          '<input type="text" class="mono" data-mp="disks" data-type="csv" value="' + escapeHTML((p.disks || []).join(", ")) + '"></label>';
        break;
      }

      case "docker":
        simpleHTML =
          '<div class="help-callout">Astuce : vous pouvez aussi cocher vos conteneurs visuellement dans l\'onglet <strong>Applications Docker</strong>.</div>' +
          '<label class="field span-2"><span class="field-label">Noms des conteneurs (séparés par des virgules)</span>' +
          '<input type="text" class="mono" data-mp="containers" data-type="csv" value="' + escapeHTML((p.containers || []).join(", ")) + '" placeholder="jellyfin, immich_server, traefik"></label>';
        advHTML =
          '<label class="field"><span class="field-label">Socket Docker</span>' +
          '<input type="text" class="mono" data-mp="socket" value="' + escapeHTML(p.socket || "/var/run/docker.sock") + '"></label>' +
          '<label class="field"><span class="field-label">Redémarrages max. tolérés</span>' +
          '<input type="number" data-mp="max_restarts" data-type="int" value="' + escapeHTML(p.max_restarts || 0) + '"></label>';
        break;

      case "proxmox": {
        const hostVal = extractHostFromProxmoxURL(p.url);
        const insecureChecked = p.insecure_skip_verify !== false;
        if (p.insecure_skip_verify === undefined) {
          p.insecure_skip_verify = true;
        }
        simpleHTML =
          '<div class="help-callout">Dans Proxmox VE : ouvrez <strong>Centre de données → Permissions → Jetons d\'API → Ajouter</strong> (ex. <span class="mono-inline">root@pam</span> + ID <span class="mono-inline">meshwatch</span>). Décochez <strong>Séparation des privilèges</strong>, ou accordez au jeton le rôle <span class="mono-inline">PVEAuditor</span> sur <span class="mono-inline">/</span> dans <strong>Permissions → Ajouter → Permission de jeton d\'API</strong>.</div>' +
          '<label class="field"><span class="field-label">Adresse IP ou URL Proxmox</span>' +
          '<input type="text" class="mono" id="mp-proxmox-host" value="' + escapeHTML(hostVal) + '" placeholder="192.168.1.30 ou https://pve.local:8006" required></label>' +
          '<label class="field"><span class="field-label">Token ID Proxmox</span>' +
          '<input type="text" class="mono" data-mp="token_id" value="' + escapeHTML(p.token_id || "") + '" placeholder="root@pam!meshwatch" required></label>' +
          '<div class="field span-2"><span class="field-label">Secret du jeton API</span>' +
          '<div class="input-with-action">' +
          '<input type="password" class="mono" id="mp-proxmox-secret" data-mp="token_secret" autocomplete="off" value="' + escapeHTML(p.token_secret || "") + '" placeholder="UUID secret généré par Proxmox">' +
          '<button type="button" class="field-action" data-toggle-secret="mp-proxmox-secret">Afficher</button>' +
          "</div></div>" +
          '<label class="field span-2"><span class="field-label">VM ou conteneurs LXC critiques à vérifier (optionnel, séparés par des virgules)</span>' +
          '<input type="text" class="mono" data-mp="vms" data-type="csv" value="' + escapeHTML((p.vms || []).join(", ")) + '" placeholder="Ex. 100, 102, homeassistant"></label>';
        advHTML =
          '<label class="field"><span class="field-label">Alerte CPU (%)</span>' +
          '<input type="number" step="any" data-mp="max_cpu_percent" data-type="float" value="' + escapeHTML(p.max_cpu_percent || 90) + '"></label>' +
          '<label class="field"><span class="field-label">Alerte mémoire RAM (%)</span>' +
          '<input type="number" step="any" data-mp="max_ram_percent" data-type="float" value="' + escapeHTML(p.max_ram_percent || 90) + '"></label>' +
          '<label class="field"><span class="field-label">Alerte stockage / disque (%)</span>' +
          '<input type="number" step="any" data-mp="max_disk_percent" data-type="float" value="' + escapeHTML(p.max_disk_percent || 90) + '"></label>' +
          '<label class="field"><span class="field-label">Nœud Proxmox ciblé (optionnel)</span>' +
          '<input type="text" class="mono" data-mp="node" value="' + escapeHTML(p.node || "") + '" placeholder="Tous les nœuds si vide (ex. pve)"></label>' +
          '<label class="field span-2"><span class="field-label">Stockages spécifiques à surveiller (optionnel, séparés par des virgules)</span>' +
          '<input type="text" class="mono" data-mp="disks" data-type="csv" value="' + escapeHTML((p.disks || []).join(", ")) + '" placeholder="Ex. local-lvm, zfs-data"></label>' +
          '<div class="field span-2"><span class="field-label">Certificat HTTPS auto-signé Proxmox (port 8006)</span>' +
          '<label class="switch-control"><input type="checkbox" data-mp="insecure_skip_verify" data-type="bool"' + (insecureChecked ? " checked" : "") + '><span class="switch-track"></span><span class="switch-text">Accepter</span></label></div>';
        break;
      }

      case "windows_winrm": {
        if (p.insecure_skip_verify === undefined) p.insecure_skip_verify = true;
        if (!p.port) p.port = p.use_https ? 5986 : 5985;
        simpleHTML =
          '<div class="help-callout">Surveillance <strong>sans agent</strong> via WinRM (actif d\'origine sur Windows Server ; sur Windows 10/11 exécutez <span class="mono-inline">Enable-PSRemoting -Force</span> en PowerShell Administrateur). Les échanges HTTP 5985 sont chiffrés en NTLMv2 et les <strong>VM Hyper-V</strong> sont détectées automatiquement.</div>' +
          '<label class="field"><span class="field-label">Adresse IP ou nom Windows</span>' +
          '<input type="text" class="mono" data-mp="host" value="' + escapeHTML(p.host || "") + '" placeholder="192.168.1.40" required></label>' +
          '<label class="field"><span class="field-label">Nom d\'utilisateur</span>' +
          '<input type="text" class="mono" data-mp="user" value="' + escapeHTML(p.user || "") + '" placeholder="Administrator ou DOMAINE\\admin" required></label>' +
          '<div class="field span-2"><span class="field-label">Mot de passe</span>' +
          '<div class="input-with-action">' +
          '<input type="password" class="mono" id="mp-winrm-password" data-mp="password" autocomplete="off" value="' + escapeHTML(p.password || "") + '" placeholder="Mot de passe du compte Windows" required>' +
          '<button type="button" class="field-action" data-toggle-secret="mp-winrm-password">Afficher</button>' +
          "</div></div>" +
          '<label class="field span-2"><span class="field-label">VM Hyper-V critiques à vérifier (optionnel, séparées par des virgules)</span>' +
          '<input type="text" class="mono" data-mp="vms" data-type="csv" value="' + escapeHTML((p.vms || []).join(", ")) + '" placeholder="Ex. SRV-AD, DockerHost"></label>' +
          '<label class="field span-2"><span class="field-label">Services Windows critiques (optionnel, séparés par des virgules)</span>' +
          '<input type="text" class="mono" data-mp="services" data-type="csv" value="' + escapeHTML((p.services || []).join(", ")) + '" placeholder="Ex. W32Time, vmms"></label>';
        advHTML =
          '<label class="field"><span class="field-label">Alerte CPU (%)</span>' +
          '<input type="number" step="any" data-mp="max_cpu_percent" data-type="float" value="' + escapeHTML(p.max_cpu_percent || 90) + '"></label>' +
          '<label class="field"><span class="field-label">Alerte mémoire RAM (%)</span>' +
          '<input type="number" step="any" data-mp="max_ram_percent" data-type="float" value="' + escapeHTML(p.max_ram_percent || 90) + '"></label>' +
          '<label class="field"><span class="field-label">Alerte espace disque plein (%)</span>' +
          '<input type="number" step="any" data-mp="max_disk_percent" data-type="float" value="' + escapeHTML(p.max_disk_percent || 90) + '"></label>' +
          '<label class="field"><span class="field-label">Disques à suivre (optionnel)</span>' +
          '<input type="text" class="mono" data-mp="disks" data-type="csv" value="' + escapeHTML((p.disks || []).join(", ")) + '" placeholder="Ex. C:, D:"></label>' +
          '<label class="field"><span class="field-label">Domaine Windows / AD (optionnel)</span>' +
          '<input type="text" class="mono" data-mp="domain" value="' + escapeHTML(p.domain || "") + '" placeholder="WORKGROUP ou CORP"></label>' +
          '<label class="field"><span class="field-label">Port WinRM</span>' +
          '<input type="number" class="mono" id="mp-winrm-port" data-mp="port" data-type="int" value="' + escapeHTML(p.port || 5985) + '"></label>' +
          '<div class="field"><span class="field-label">Transport WinRM HTTPS (port 5986)</span>' +
          '<label class="switch-control"><input type="checkbox" id="mp-winrm-https" data-mp="use_https" data-type="bool"' + (p.use_https ? " checked" : "") + '><span class="switch-track"></span><span class="switch-text">HTTPS</span></label></div>' +
          '<div class="field"><span class="field-label">Certificat HTTPS auto-signé</span>' +
          '<label class="switch-control"><input type="checkbox" data-mp="insecure_skip_verify" data-type="bool"' + (p.insecure_skip_verify ? " checked" : "") + '><span class="switch-track"></span><span class="switch-text">Accepter</span></label></div>';
        break;
      }

      case "linux_ssh": {
        if (!p.port) p.port = 22;
        simpleHTML =
          '<div class="help-callout">Surveillance Linux <strong>sans aucun agent</strong> via SSH (CPU, RAM, disques montés et services <span class="mono-inline">systemd</span>).</div>' +
          '<label class="field"><span class="field-label">Adresse IP ou nom d\'hôte Linux</span>' +
          '<input type="text" class="mono" data-mp="host" value="' + escapeHTML(p.host || "") + '" placeholder="192.168.1.45" required></label>' +
          '<label class="field"><span class="field-label">Nom d\'utilisateur SSH</span>' +
          '<input type="text" class="mono" data-mp="user" value="' + escapeHTML(p.user || "") + '" placeholder="root, ubuntu, debian..." required></label>' +
          '<div class="field span-2"><span class="field-label">Mot de passe SSH (ou laissez vide si vous utilisez une clé privée dans Options avancées)</span>' +
          '<div class="input-with-action">' +
          '<input type="password" class="mono" id="mp-ssh-password" data-mp="password" autocomplete="off" value="' + escapeHTML(p.password || "") + '" placeholder="Mot de passe SSH">' +
          '<button type="button" class="field-action" data-toggle-secret="mp-ssh-password">Afficher</button>' +
          "</div></div>" +
          '<label class="field span-2"><span class="field-label">Services systemd critiques (optionnel, séparés par des virgules)</span>' +
          '<input type="text" class="mono" data-mp="services" data-type="csv" value="' + escapeHTML((p.services || []).join(", ")) + '" placeholder="Ex. docker, nginx, ssh"></label>';
        advHTML =
          '<label class="field"><span class="field-label">Port SSH</span>' +
          '<input type="number" class="mono" data-mp="port" data-type="int" value="' + escapeHTML(p.port || 22) + '"></label>' +
          '<label class="field"><span class="field-label">Alerte CPU (%)</span>' +
          '<input type="number" step="any" data-mp="max_cpu_percent" data-type="float" value="' + escapeHTML(p.max_cpu_percent || 90) + '"></label>' +
          '<label class="field"><span class="field-label">Alerte mémoire RAM (%)</span>' +
          '<input type="number" step="any" data-mp="max_ram_percent" data-type="float" value="' + escapeHTML(p.max_ram_percent || 90) + '"></label>' +
          '<label class="field"><span class="field-label">Alerte espace disque plein (%)</span>' +
          '<input type="number" step="any" data-mp="max_disk_percent" data-type="float" value="' + escapeHTML(p.max_disk_percent || 90) + '"></label>' +
          '<label class="field span-2"><span class="field-label">Points de montage à suivre (optionnel)</span>' +
          '<input type="text" class="mono" data-mp="disks" data-type="csv" value="' + escapeHTML((p.disks || []).join(", ")) + '" placeholder="Ex. /, /data"></label>' +
          '<label class="field span-2"><span class="field-label">Clé privée SSH PEM (optionnel, remplace le mot de passe)</span>' +
          '<textarea rows="3" class="mono" data-mp="ssh_key" spellcheck="false" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----">' + escapeHTML(p.ssh_key || "") + "</textarea></label>";
        break;
      }

      case "snmp_oid":
        simpleHTML =
          '<label class="field"><span class="field-label">Adresse IP de l\'appareil</span>' +
          '<input type="text" class="mono" data-mp="host" value="' + escapeHTML(p.host || "") + '" placeholder="192.168.1.50" required></label>' +
          '<label class="field"><span class="field-label">OID SNMP</span>' +
          '<input type="text" class="mono" data-mp="oid" value="' + escapeHTML(p.oid || "") + '" required></label>';
        advHTML =
          '<label class="field"><span class="field-label">Communauté SNMPv2c</span>' +
          '<input type="text" class="mono" data-mp="community" value="' + escapeHTML(p.community || "public") + '"></label>' +
          '<label class="field"><span class="field-label">Valeur attendue</span>' +
          '<input type="text" class="mono" data-mp="expected_value" value="' + escapeHTML(p.expected_value || "") + '"></label>' +
          '<label class="field"><span class="field-label">Seuil minimum</span>' +
          '<input type="number" step="any" data-mp="min_value" data-type="floatptr" value="' + escapeHTML(p.min_value != null ? p.min_value : "") + '"></label>' +
          '<label class="field"><span class="field-label">Seuil maximum</span>' +
          '<input type="number" step="any" data-mp="max_value" data-type="floatptr" value="' + escapeHTML(p.max_value != null ? p.max_value : "") + '"></label>';
        break;
    }

    const container = $("probe-modal-fields");
    container.innerHTML =
      '<div class="form-grid two-col">' +
      '<label class="field span-2"><span class="field-label">Nom affiché pour ce service</span>' +
      '<input type="text" data-mp="id" value="' + escapeHTML(p.id || "") + '" placeholder="Ex. NAS Salon, Jellyfin..." required></label>' +
      simpleHTML +
      "</div>" +
      '<details class="advanced-fold"><summary>Options avancées (fréquence, seuils)</summary>' +
      '<div class="form-grid two-col fold-body">' +
      '<label class="field"><span class="field-label">Fréquence de vérification</span>' +
      '<select id="mp-interval-select" data-mp="interval">' +
      '<option value="30s">Toutes les 30 secondes</option>' +
      '<option value="1m">Toutes les minutes</option>' +
      '<option value="2m">Toutes les 2 minutes</option>' +
      '<option value="5m">Toutes les 5 minutes</option>' +
      "</select></label>" +
      '<label class="field"><span class="field-label">Délai max de réponse</span>' +
      '<select id="mp-timeout-select" data-mp="timeout">' +
      '<option value="5s">5 secondes</option>' +
      '<option value="10s">10 secondes (recommandé)</option>' +
      '<option value="20s">20 secondes</option>' +
      "</select></label>" +
      advHTML +
      "</div></details>";

    normalizeDurationSelect($("mp-interval-select"), p.interval || "1m");
    normalizeDurationSelect($("mp-timeout-select"), p.timeout || "10s");

    const pveHost = $("mp-proxmox-host");
    if (pveHost) {
      pveHost.addEventListener("input", () => {
        state.modalProbeDraft.url = buildProxmoxURL(pveHost.value);
      });
    }

    const winrmHTTPS = $("mp-winrm-https");
    if (winrmHTTPS) {
      winrmHTTPS.addEventListener("change", () => {
        const portInput = $("mp-winrm-port");
        if (!portInput) return;
        const cur = Number(portInput.value || 0);
        if (!cur || cur === 5985 || cur === 5986) {
          const nextPort = winrmHTTPS.checked ? 5986 : 5985;
          portInput.value = String(nextPort);
          state.modalProbeDraft.port = nextPort;
        }
      });
    }

    container.querySelectorAll("[data-toggle-secret]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const input = $(btn.dataset.toggleSecret);
        if (!input) return;
        const hidden = input.type === "password";
        input.type = hidden ? "text" : "password";
        btn.textContent = hidden ? "Masquer" : "Afficher";
      });
    });

    const expHost = $("mp-exporter-host");
    if (expHost) {
      const defPort = p.kind === "node_exporter" ? 9100 : 9182;
      expHost.addEventListener("input", () => {
        state.modalProbeDraft.url = buildExporterURL(expHost.value, defPort);
      });
    }

    const tcpPreset = $("mp-tcp-preset");
    if (tcpPreset) {
      tcpPreset.addEventListener("change", () => {
        const wrap = $("mp-tcp-port-wrap");
        if (tcpPreset.value === "custom") {
          wrap.hidden = false;
        } else {
          wrap.hidden = true;
          state.modalProbeDraft.port = Number(tcpPreset.value);
          const portInput = container.querySelector('[data-mp="port"]');
          if (portInput) portInput.value = tcpPreset.value;
        }
      });
    }

    container.querySelectorAll("[data-mp]").forEach((el) => {
      const evt = el.tagName === "SELECT" || el.type === "checkbox" ? "change" : "input";
      el.addEventListener(evt, () => {
        const field = el.dataset.mp;
        const type = el.dataset.type || "string";
        if (type === "bool") state.modalProbeDraft[field] = el.checked;
        else if (type === "int") state.modalProbeDraft[field] = el.value === "" ? 0 : parseInt(el.value, 10) || 0;
        else if (type === "intptr") state.modalProbeDraft[field] = el.value === "" ? null : parseInt(el.value, 10);
        else if (type === "float") state.modalProbeDraft[field] = el.value === "" ? 0 : parseFloat(el.value) || 0;
        else if (type === "floatptr") state.modalProbeDraft[field] = el.value === "" ? null : parseFloat(el.value);
        else if (type === "csv") state.modalProbeDraft[field] = el.value.split(",").map((s) => s.trim()).filter(Boolean);
        else state.modalProbeDraft[field] = el.value;

        if (el.dataset.rerender === "1") renderProbeModalFields();
      });
    });
  }

  function syncProbeDraftFromModal() {
    const p = state.modalProbeDraft;
    if (!p) return null;
    const pveHost = $("mp-proxmox-host");
    if (pveHost) {
      p.url = buildProxmoxURL(pveHost.value);
    }
    const expHost = $("mp-exporter-host");
    if (expHost) {
      const defPort = p.kind === "node_exporter" ? 9100 : 9182;
      p.url = buildExporterURL(expHost.value, defPort);
    }
    p.id = String(p.id || "").trim() || ensureUniqueProbeID(slugifyID(p.kind, "service"), state.modalProbeIndex);
    return p;
  }

  async function runModalProbeTest() {
    const p = syncProbeDraftFromModal();
    if (!p) return;
    const btn = $("probe-modal-test");
    const box = $("probe-test-result");
    btn.disabled = true;
    btn.textContent = "Test en cours...";
    box.hidden = true;

    try {
      const { ok, data } = await apiFetch("/api/probes/test", {
        method: "POST",
        body: JSON.stringify({ probe: p })
      });
      box.hidden = false;
      box.className = "test-banner";
      if (!ok) {
        box.classList.add("is-err");
        box.textContent = "Vérifiez les paramètres : " + humanizeError(data.error || "configuration invalide");
        return;
      }
      if (data.ok) {
        box.classList.add("is-ok");
        box.textContent = "Connexion réussie (" + (data.latency_ms || 0) + " ms) · " + humanizeProbeSummary(data);
      } else {
        box.classList.add("is-err");
        box.textContent = "Échec du test : " + humanizeProbeSummary(data);
      }
    } catch (err) {
      box.hidden = false;
      box.className = "test-banner is-err";
      box.textContent = "Erreur : " + err.message;
    } finally {
      btn.disabled = false;
      btn.textContent = "Tester la connexion";
    }
  }

  async function submitProbeModal(e) {
    e.preventDefault();
    const p = syncProbeDraftFromModal();
    if (!p) return;

    if (!state.config.probes) state.config.probes = [];
    const prevProbes = deepClone(state.config.probes);

    if (state.modalProbeIndex >= 0) {
      state.config.probes[state.modalProbeIndex] = p;
    } else {
      p.id = ensureUniqueProbeID(p.id, -1);
      state.config.probes.push(p);
    }

    const saveBtn = $("probe-modal-save");
    saveBtn.disabled = true;
    saveBtn.textContent = "Enregistrement...";
    const ok = await saveConfiguration("« " + p.id + " » a été enregistré.");
    saveBtn.disabled = false;
    saveBtn.textContent = "Enregistrer";

    if (ok) {
      const cb = state.modalOnSaved;
      closeProbeModal();
      if (cb) cb();
      renderManagedProbes();
    } else {
      state.config.probes = prevProbes;
    }
  }

  /* ---------------- MES AMIS : INVITATION 1 CLIC ---------------- */

  function encodeInviteCode(payload) {
    const json = JSON.stringify(payload);
    const bytes = new TextEncoder().encode(json);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return "MW1-" + btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decodeInviteCode(raw) {
    const trimmed = String(raw || "").trim();
    if (!trimmed) return null;
    if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
      return { name: "", pubkey: trimmed.toLowerCase(), psk: "" };
    }
    if (!trimmed.startsWith("MW1-")) return null;
    try {
      let b64 = trimmed.slice(4).replace(/-/g, "+").replace(/_/g, "/");
      while (b64.length % 4) b64 += "=";
      const bin = atob(b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const obj = JSON.parse(new TextDecoder().decode(bytes));
      if (!obj || !/^[0-9a-fA-F]{64}$/.test(obj.pubkey || "")) return null;
      return {
        name: String(obj.name || "").trim(),
        pubkey: obj.pubkey.toLowerCase(),
        psk: /^[0-9a-fA-F]{64}$/.test(obj.psk || "") ? obj.psk.toLowerCase() : ""
      };
    } catch (_) {
      return null;
    }
  }

  function updateInviteCodeDisplay() {
    const input = $("my-invite-code");
    if (!input || !state.config) return;
    const pub = (state.status && state.status.pubkey_hex) || (state.config.node && state.config.node.pubkey_hex) || "";
    if (!pub) {
      input.value = "";
      return;
    }
    const payload = {
      name: (state.config.node && state.config.node.name) || "Mon Homelab",
      pubkey: pub
    };
    if ($("invite-include-group").checked && state.config.node && state.config.node.group_psk_hex) {
      payload.psk = state.config.node.group_psk_hex;
    }
    input.value = encodeInviteCode(payload);
  }

  function handleInviteInput() {
    const raw = $("friend-invite-input").value;
    const parsed = decodeInviteCode(raw);
    state.parsedInvite = parsed;
    const preview = $("friend-invite-preview");
    const addBtn = $("add-friend-from-invite-btn");

    if (!parsed) {
      preview.hidden = true;
      addBtn.disabled = true;
      return;
    }

    preview.hidden = false;
    addBtn.disabled = false;
    $("friend-invite-name").textContent = parsed.name
      ? "Invitation reconnue : " + parsed.name
      : "Clé publique reconnue (" + parsed.pubkey.slice(0, 12) + "...)";

    const currentPSK = (state.config && state.config.node && state.config.node.group_psk_hex) || "";
    const hasDifferentPSK = Boolean(parsed.psk && parsed.psk !== currentPSK.toLowerCase());
    const wrap = $("friend-join-group-wrap");
    const cb = $("friend-join-group");
    const label = $("friend-join-group-label");

    if (hasDifferentPSK) {
      wrap.hidden = false;
      const existingPeers = ((state.config && state.config.peers) || []).length;
      cb.checked = existingPeers === 0;
      label.textContent = existingPeers === 0
        ? "Rejoindre automatiquement son groupe privé chiffré (recommandé)"
        : "Remplacer mon groupe actuel par le sien (attention : vos autres amis devront utiliser le même)";
    } else {
      wrap.hidden = true;
      cb.checked = false;
    }
  }

  async function addFriendFromInvite() {
    const parsed = state.parsedInvite;
    if (!parsed || !state.config) return;

    const myPub = ((state.status && state.status.pubkey_hex) || (state.config.node && state.config.node.pubkey_hex) || "").toLowerCase();
    if (myPub && parsed.pubkey === myPub) {
      showToast("warn", "C'est votre propre code d'invitation ! Collez celui envoyé par votre ami.");
      return;
    }

    if (!state.config.peers) state.config.peers = [];
    if (state.config.peers.some((p) => (p.pubkey_hex || "").toLowerCase() === parsed.pubkey)) {
      showToast("warn", "Cet ami est déjà dans votre liste.");
      return;
    }

    const prevConfig = deepClone(state.config);
    const name = parsed.name || "Ami " + (state.config.peers.length + 1);
    state.config.peers.push({ name, pubkey_hex: parsed.pubkey });

    if (parsed.psk && $("friend-join-group").checked) {
      state.config.node.group_psk_hex = parsed.psk;
      $("cfg-psk").value = parsed.psk;
    }

    const ok = await saveConfiguration(name + " a été ajouté à vos amis.");
    if (ok) {
      $("friend-invite-input").value = "";
      state.parsedInvite = null;
      $("friend-invite-preview").hidden = true;
      $("add-friend-from-invite-btn").disabled = true;
      updateInviteCodeDisplay();
      renderPeersList();
    } else {
      state.config = prevConfig;
    }
  }

  function renderPeersList() {
    const peers = (state.config && state.config.peers) || [];
    $("peers-count-label").textContent = peers.length + (peers.length > 1 ? " amis" : " ami");
    const container = $("peers-list");

    if (!peers.length) {
      container.innerHTML =
        '<div class="empty-state">Aucun ami ajouté pour le moment. Partagez votre code d\'invitation ci-dessus ou collez celui d\'un proche.</div>';
      return;
    }

    const liveByPub = {};
    ((state.status && state.status.peers) || []).forEach((lp) => {
      liveByPub[(lp.pubkey_hex || "").toLowerCase()] = lp;
    });

    container.innerHTML = peers
      .map((p, idx) => {
        const live = liveByPub[(p.pubkey_hex || "").toLowerCase()];
        let cls = "is-muted";
        let stateLabel = "En attente de connexion";
        if (live) {
          if (live.timed_out) {
            cls = "is-err";
            stateLabel = "Hors ligne";
          } else if (live.online && !live.overall_ok) {
            cls = "is-warn";
            stateLabel = "Service en alerte";
          } else if (live.online) {
            cls = "is-ok";
            stateLabel = "En ligne";
          }
        }
        const sub = "Identifiant : " + (p.pubkey_hex || "").slice(0, 18) + "...";
        return (
          '<div class="surface-row">' +
          '<div class="row-main">' +
          '<div class="row-title-line">' +
          '<span class="status-cell ' + cls + '"><span class="status-dot ' + cls + '"></span>' + stateLabel + "</span>" +
          '<span class="row-title">' + escapeHTML(p.name || "Ami sans nom") + "</span>" +
          "</div>" +
          '<div class="row-sub">' + escapeHTML(sub) + "</div>" +
          "</div>" +
          '<div class="row-right">' +
          '<div class="row-actions">' +
          '<button type="button" class="inline-action" data-edit-peer="' + idx + '">Modifier</button>' +
          '<button type="button" class="inline-danger" data-remove-peer="' + idx + '">Retirer</button>' +
          "</div>" +
          "</div>" +
          "</div>"
        );
      })
      .join("");

    container.querySelectorAll("[data-edit-peer]").forEach((btn) => {
      btn.addEventListener("click", () => openFriendModal(Number(btn.dataset.editPeer)));
    });
    container.querySelectorAll("[data-remove-peer]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const idx = Number(btn.dataset.removePeer);
        const peer = state.config.peers[idx];
        if (!peer) return;
        if (!confirm("Retirer « " + peer.name + " » de vos amis ?")) return;
        const removed = state.config.peers.splice(idx, 1)[0];
        const ok = await saveConfiguration(removed.name + " a été retiré de vos amis.");
        if (!ok) state.config.peers.splice(idx, 0, removed);
        renderPeersList();
      });
    });
  }

  function openFriendModal(idx) {
    state.modalFriendIndex = idx;
    if (idx >= 0 && state.config.peers[idx]) {
      const p = state.config.peers[idx];
      $("friend-modal-title").textContent = "Modifier " + (p.name || "cet ami");
      $("fm-name").value = p.name || "";
      $("fm-pubkey").value = p.pubkey_hex || "";
    } else {
      $("friend-modal-title").textContent = "Ajouter un ami manuellement";
      $("fm-name").value = "";
      $("fm-pubkey").value = "";
    }
    $("friend-modal").hidden = false;
    $("fm-name").focus();
  }

  function closeFriendModal() {
    $("friend-modal").hidden = true;
    state.modalFriendIndex = -1;
  }

  async function submitFriendModal(e) {
    e.preventDefault();
    const entry = {
      name: $("fm-name").value.trim(),
      pubkey_hex: $("fm-pubkey").value.trim().toLowerCase()
    };
    if (!state.config.peers) state.config.peers = [];
    const prevPeers = deepClone(state.config.peers);
    if (state.modalFriendIndex >= 0) {
      state.config.peers[state.modalFriendIndex] = entry;
    } else {
      state.config.peers.push(entry);
    }

    const ok = await saveConfiguration(entry.name + " a été enregistré.");
    if (ok) {
      closeFriendModal();
      renderPeersList();
    } else {
      state.config.peers = prevPeers;
    }
  }

  /* ---------------- ALERTES ---------------- */

  function generateRandomNtfyChannel() {
    const bytes = new Uint8Array(6);
    crypto.getRandomValues(bytes);
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    const topic = "meshwatch-" + hex.slice(0, 6) + "-" + hex.slice(6);
    $("cfg-ntfy-url").value = "https://ntfy.sh/" + topic;
    $("cfg-ntfy-topic").value = "";
    $("cfg-ntfy-enabled").checked = true;
    $("ntfy-topic-hint").textContent = "Abonnez-vous au canal « " + topic + " » dans l'application ntfy sur votre téléphone.";
    setDirty(true);
    showToast("ok", "Canal privé créé : « " + topic + " ». Cliquez sur Enregistrer puis Testez.");
  }

  async function runTestNotify() {
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
        showToast("err", data.error || "Activez au moins ntfy ou Photon avant de tester.");
        out.hidden = true;
        return;
      }
      out.innerHTML = (data.results || [])
        .map((r) => {
          const cls = r.ok ? "is-ok" : "is-err";
          const label = r.ok ? "Envoyé (" + r.latency_ms + " ms)" : "Échec : " + humanizeError(r.error);
          return (
            '<div class="test-output-line">' +
            '<span class="row-title">' + escapeHTML(r.channel === "ntfy" ? "Téléphone (ntfy)" : "iMessage (Photon)") + "</span>" +
            '<span class="status-cell ' + cls + '"><span class="status-dot ' + cls + '"></span>' + escapeHTML(label) + "</span>" +
            "</div>"
          );
        })
        .join("");
      out.hidden = false;
      showToast(data.ok ? "ok" : "warn", data.ok ? "Alerte de test envoyée sur votre téléphone." : "Certains canaux ont échoué.");
    } catch (err) {
      showToast("err", err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Envoyer une alerte de test";
    }
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
        $("settings-update-detail").textContent = data.error || "Impossible de vérifier les mises à jour.";
        $("settings-update-btn").hidden = true;
        $("nav-update-dot").hidden = true;
        return;
      }
      state.updateInfo = data;
      renderUpdateState(data);
    } catch (_) {
    } finally {
      if (btn && force) {
        btn.disabled = false;
        btn.textContent = "Vérifier";
      }
    }
  }

  function renderUpdateState(info) {
    $("settings-version-label").textContent =
      (info.current_version || "dev") + (info.current_commit ? " (" + info.current_commit + ")" : "");

    const banner = $("update-banner");
    const settingsBtn = $("settings-update-btn");
    const navDot = $("nav-update-dot");

    navDot.hidden = !info.update_available;

    if (info.update_available) {
      banner.hidden = false;
      $("update-banner-title").textContent = "Nouvelle version disponible : " + info.latest_version;
      $("update-banner-desc").textContent =
        info.release_name || "Des améliorations et correctifs sont prêts à être installés en un clic.";
      $("update-now-btn").textContent = info.can_auto_update ? "Mettre à jour maintenant" : "Voir la mise à jour";

      $("settings-update-headline").textContent = "Version " + info.latest_version + " disponible";
      $("settings-update-detail").textContent = info.can_auto_update
        ? (info.release_name || "Cliquez sur Mettre à jour maintenant pour installer la nouvelle version automatiquement.")
        : (info.auto_update_reason || "Mise à jour manuelle disponible sur GitHub.");
      settingsBtn.hidden = false;
      settingsBtn.textContent = info.can_auto_update ? "Mettre à jour maintenant" : "Ouvrir sur GitHub";
    } else if (info.building) {
      banner.hidden = true;
      $("settings-update-headline").textContent = "Nouvelle version en cours de préparation";
      $("settings-update-detail").textContent =
        "Une image Docker est en cours de compilation (prête dans environ 1 minute). Cliquez sur Vérifier juste après.";
      settingsBtn.hidden = true;
    } else {
      banner.hidden = true;
      $("settings-update-headline").textContent = "Votre MeshWatch est à jour";
      const suffix = info.auto_update_reason ? " (" + info.auto_update_reason + ")" : "";
      $("settings-update-detail").textContent =
        "Dernière version publiée : " + (info.latest_version || info.current_version) + "." + suffix;
      settingsBtn.hidden = true;
    }
  }

  async function triggerUpdate() {
    const info = state.updateInfo;
    if (!info) return;
    if (!info.can_auto_update) {
      if (info.release_url) window.open(info.release_url, "_blank", "noopener");
      showToast("warn", info.auto_update_reason || "Lancez docker compose pull && docker compose up -d.");
      return;
    }

    if (!confirm("Installer la version " + info.latest_version + " et redémarrer MeshWatch maintenant ?")) {
      return;
    }

    $("updating-overlay").hidden = false;
    $("updating-message").textContent =
      "Téléchargement de l'image " + info.image + " et redémarrage automatique. Ne fermez pas cette page...";

    const prevVersion = (info.current_version || "") + ":" + (info.current_commit || "");
    const prevStartedAt = (state.status && state.status.started_at) || "";
    const targetCommit = info.latest_commit || "";

    try {
      const { ok, data } = await apiFetch("/api/update/apply", {
        method: "POST",
        body: JSON.stringify({ image: info.image })
      });
      if (!ok) {
        $("updating-overlay").hidden = true;
        showToast("err", "Mise à jour impossible : " + (data.error || "vérifiez l'accès au socket Docker"));
        return;
      }

      $("updating-message").textContent =
        "Redémarrage sur la version " + info.latest_version + "... Reconnexion automatique dès qu'elle est prête.";

      let sawDisconnect = false;
      const started = Date.now();
      const pollReconnect = async () => {
        if (Date.now() - started > 150000) {
          $("updating-overlay").hidden = true;
          showToast("warn", "Le redémarrage prend plus de temps que prévu. Actualisez la page.");
          return;
        }
        try {
          const r = await apiFetch("/api/status?t=" + Date.now());
          if (r.ok && r.data) {
            const curVer = (r.data.version || "") + ":" + (r.data.commit || "");
            const curStartedAt = r.data.started_at || "";
            const commitMatched = targetCommit && r.data.commit && r.data.commit.startsWith(targetCommit);
            const restarted =
              commitMatched ||
              (curVer !== prevVersion) ||
              (prevStartedAt && curStartedAt && curStartedAt !== prevStartedAt) ||
              (sawDisconnect && (r.data.uptime_sec || 0) < 30);

            if (restarted) {
              window.location.replace(window.location.pathname + "?v=" + Date.now());
              return;
            }
          }
        } catch (_) {
          sawDisconnect = true;
        }
        setTimeout(pollReconnect, 1500);
      };
      setTimeout(pollReconnect, 2500);
    } catch (err) {
      $("updating-overlay").hidden = true;
      showToast("err", "Erreur de mise à jour : " + err.message);
    }
  }

  /* ---------------- CONFIG FORMS & BACKUP ---------------- */

  function populateFormsFromConfig() {
    const cfg = state.config;
    if (!cfg) return;

    $("cfg-node-name").value = cfg.node.name || "";
    normalizeDurationSelect($("cfg-hb-interval"), cfg.node.heartbeat_interval || "30s");
    normalizeDurationSelect($("cfg-peer-timeout"), cfg.node.peer_timeout || "1m30s");
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
    const pMode = inferPhotonMode(photon);
    $("cfg-photon-mode").value = pMode;
    syncPhotonModeVisibility(pMode);

    $("cfg-photon-project-id").value = photon.project_id || "";
    $("cfg-photon-api-key").value = photon.api_key || (pMode === "cloud" ? photon.token || "" : "");
    $("cfg-photon-recipient").value = photon.recipient || "";
    $("cfg-photon-cloud-url").value = pMode === "cloud" ? (photon.url || "") : "";
    $("cfg-photon-sender-id").value = photon.sender_id || "";
    $("cfg-photon-space-id").value = photon.space_id || "";

    $("cfg-photon-server-url").value = photon.server_url || "";
    $("cfg-photon-proxy-key").value = pMode === "proxy" ? (photon.api_key || "") : "";
    $("cfg-photon-proxy-recipient").value = photon.recipient || "";
    $("cfg-photon-proxy-url").value = pMode === "proxy" ? (photon.url || "https://imessage-swagger.photon.codes") : "https://imessage-swagger.photon.codes";
    $("cfg-photon-proxy-token").value = pMode === "proxy" ? (photon.token || "") : "";

    $("cfg-photon-url").value = pMode === "custom" ? (photon.url || "") : "";
    $("cfg-photon-custom-recipient").value = photon.recipient || "";
    $("cfg-photon-token").value = pMode === "custom" ? (photon.token || "") : "";
    $("cfg-photon-rec-field").value = photon.recipient_field || "recipient";
    $("cfg-photon-msg-field").value = photon.message_field || "message";

    const storageBadge = $("settings-storage-status");
    const storageDesc = $("settings-storage-desc");
    if (state.writable) {
      storageBadge.className = "status-cell is-ok";
      storageBadge.innerHTML = '<span class="status-dot is-ok"></span>Enregistrement automatique actif';
      storageDesc.textContent =
        "Toutes vos modifications sont enregistrées automatiquement sur votre serveur. Vous pouvez aussi exporter une copie de secours ou restaurer une sauvegarde en un clic.";
    } else {
      storageBadge.className = "status-cell is-warn";
      storageBadge.innerHTML = '<span class="status-dot is-warn"></span>Stockage en lecture seule';
      storageDesc.textContent =
        "Le volume de configuration Docker est monté en lecture seule (:ro). Retirez :ro sur config.yaml dans docker-compose.yml pour rendre vos modifications permanentes après redémarrage.";
    }

    updateInviteCodeDisplay();
    renderPeersList();
    renderManagedProbes();
  }

  function inferPhotonMode(ph) {
    if (!ph) return "cloud";
    const m = String(ph.mode || "").toLowerCase().trim();
    if (m === "cloud" || m === "spectrum" || m === "proxy" || m === "custom") {
      return m === "spectrum" ? "cloud" : m;
    }
    if (ph.project_id || String(ph.api_key || "").startsWith("pho_") || String(ph.url || "").includes("api.photon.codes") || String(ph.url || "").includes("spectrum.photon.codes")) {
      return "cloud";
    }
    if (ph.server_url || String(ph.url || "").includes("imessage-swagger.photon.codes")) {
      return "proxy";
    }
    if (ph.url && ph.recipient) return "custom";
    return "cloud";
  }

  function syncPhotonModeVisibility(mode) {
    $("photon-mode-cloud").hidden = mode !== "cloud";
    $("photon-mode-proxy").hidden = mode !== "proxy";
    $("photon-mode-custom").hidden = mode !== "custom";
  }

  function readPhotonFields() {
    const mode = $("cfg-photon-mode").value || "cloud";
    const enabled = $("cfg-photon-enabled").checked;
    if (mode === "cloud") {
      return {
        enabled,
        mode: "cloud",
        url: $("cfg-photon-cloud-url").value.trim(),
        project_id: $("cfg-photon-project-id").value.trim(),
        api_key: $("cfg-photon-api-key").value.trim(),
        recipient: $("cfg-photon-recipient").value.trim(),
        sender_id: $("cfg-photon-sender-id").value.trim(),
        space_id: $("cfg-photon-space-id").value.trim()
      };
    }
    if (mode === "proxy") {
      return {
        enabled,
        mode: "proxy",
        url: $("cfg-photon-proxy-url").value.trim() || "https://imessage-swagger.photon.codes",
        server_url: $("cfg-photon-server-url").value.trim(),
        api_key: $("cfg-photon-proxy-key").value.trim(),
        token: $("cfg-photon-proxy-token").value.trim(),
        recipient: $("cfg-photon-proxy-recipient").value.trim()
      };
    }
    return {
      enabled,
      mode: "custom",
      url: $("cfg-photon-url").value.trim(),
      recipient: $("cfg-photon-custom-recipient").value.trim(),
      token: $("cfg-photon-token").value.trim(),
      recipient_field: $("cfg-photon-rec-field").value.trim() || "recipient",
      message_field: $("cfg-photon-msg-field").value.trim() || "message"
    };
  }

  function readGeneralFieldsIntoConfig() {
    const cfg = state.config;
    if (!cfg) return;
    cfg.node.name = $("cfg-node-name").value.trim() || "mon-homelab";
    cfg.node.heartbeat_interval = $("cfg-hb-interval").value || "30s";
    cfg.node.peer_timeout = $("cfg-peer-timeout").value || "1m30s";
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
      photon_imessage: readPhotonFields()
    };
  }

  async function saveConfiguration(customSuccessMsg) {
    readGeneralFieldsIntoConfig();
    const saveBtn = $("save-btn");
    if (saveBtn) {
      saveBtn.disabled = true;
      saveBtn.textContent = "Enregistrement...";
    }

    try {
      const { ok, data } = await apiFetch("/api/config", {
        method: "PUT",
        body: JSON.stringify({ config: state.config })
      });
      if (!ok) {
        const msg = (data.errors && data.errors.join(" · ")) || data.error || "Paramètres invalides";
        showToast("err", "Impossible d'enregistrer : " + msg);
        return false;
      }

      state.config = data.config;
      state.savedConfigSnapshot = deepClone(data.config);
      state.rawYAML = data.yaml || "";
      state.writable = Boolean(data.persisted);
      setDirty(false);
      populateFormsFromConfig();

      if (data.persisted) {
        showToast("ok", customSuccessMsg || "Modifications enregistrées et actives.");
      } else {
        showToast(
          "warn",
          "Activé immédiatement (le volume Docker est en lecture seule : retirez :ro dans docker-compose.yml pour conserver après redémarrage).",
          7500
        );
      }
      await fetchStatus();
      return true;
    } catch (err) {
      showToast("err", "Erreur d'enregistrement : " + err.message);
      return false;
    } finally {
      if (saveBtn) {
        saveBtn.disabled = false;
        saveBtn.textContent = "Enregistrer maintenant";
      }
    }
  }

  async function runQuickSetup() {
    const btn = $("quick-setup-btn");
    btn.disabled = true;
    btn.textContent = "Démarrage...";
    try {
      const { ok, data } = await apiFetch("/api/keygen", { method: "POST", body: "{}" });
      if (!ok) {
        showToast("err", data.error || "Impossible de créer votre identité.");
        return;
      }
      const chosenName = ($("setup-node-name").value || "").trim() || "mon-homelab";
      state.config.node.name = chosenName;
      state.config.node.private_key_hex = data.private_key_hex;
      state.config.node.pubkey_hex = data.pubkey_hex;
      state.config.node.group_psk_hex = data.group_psk_hex;
      $("cfg-node-name").value = chosenName;
      $("cfg-privkey").value = data.private_key_hex;
      $("cfg-psk").value = data.group_psk_hex;
      $("id-pubkey").value = data.pubkey_hex;
      $("id-topic-tag").value = data.topic_tag;

      await saveConfiguration("MeshWatch est démarré et prêt !");
    } catch (err) {
      showToast("err", err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Démarrer en un clic";
    }
  }

  async function runRegenerateKeys() {
    if (!confirm("Générer une nouvelle identité ? Vos amis devront recevoir votre nouveau code d'invitation.")) return;
    try {
      const { ok, data } = await apiFetch("/api/keygen", { method: "POST", body: "{}" });
      if (!ok) {
        showToast("err", data.error || "Impossible de générer les clés");
        return;
      }
      state.config.node.private_key_hex = data.private_key_hex;
      state.config.node.pubkey_hex = data.pubkey_hex;
      if (confirm("Créer aussi une nouvelle clé secrète de groupe ? Annulez pour rester dans le groupe actuel.")) {
        state.config.node.group_psk_hex = data.group_psk_hex;
      }
      $("cfg-privkey").value = state.config.node.private_key_hex;
      $("cfg-psk").value = state.config.node.group_psk_hex;
      $("id-pubkey").value = data.pubkey_hex;
      $("id-topic-tag").value = data.topic_tag;
      await saveConfiguration("Nouvelles clés enregistrées.");
    } catch (err) {
      showToast("err", err.message);
    }
  }

  async function runCheckWAN() {
    const btn = $("check-wan-btn");
    btn.disabled = true;
    btn.textContent = "Vérification...";
    try {
      const { ok, data } = await apiFetch("/api/check-automute", { method: "POST", body: "{}" });
      if (!ok) {
        showToast("warn", data.error || "Vérification impossible.");
        return;
      }
      showToast(
        data.muted ? "warn" : "ok",
        data.muted ? "Internet semble coupé : alertes mises en pause." : "Accès Internet opérationnel."
      );
      await fetchStatus();
    } catch (err) {
      showToast("err", err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Vérifier";
    }
  }

  function exportBackup() {
    const content = state.rawYAML || "";
    if (!content) {
      showToast("warn", "Aucune configuration à exporter.");
      return;
    }
    const blob = new Blob([content], { type: "text/yaml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "meshwatch-sauvegarde.yaml";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast("ok", "Sauvegarde exportée.");
  }

  async function importBackupFile(file) {
    if (!file) return;
    try {
      const text = await file.text();
      const { ok, data } = await apiFetch("/api/config", {
        method: "PUT",
        body: JSON.stringify({ yaml: text })
      });
      if (!ok) {
        const msg = (data.errors && data.errors.join(" · ")) || data.error || "Fichier de sauvegarde invalide";
        showToast("err", "Restauration impossible : " + msg);
        return;
      }
      state.config = data.config;
      state.savedConfigSnapshot = deepClone(data.config);
      state.rawYAML = data.yaml || text;
      setDirty(false);
      populateFormsFromConfig();
      await fetchStatus();
      showToast("ok", "Sauvegarde restaurée et activée.");
    } catch (err) {
      showToast("err", "Erreur lors de la restauration : " + err.message);
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
      state.savedConfigSnapshot = deepClone(cfgRes.data.config);
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

    $("home-add-device-btn").addEventListener("click", () => switchTab("discover"));
    $("run-all-probes-btn").addEventListener("click", runAllProbesNow);
    $("dismiss-onboarding-btn").addEventListener("click", () => {
      state.onboardingDismissed = true;
      localStorage.setItem("mw_hide_onboarding", "1");
      $("onboarding-card").hidden = true;
    });

    $("save-btn").addEventListener("click", () => saveConfiguration());
    $("save-alerts-btn").addEventListener("click", () => saveConfiguration("Réglages des alertes enregistrés."));
    $("save-settings-btn").addEventListener("click", () => saveConfiguration("Réglages enregistrés."));
    $("discard-changes-btn").addEventListener("click", () => {
      if (state.savedConfigSnapshot) {
        state.config = deepClone(state.savedConfigSnapshot);
        populateFormsFromConfig();
      }
      setDirty(false);
      showToast("ok", "Modifications annulées.");
    });

    $("quick-setup-btn").addEventListener("click", runQuickSetup);
    $("keygen-btn").addEventListener("click", runRegenerateKeys);
    $("test-notify-btn").addEventListener("click", runTestNotify);
    $("generate-ntfy-btn").addEventListener("click", generateRandomNtfyChannel);
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

    $("open-add-probe-btn").addEventListener("click", () => openProbeModal(-1));
    $("probe-modal-close").addEventListener("click", closeProbeModal);
    $("probe-modal-back").addEventListener("click", () => {
      $("probe-modal-picker").hidden = false;
      $("probe-modal-form").hidden = true;
      $("probe-modal-title").textContent = "Ajouter un appareil ou service";
      $("probe-modal-subtitle").textContent = "Choisissez simplement ce que vous souhaitez surveiller.";
    });
    $("probe-modal-test").addEventListener("click", runModalProbeTest);
    $("probe-modal-form").addEventListener("submit", submitProbeModal);
    document.querySelectorAll("[data-pick-kind]").forEach((btn) => {
      btn.addEventListener("click", () => pickProbeKindInModal(btn.dataset.pickKind));
    });

    $("invite-include-group").addEventListener("change", updateInviteCodeDisplay);
    $("my-invite-code").addEventListener("click", (e) => e.target.select());
    $("copy-invite-btn").addEventListener("click", async () => {
      const btn = $("copy-invite-btn");
      const input = $("my-invite-code");
      const code = input.value;
      if (!code) {
        showToast("warn", "Démarrez d'abord votre installation pour obtenir un code d'invitation.");
        return;
      }
      const ok = await copyTextToClipboard(code, input);
      if (ok) {
        const prev = btn.textContent;
        btn.textContent = "Copié !";
        setTimeout(() => {
          btn.textContent = prev;
        }, 1800);
        showToast("ok", "Code d'invitation copié ! Envoyez-le à votre ami.");
      } else {
        showToast("warn", "Code sélectionné : appuyez sur Ctrl+C (ou Cmd+C) pour le copier.");
      }
    });
    $("friend-invite-input").addEventListener("input", handleInviteInput);
    $("add-friend-from-invite-btn").addEventListener("click", addFriendFromInvite);
    $("add-friend-manual-btn").addEventListener("click", () => openFriendModal(-1));
    $("friend-modal-close").addEventListener("click", closeFriendModal);
    $("friend-modal-cancel").addEventListener("click", closeFriendModal);
    $("friend-modal-form").addEventListener("submit", submitFriendModal);

    $("check-update-btn").addEventListener("click", () => checkUpdates(true));
    $("update-now-btn").addEventListener("click", triggerUpdate);
    $("settings-update-btn").addEventListener("click", triggerUpdate);
    $("export-backup-btn").addEventListener("click", exportBackup);
    $("import-backup-btn").addEventListener("click", () => $("import-backup-file").click());
    $("import-backup-file").addEventListener("change", (e) => {
      const file = e.target.files && e.target.files[0];
      if (file) importBackupFile(file);
      e.target.value = "";
    });

    $("cfg-photon-mode").addEventListener("change", () => {
      syncPhotonModeVisibility($("cfg-photon-mode").value);
      setDirty(true);
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
      "cfg-photon-project-id",
      "cfg-photon-api-key",
      "cfg-photon-recipient",
      "cfg-photon-cloud-url",
      "cfg-photon-sender-id",
      "cfg-photon-space-id",
      "cfg-photon-server-url",
      "cfg-photon-proxy-key",
      "cfg-photon-proxy-recipient",
      "cfg-photon-proxy-url",
      "cfg-photon-proxy-token",
      "cfg-photon-url",
      "cfg-photon-custom-recipient",
      "cfg-photon-token",
      "cfg-photon-rec-field",
      "cfg-photon-msg-field"
    ].forEach((id) => {
      const el = $(id);
      if (!el) return;
      const evt = el.tagName === "SELECT" || el.type === "checkbox" ? "change" : "input";
      el.addEventListener(evt, () => setDirty(true));
    });

    document.querySelectorAll("[data-copy]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const input = $(btn.dataset.copy);
        if (!input || !input.value) return;
        const ok = await copyTextToClipboard(input.value, input);
        if (ok) {
          const prev = btn.textContent;
          btn.textContent = "Copié !";
          setTimeout(() => {
            btn.textContent = prev;
          }, 1600);
          showToast("ok", "Copié dans le presse-papiers.");
        } else {
          showToast("warn", "Sélectionné : appuyez sur Ctrl+C (ou Cmd+C) pour copier.");
        }
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

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        if (!$("probe-modal").hidden) closeProbeModal();
        if (!$("friend-modal").hidden) closeFriendModal();
      }
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
      showToast("err", "Impossible de joindre MeshWatch : " + err.message);
    }
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
