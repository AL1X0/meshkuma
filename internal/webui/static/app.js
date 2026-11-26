(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const MW = () => window.MWViz || {};

  const STORAGE = {
    theme: "mw_theme",
    token: "mw_ui_token",
    subtab: "mw_discover_subtab",
    selectedProbe: "mw_selected_probe",
    inspTab: "mw_insp_tab"
  };

  const PROBE_KINDS = {
    http: { label: "HTTP / HTTPS", badge: "HTTP", host: false },
    tcp: { label: "Port TCP", badge: "TCP", host: false },
    docker: { label: "Docker", badge: "DOCKER", host: false },
    synology: { label: "Synology SNMP", badge: "SYNOLOGY", host: true },
    proxmox: { label: "Proxmox VE", badge: "PROXMOX", host: true },
    windows_winrm: { label: "Windows WinRM", badge: "WINDOWS", host: true },
    linux_ssh: { label: "Linux SSH", badge: "LINUX", host: true },
    snmp_oid: { label: "SNMP OID", badge: "SNMP", host: false },
    node_exporter: { label: "Node Exporter", badge: "LINUX EXP", host: true },
    windows_exporter: { label: "Windows Exporter", badge: "WIN EXP", host: true }
  };

  const PROBE_GUIDES = {
    proxmox: "Dans Proxmox VE : Datacenter → Permissions → API Tokens → Add (ex. root@pam!meshwatch), décochez Privilege Separation ou accordez le rôle PVEAuditor sur /. Renseignez Token ID et Secret.",
    synology: "Dans Synology DSM : Panneau de configuration → Terminal et SNMP → Activer le service SNMP (v2c recommandé en LAN, ou SNMPv3 chiffré). Port UDP 161 par défaut.",
    windows_winrm: "Activez WinRM sur Windows/Hyper-V : exécutez « winrm quickconfig » puis « Enable-PSRemoting -Force » en PowerShell admin. Pour HTTP LAN sans TLS : « winrm set winrm/config/service @{AllowUnencrypted=\"true\"} » et Auth Basic.",
    linux_ssh: "Sous Linux : indiquez l'utilisateur SSH et un mot de passe ou une clé privée PEM/OpenSSH (lecture seule : /proc/stat, /proc/meminfo, df, systemctl).",
    docker: "Surveille l'état et la santé de vos conteneurs locaux via /var/run/docker.sock monté en lecture seule dans MeshWatch."
  };

  function loadStoredToken() {
    try {
      return (localStorage.getItem(STORAGE.token) || sessionStorage.getItem(STORAGE.token) || "").trim();
    } catch {
      return "";
    }
  }

  function persistToken(tok) {
    const clean = String(tok || "").trim();
    try {
      if (clean) {
        localStorage.setItem(STORAGE.token, clean);
        sessionStorage.setItem(STORAGE.token, clean);
      } else {
        localStorage.removeItem(STORAGE.token);
        sessionStorage.removeItem(STORAGE.token);
      }
    } catch {
      /* ignore storage errors in restricted contexts */
    }
  }

  const state = {
    tab: "home",
    discoverSubtab: localStorage.getItem(STORAGE.subtab) || "docker",
    theme: localStorage.getItem(STORAGE.theme) || "dark",
    token: loadStoredToken(),
    status: null,
    config: null,
    draft: null,
    rawYAML: "",
    updateInfo: null,
    dockerContainers: [],
    lanItems: [],
    lanScanned: false,
    fleetFilter: "all",
    fleetSearch: "",
    fleetSort: "status",
    selectedProbeID: localStorage.getItem(STORAGE.selectedProbe) || "",
    inspectorTab: localStorage.getItem(STORAGE.inspTab) || "overview",
    editingIndex: -1,
    modalKind: "http",
    dirty: false,
    ledBusyUntil: 0,
    ledBusyMode: "orbit",
    ledBusyLabel: "",
    ledBusySub: "",
    paletteOpen: false,
    paletteItems: [],
    paletteIndex: 0,
    keySeq: "",
    keySeqTimer: null,
    statusTimer: null,
    toastTimer: null,
    updatePollTimer: null
  };

  /* -------------------- Utilities -------------------- */

  function esc(val) {
    return String(val == null ? "" : val)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function clone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  function ensureDraftShape(cfg) {
    const d = cfg && typeof cfg === "object" ? clone(cfg) : {};
    if (!d.node || typeof d.node !== "object") {
      d.node = {
        name: "mon-homelab",
        private_key_hex: "",
        group_psk_hex: "",
        heartbeat_interval: "30s",
        peer_timeout: "1m30s"
      };
    }
    if (!d.logging || typeof d.logging !== "object") {
      d.logging = { level: "info", format: "text" };
    }
    if (!d.nostr || typeof d.nostr !== "object") {
      d.nostr = { relays: ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"] };
    }
    if (!Array.isArray(d.nostr.relays)) d.nostr.relays = [];
    if (!d.auto_mute || typeof d.auto_mute !== "object") {
      d.auto_mute = { targets: ["1.1.1.1:443", "9.9.9.9:443"], timeout: "3s" };
    }
    if (!Array.isArray(d.auto_mute.targets)) d.auto_mute.targets = [];
    if (!Array.isArray(d.peers)) d.peers = [];
    if (!Array.isArray(d.probes)) d.probes = [];
    if (!d.notifications || typeof d.notifications !== "object") d.notifications = {};
    if (!d.notifications.ntfy || typeof d.notifications.ntfy !== "object") d.notifications.ntfy = { enabled: false };
    if (!d.notifications.photon_imessage || typeof d.notifications.photon_imessage !== "object") {
      d.notifications.photon_imessage = { enabled: false, mode: "cloud" };
    }
    return d;
  }

  function showToast(msg, tone = "ok") {
    const el = $("toast-bar");
    if (!el) return;
    el.textContent = msg;
    el.className = "toast-bar" + (tone === "err" ? " is-err" : tone === "warn" ? " is-warn" : " is-ok");
    el.hidden = false;
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => {
      el.hidden = true;
    }, 3800);
  }

  function fmtUptime(sec) {
    const s = Math.max(0, Math.floor(Number(sec) || 0));
    if (!s) return "—";
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return d + "j " + h + "h";
    if (h > 0) return h + "h " + m + "m";
    return m + "m " + (s % 60) + "s";
  }

  function fmtAge(tsSec) {
    if (!tsSec) return "jamais";
    const diff = Math.max(0, Math.round(Date.now() / 1000 - tsSec));
    if (diff < 60) return "il y a " + diff + "s";
    if (diff < 3600) return "il y a " + Math.floor(diff / 60) + "m";
    if (diff < 86400) return "il y a " + Math.floor(diff / 3600) + "h";
    return "il y a " + Math.floor(diff / 86400) + "j";
  }

  function fmtTime(tsSec) {
    if (!tsSec) return "—";
    return new Date(tsSec * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function fmtMB(mb) {
    const v = Number(mb) || 0;
    if (v >= 1024) return (v / 1024).toFixed(1) + " Go";
    return Math.round(v) + " Mo";
  }

  function splitCSV(text) {
    return String(text || "")
      .split(/[,\n]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function splitLines(text) {
    return String(text || "")
      .split(/\r?\n+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function splitHostPort(raw, defaultPort) {
    const s = String(raw || "").trim();
    if (!s) return { host: "", port: defaultPort };
    const idx = s.lastIndexOf(":");
    if (idx > 0 && /^\d+$/.test(s.slice(idx + 1))) {
      return { host: s.slice(0, idx), port: Number(s.slice(idx + 1)) || defaultPort };
    }
    return { host: s, port: defaultPort };
  }

  function isHostKind(kind) {
    return Boolean(PROBE_KINDS[kind]?.host);
  }

  function probeTargetLabel(p) {
    if (!p) return "—";
    if (p.url) return p.url;
    if (p.address) return p.address;
    if (p.host) {
      const base = p.port ? p.host + ":" + p.port : p.host;
      return p.oid ? base + " · " + p.oid : base;
    }
    if (p.kind === "docker") {
      return p.containers && p.containers.length ? p.containers.join(", ") : p.socket || "Docker local";
    }
    return PROBE_KINDS[p.kind]?.label || p.kind || "—";
  }

  /* -------------------- Theme & Hardware LED State -------------------- */

  function applyTheme(theme) {
    const next = theme === "light" ? "light" : "dark";
    state.theme = next;
    localStorage.setItem(STORAGE.theme, next);
    document.documentElement.setAttribute("data-theme", next);
    const dk = $("theme-dark-btn");
    const lt = $("theme-light-btn");
    if (dk) dk.classList.toggle("is-active", next === "dark");
    if (lt) lt.classList.toggle("is-active", next === "light");
    if (state.status) renderTopologyAndInspectorCharts();
  }

  function triggerLEDBusy(mode, label, sub, durationMs = 2800) {
    state.ledBusyMode = mode;
    state.ledBusyLabel = label;
    state.ledBusySub = sub || "";
    state.ledBusyUntil = Date.now() + durationMs;
    syncHeroAndStatusLED();
    setTimeout(() => {
      if (Date.now() >= state.ledBusyUntil) syncHeroAndStatusLED();
    }, durationMs + 60);
  }

  function syncHeroAndStatusLED() {
    const st = state.status;
    const pill = $("hero-led-pill");
    const canvas = $("hero-led-canvas");
    const label = $("hero-led-label");
    const sub = $("hero-led-sub");
    const sCanvas = $("status-led-canvas");
    const sText = $("status-live-text");

    let mode = "radar";
    let color = "ok";
    let tone = "ok";
    let text = "Veille active";
    let subTxt = "NOMINAL · E2E";

    if (Date.now() < state.ledBusyUntil) {
      mode = state.ledBusyMode || "orbit";
      color = "orange";
      tone = "orange";
      text = state.ledBusyLabel || "Analyse en cours";
      subTxt = state.ledBusySub || "ACTIF";
    } else if (st) {
      const hasDown = (st.probes || []).some((p) => !p.ok) || (st.peers || []).some((p) => p.timed_out || (p.online && !p.overall_ok));
      if (st.mode === "setup") {
        mode = "wave";
        color = "warn";
        tone = "warn";
        text = "Initialisation requise";
        subTxt = "CLÉS NOSTR";
      } else if (st.muted) {
        mode = "idle";
        color = "muted";
        tone = "muted";
        text = "Auto-mute actif";
        subTxt = "PERTE FAI LOCALE";
      } else if (hasDown || !st.overall_ok) {
        mode = "cross";
        color = "danger";
        tone = "danger";
        text = "Incident détecté";
        subTxt = "ALERTE ACTIVE";
      } else {
        mode = "radar";
        color = "ok";
        tone = "ok";
        text = "Maillage nominal";
        subTxt = ((st.probes || []).length || 0) + " SONDES · AES-GCM";
      }
    }

    if (pill) pill.dataset.tone = tone;
    if (label) label.textContent = text;
    if (sub) sub.textContent = subTxt;
    if (canvas) {
      canvas.dataset.ledMode = mode;
      canvas.dataset.ledColor = color;
    }
    if (sCanvas) {
      sCanvas.dataset.ledMode = mode;
      sCanvas.dataset.ledColor = color;
    }
    if (sText) {
      sText.textContent = Date.now() < state.ledBusyUntil ? state.ledBusyLabel : text.toUpperCase();
    }
    MW().syncLEDs && MW().syncLEDs(document);
  }

  /* -------------------- HTTP & Auth -------------------- */

  async function apiFetch(path, opts = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    if (state.token) headers["Authorization"] = "Bearer " + state.token;
    const res = await fetch(path, Object.assign({}, opts, { headers }));
    if (res.status === 401) {
      state.token = "";
      persistToken("");
      openAuthGate("Jeton invalide ou expiré.");
      throw new Error("Non autorisé (401)");
    }
    const text = await res.text();
    let data = {};
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = { raw: text };
      }
    }
    if (!res.ok) {
      const msg = (data.errors && data.errors.join(" · ")) || data.error || data.message || ("HTTP " + res.status);
      throw new Error(msg);
    }
    return data;
  }

  function openAuthGate(errText = "") {
    const gate = $("auth-gate");
    if (!gate) return;
    gate.hidden = false;
    const err = $("auth-error-box");
    if (err) {
      err.textContent = errText;
      err.hidden = !errText;
    }
    setTimeout(() => $("auth-token-input")?.focus(), 40);
  }

  async function submitAuthToken() {
    const val = ($("auth-token-input")?.value || "").trim();
    if (!val) return;
    try {
      const res = await fetch("/api/auth/check", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + val
        }
      });
      const check = await res.json().catch(() => ({}));
      if (check.auth_required && !check.authenticated) {
        openAuthGate("Jeton invalide.");
        return;
      }
      state.token = val;
      persistToken(val);
      $("auth-gate").hidden = true;
      await loadInitialData();
    } catch (e) {
      openAuthGate(e.message || "Erreur d'authentification");
    }
  }

  /* -------------------- Initial Load & Polling -------------------- */

  async function bootstrap() {
    applyTheme(state.theme);
    bindStaticEvents();
    MW().syncLEDs && MW().syncLEDs(document);

    try {
      const check = await apiFetch("/api/auth/check", { method: "GET" });
      if (check.auth_required && !check.authenticated) {
        openAuthGate();
        return;
      }
      if (state.token && check.authenticated) {
        persistToken(state.token);
      }
      await loadInitialData();
    } catch (e) {
      if (!String(e.message || "").includes("401")) {
        showToast("Erreur de connexion au serveur : " + e.message, "err");
      }
    }
  }

  async function loadInitialData() {
    await Promise.all([fetchStatus(), fetchConfig()]);
    checkUpdates(false);
    detectDiscoverDefaults();
    clearInterval(state.statusTimer);
    state.statusTimer = setInterval(fetchStatus, 5000);
  }

  async function fetchStatus() {
    try {
      const st = await apiFetch("/api/status", { method: "GET" });
      state.status = st;
      renderAll();
    } catch {
      /* handled by apiFetch if 401 */
    }
  }

  async function fetchConfig() {
    const res = await apiFetch("/api/config", { method: "GET" });
    state.config = ensureDraftShape(res.config);
    state.draft = clone(state.config);
    state.rawYAML = res.yaml || "";
    state.dirty = false;
    renderConfigForms();
    syncUnsavedBar();
  }

  function markDirty() {
    state.dirty = true;
    syncUnsavedBar();
  }

  function syncUnsavedBar() {
    const bar = $("unsaved-bar");
    if (bar) bar.hidden = !state.dirty;
  }

  async function saveConfiguration(showMsg = true) {
    if (!state.draft) return false;
    pullConfigFormsIntoDraft();
    triggerLEDBusy("sweep", "Sauvegarde config", "RECHARGEMENT", 2200);
    try {
      const res = await apiFetch("/api/config", {
        method: "PUT",
        body: JSON.stringify({ config: state.draft })
      });
      state.config = ensureDraftShape(res.config || state.draft);
      state.draft = clone(state.config);
      state.rawYAML = res.yaml || "";
      state.dirty = false;
      syncUnsavedBar();
      await fetchStatus();
      renderConfigForms();
      if (showMsg) {
        if (res.persisted === false) {
          showToast("Activé en mémoire (config.yaml en lecture seule).", "warn");
        } else {
          showToast("Configuration enregistrée et appliquée.");
        }
      }
      return true;
    } catch (e) {
      showToast("Erreur d'enregistrement : " + e.message, "err");
      return false;
    }
  }

  /* -------------------- Navigation & Tabs -------------------- */

  function switchTab(tab, subtab = null) {
    const valid = ["home", "discover", "friends", "alerts", "settings"];
    if (!valid.includes(tab)) tab = "home";
    state.tab = tab;

    document.querySelectorAll(".space-link[data-tab]").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.tab === tab);
    });
    document.querySelectorAll(".view-panel[data-panel]").forEach((sec) => {
      sec.hidden = sec.dataset.panel !== tab;
    });

    const spaceTabs = $("space-tabs");
    if (spaceTabs) {
      spaceTabs.hidden = tab !== "discover";
    }
    if (tab === "discover") {
      switchDiscoverSubtab(subtab || state.discoverSubtab);
    }

    $("sidebar")?.classList.remove("open");
    renderAll();
  }

  function switchDiscoverSubtab(sub) {
    const valid = ["docker", "lan", "managed"];
    if (!valid.includes(sub)) sub = "docker";
    state.discoverSubtab = sub;
    localStorage.setItem(STORAGE.subtab, sub);

    document.querySelectorAll("#space-tabs button[data-subtab]").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.subtab === sub);
    });
    document.querySelectorAll("#view-discover .sub-panel[data-subpanel]").forEach((el) => {
      el.hidden = el.dataset.subpanel !== sub;
    });

    if (sub === "managed") renderManagedProbes();
  }

  /* -------------------- Global Rendering -------------------- */

  function renderAll() {
    const st = state.status;
    if (!st) return;

    renderSidebar(st);
    renderTopbar(st);
    renderHome(st);
    renderManagedProbes();
    renderFriendsView(st);
    renderStatusbar(st);
    syncHeroAndStatusLED();
    MW().syncLEDs && MW().syncLEDs(document);
  }

  function renderSidebar(st) {
    const probes = st.probes || [];
    const peers = st.peers || [];
    const relays = st.relays || [];
    const connRelays = relays.filter((r) => r.connected).length;

    const fb = $("nav-friends-badge");
    if (fb) {
      fb.textContent = String(peers.length);
      fb.hidden = peers.length === 0;
    }

    const hostDot = $("sidebar-host-dot");
    if (hostDot) {
      hostDot.className = "pulse-dot status-dot " + (st.mode === "setup" ? "is-warn" : st.overall_ok ? "is-ok" : "is-err");
    }
    if ($("sidebar-host-name")) $("sidebar-host-name").textContent = st.node_name || "MeshWatch";
    if ($("sidebar-host-meta")) $("sidebar-host-meta").textContent = probes.length + " sonde(s) · " + connRelays + "/" + relays.length + " relais";
    if ($("sidebar-host-uptime")) $("sidebar-host-uptime").textContent = "uptime " + fmtUptime(st.uptime_sec);

    const listEl = $("sidebar-probes");
    if (!listEl) return;
    if (!probes.length) {
      listEl.innerHTML = '<div style="padding:4px 6px;font-size:11.5px;color:var(--text-faint);">Aucune sonde</div>';
      return;
    }
    listEl.innerHTML = probes.slice(0, 10).map((p) => {
      const sel = p.id === state.selectedProbeID ? " active" : "";
      const dotCls = p.ok ? "is-ok" : "is-err";
      const metrics = (st.probe_metrics || {})[p.id];
      const badgeTxt = metrics && metrics.cpu_percent != null
        ? Math.round(metrics.cpu_percent) + "%"
        : p.latency_ms + "ms";
      return (
        '<button class="side-link' + sel + '" type="button" data-side-probe="' + esc(p.id) + '">' +
        '<span class="status-dot ' + dotCls + '"></span>' +
        '<span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(p.id) + "</span>" +
        '<span class="mono" style="font-size:10.5px;color:var(--text-faint);">' + esc(badgeTxt) + "</span>" +
        "</button>"
      );
    }).join("");

    listEl.querySelectorAll("[data-side-probe]").forEach((btn) => {
      btn.addEventListener("click", () => {
        selectProbe(btn.dataset.sideProbe);
        if (state.tab !== "home") switchTab("home");
      });
    });
  }

  function renderTopbar(st) {
    const probes = st.probes || [];
    const okCount = probes.filter((p) => p.ok).length;
    const peers = st.peers || [];
    const onlinePeers = peers.filter((p) => p.online).length;
    const pm = st.probe_metrics || {};

    let cpuSum = 0;
    let cpuN = 0;
    probes.forEach((p) => {
      const m = pm[p.id];
      if (m && typeof m.cpu_percent === "number") {
        cpuSum += m.cpu_percent;
        cpuN++;
      }
    });
    const avgCPU = cpuN ? Math.round(cpuSum / cpuN) + "%" : "—";
    const latencies = probes.map((p) => p.latency_ms).filter((v) => typeof v === "number" && v > 0);
    const avgLat = latencies.length ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) + " ms" : "—";

    const gp = $("g-probes");
    if (gp) {
      gp.textContent = okCount + "/" + probes.length;
      gp.className = okCount < probes.length ? "hot" : "";
    }
    const gc = $("g-cpu");
    if (gc) {
      gc.textContent = avgCPU;
      gc.className = cpuN && cpuSum / cpuN >= 80 ? "hot" : "";
    }
    if ($("g-latency")) $("g-latency").textContent = avgLat;
    if ($("g-peers")) $("g-peers").textContent = onlinePeers + "/" + peers.length;
  }

  function renderStatusbar(st) {
    const relays = st.relays || [];
    const connRelays = relays.filter((r) => r.connected).length;
    const probes = st.probes || [];
    const nm = $("status-network-meta");
    if (nm) {
      nm.textContent =
        (st.node_name || "MeshWatch") +
        " · " + connRelays + "/" + relays.length + " relais · " +
        probes.length + " sondes · HB " + (st.heartbeat_interval_sec || 15) + "s";
    }
    const sv = $("status-version");
    if (sv) sv.textContent = (st.version || "dev") + (st.commit ? " (" + st.commit.slice(0, 7) + ")" : "");
  }

  /* -------------------- View 01: Home, Metrics, Fleet & Inspector -------------------- */

  function renderHome(st) {
    const probes = st.probes || [];
    const peers = st.peers || [];
    const relays = st.relays || [];
    const pm = st.probe_metrics || {};
    const ph = st.probe_history || {};
    const cfgProbes = state.draft?.probes || [];

    const setupNotice = $("home-setup-notice");
    if (setupNotice) {
      setupNotice.hidden = st.mode !== "setup";
    }

    const okCount = probes.filter((p) => p.ok).length;
    const connRelays = relays.filter((r) => r.connected).length;
    const onlinePeers = peers.filter((p) => p.online).length;

    const subEl = $("home-sub");
    if (subEl) {
      subEl.textContent =
        (st.node_name || "Agent local") +
        " · " + okCount + "/" + probes.length + " sondes saines · " +
        onlinePeers + "/" + peers.length + " amis en ligne · " +
        connRelays + "/" + relays.length + " relais Nostr";
    }

    const hasNode = st.mode !== "setup" && Boolean(st.node_name);
    const hasProbes = cfgProbes.length > 0 || probes.length > 0;
    const hasPeers = peers.length > 0;
    const todo = $("home-todo-strip");
    if (todo) {
      todo.hidden = hasNode && hasProbes && hasPeers;
      $("todo-step-node")?.classList.toggle("is-done", hasNode);
      $("todo-step-probes")?.classList.toggle("is-done", hasProbes);
      $("todo-step-friends")?.classList.toggle("is-done", hasPeers);
      if ($("todo-mark-node")) $("todo-mark-node").textContent = hasNode ? "✓" : "1";
      if ($("todo-mark-probes")) $("todo-mark-probes").textContent = hasProbes ? "✓" : "2";
      if ($("todo-mark-friends")) $("todo-mark-friends").textContent = hasPeers ? "✓" : "3";
    }

    const pct = probes.length ? Math.round((okCount / probes.length) * 100) : 100;
    if ($("mc-probes-val")) $("mc-probes-val").innerHTML = okCount + " <small>/ " + probes.length + "</small>";
    if ($("mc-probes-dot")) $("mc-probes-dot").className = "status-dot " + (okCount < probes.length ? "is-err" : "is-ok");
    if ($("mc-probes-sub")) $("mc-probes-sub").textContent = probes.length ? pct + "% opérationnelles" : "Ajoutez une première sonde";

    const latSamples = [];
    probes.forEach((p) => {
      const h = ph[p.id] || [];
      h.forEach((pt, idx) => {
        if (!latSamples[idx]) latSamples[idx] = [];
        if (typeof pt.latency_ms === "number") latSamples[idx].push(pt.latency_ms);
      });
    });
    const avgLatSeries = latSamples
      .filter((arr) => arr && arr.length)
      .map((arr) => arr.reduce((a, b) => a + b, 0) / arr.length);

    let cpuVals = [];
    probes.forEach((p) => {
      const m = pm[p.id];
      if (m && typeof m.cpu_percent === "number") cpuVals.push(m.cpu_percent);
    });
    const avgCPU = cpuVals.length ? cpuVals.reduce((a, b) => a + b, 0) / cpuVals.length : null;
    if ($("mc-cpu-val")) $("mc-cpu-val").innerHTML = avgCPU != null ? Math.round(avgCPU) + "<small>%</small>" : "—";
    if ($("mc-cpu-sub")) $("mc-cpu-sub").textContent = cpuVals.length ? "Sur " + cpuVals.length + " hôte(s) instrumenté(s)" : "Pas d'hôte CPU configuré";
    if ($("mc-cpu-meter")) $("mc-cpu-meter").innerHTML = avgCPU != null ? MW().meterHTML(avgCPU, 75, 90) : "";

    const cpuSeries = [];
    probes.forEach((p) => {
      const h = ph[p.id] || [];
      h.forEach((pt, idx) => {
        if (typeof pt.cpu === "number") {
          if (!cpuSeries[idx]) cpuSeries[idx] = [];
          cpuSeries[idx].push(pt.cpu);
        }
      });
    });
    const avgCpuSeries = cpuSeries.filter((a) => a && a.length).map((a) => a.reduce((x, y) => x + y, 0) / a.length);
    if ($("mc-cpu-spark")) $("mc-cpu-spark").innerHTML = MW().sparklineHTML(avgCpuSeries, { color: "var(--action)", fluid: true, max: 100 });

    const latAll = probes.map((p) => p.latency_ms).filter((v) => typeof v === "number").sort((a, b) => a - b);
    const p50 = latAll.length ? latAll[Math.floor(latAll.length / 2)] : null;
    const p95 = latAll.length ? latAll[Math.min(latAll.length - 1, Math.floor(latAll.length * 0.95))] : null;
    if ($("mc-lat-val")) $("mc-lat-val").innerHTML = p50 != null ? p50 + "<small>ms</small>" : "—";
    if ($("mc-lat-sub")) $("mc-lat-sub").textContent = p95 != null ? "P95 : " + p95 + " ms" : "Aucune mesure";
    if ($("mc-lat-spark")) $("mc-lat-spark").innerHTML = MW().sparklineHTML(avgLatSeries, { color: "var(--info)", fluid: true });
    if ($("mc-probes-spark")) $("mc-probes-spark").innerHTML = MW().sparklineHTML(probes.map((p) => (p.ok ? 100 : 0)), { color: "var(--ok)", fluid: true, max: 100 });

    if ($("mc-mesh-val")) $("mc-mesh-val").innerHTML = onlinePeers + " <small>/ " + peers.length + " amis</small>";
    if ($("mc-mesh-sub")) $("mc-mesh-sub").textContent = connRelays + "/" + relays.length + " relais Nostr · " + (st.muted ? "Auto-mute actif" : "En veille");
    if ($("mc-mesh-spark")) $("mc-mesh-spark").innerHTML = MW().sparklineHTML(relays.map((r) => (r.connected ? 100 : 10)), { color: "var(--primary)", fluid: true, max: 100 });

    renderFleetTable(st);
    renderInspector(st);
    renderTopologyAndPeers(st);
  }

  function renderFleetTable(st) {
    const probes = st.probes || [];
    const pm = st.probe_metrics || {};
    const ph = st.probe_history || {};
    const cfgProbes = state.draft?.probes || [];

    const okN = probes.filter((p) => p.ok).length;
    const downN = probes.length - okN;
    const hostsN = probes.filter((p) => isHostKind(p.kind)).length;
    if ($("seg-all")) $("seg-all").textContent = String(probes.length);
    if ($("seg-ok")) $("seg-ok").textContent = String(okN);
    if ($("seg-down")) $("seg-down").textContent = String(downN);
    if ($("seg-hosts")) $("seg-hosts").textContent = String(hostsN);

    const q = (state.fleetSearch || "").toLowerCase();
    let list = probes.slice().filter((p) => {
      if (state.fleetFilter === "ok" && !p.ok) return false;
      if (state.fleetFilter === "down" && p.ok) return false;
      if (state.fleetFilter === "hosts" && !isHostKind(p.kind)) return false;
      if (q) {
        const cfg = cfgProbes.find((c) => c.id === p.id);
        const hay = (p.id + " " + p.kind + " " + p.summary + " " + probeTargetLabel(cfg)).toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    list.sort((a, b) => {
      if (state.fleetSort === "name") return (a.id || "").localeCompare(b.id || "");
      if (state.fleetSort === "latency") return (b.latency_ms || 0) - (a.latency_ms || 0);
      if (state.fleetSort === "cpu") {
        const ac = pm[a.id]?.cpu_percent ?? -1;
        const bc = pm[b.id]?.cpu_percent ?? -1;
        return bc - ac;
      }
      if (a.ok !== b.ok) return a.ok ? 1 : -1;
      return (a.id || "").localeCompare(b.id || "");
    });

    if (probes.length && (!state.selectedProbeID || !probes.some((p) => p.id === state.selectedProbeID))) {
      selectProbe((list[0] || probes[0]).id, false);
    }

    const tbody = $("fleet-tbody");
    const emptyEl = $("fleet-empty");
    if (!tbody || !emptyEl) return;

    if (!list.length) {
      tbody.innerHTML = "";
      emptyEl.hidden = false;
      return;
    }
    emptyEl.hidden = true;

    tbody.innerHTML = list.map((p) => {
      const m = pm[p.id] || {};
      const hist = ph[p.id] || [];
      const selected = p.id === state.selectedProbeID ? " selected" : "";
      const kindBadge = PROBE_KINDS[p.kind]?.badge || p.kind || "SONDE";
      const statusCell = p.ok
        ? '<span class="status-cell is-ok"><span class="status-dot is-ok"></span>OPÉRATIONNEL</span>'
        : '<span class="status-cell is-err"><span class="status-dot is-err"></span>EN PANNE</span>';

      let col3 = '<span style="color:var(--text-faint);">—</span>';
      if (typeof m.cpu_percent === "number") {
        col3 = "<div>" + Math.round(m.cpu_percent) + "%</div>" + MW().meterHTML(m.cpu_percent, 75, 90);
      } else if (typeof m.temp_c === "number") {
        col3 = '<span class="' + (m.temp_c >= 65 ? "badge warn" : "badge ok") + '">' + Math.round(m.temp_c) + " °C</span>";
      } else if (typeof m.tls_days === "number") {
        col3 = '<span class="mono">TLS ' + m.tls_days + "j</span>";
      }

      let col4 = '<span style="color:var(--text-faint);">—</span>';
      if (typeof m.ram_percent === "number") {
        col4 = "<div>RAM " + Math.round(m.ram_percent) + "%</div>" + (typeof m.disk_max_pct === "number" ? '<div style="font-size:10.5px;color:var(--text-faint);">Disk ' + Math.round(m.disk_max_pct) + "%</div>" : "");
      } else if (m.containers && m.containers.length) {
        col4 = '<span class="mono">' + m.containers.length + " conteneur(s)</span>";
      } else if (typeof m.http_status === "number") {
        col4 = '<span class="mono">HTTP ' + m.http_status + "</span>";
      }

      return (
        '<tr class="clickable' + selected + '" data-select-probe="' + esc(p.id) + '">' +
        "<td>" +
          '<div class="ct-name">' +
            '<span class="status-dot ' + (p.ok ? "is-ok" : "is-err") + '"></span>' +
            '<div style="min-width:0;">' +
              '<div class="ct-title">' + esc(p.id) + ' <span class="row-kind" style="margin-left:6px;">' + esc(kindBadge) + "</span></div>" +
              '<div class="ct-sub" title="' + esc(p.summary) + '">' + esc(p.summary || "—") + "</div>" +
            "</div>" +
          "</div>" +
        "</td>" +
        "<td>" + statusCell + "</td>" +
        '<td class="num">' + col3 + "</td>" +
        '<td class="num">' + col4 + "</td>" +
        '<td class="num">' +
          "<div>" + esc(p.latency_ms) + " ms</div>" +
          MW().uptimeStripHTML(hist, false, 14) +
        "</td>" +
        '<td class="num">' +
          '<div class="row-actions">' +
            '<button class="inline-action" type="button" data-quick-test="' + esc(p.id) + '">Tester</button>' +
            '<button class="inline-action" type="button" data-quick-edit="' + esc(p.id) + '">Éditer</button>' +
          "</div>" +
        "</td>" +
        "</tr>"
      );
    }).join("");

    tbody.querySelectorAll("[data-select-probe]").forEach((tr) => {
      tr.addEventListener("click", (e) => {
        if (e.target.closest("button")) return;
        selectProbe(tr.dataset.selectProbe);
      });
    });
    tbody.querySelectorAll("[data-quick-test]").forEach((btn) => {
      btn.addEventListener("click", () => quickTestProbeByID(btn.dataset.quickTest));
    });
    tbody.querySelectorAll("[data-quick-edit]").forEach((btn) => {
      btn.addEventListener("click", () => editProbeByID(btn.dataset.quickEdit));
    });
  }

  function selectProbe(id, rerender = true) {
    state.selectedProbeID = id || "";
    localStorage.setItem(STORAGE.selectedProbe, state.selectedProbeID);
    if (rerender && state.status) {
      renderSidebar(state.status);
      renderFleetTable(state.status);
      renderInspector(state.status);
      MW().syncLEDs && MW().syncLEDs($("probe-inspector"));
    }
  }

  function renderInspector(st) {
    const probes = st.probes || [];
    const probe = probes.find((p) => p.id === state.selectedProbeID) || probes[0];
    const body = $("insp-body");
    if (!body) return;

    if (!probe) {
      if ($("insp-title")) $("insp-title").textContent = "Aucune sonde sélectionnée";
      if ($("insp-summary")) $("insp-summary").textContent = "Ajoutez ou sélectionnez une sonde pour inspecter ses graphiques et ressources.";
      if ($("insp-kind-chip")) $("insp-kind-chip").textContent = "—";
      if ($("insp-status-badge")) {
        $("insp-status-badge").textContent = "VIDE";
        $("insp-status-badge").className = "badge";
      }
      if ($("insp-latency-label")) $("insp-latency-label").textContent = "—";
      body.innerHTML = '<div class="empty-state">Commencez dans l\'onglet Découverte ou cliquez sur + Nouvelle sonde.</div>';
      return;
    }

    const m = (st.probe_metrics || {})[probe.id] || {};
    const hist = (st.probe_history || {})[probe.id] || [];
    const cfg = (state.draft?.probes || []).find((c) => c.id === probe.id);

    const inspLED = $("insp-led-canvas");
    if (inspLED) {
      inspLED.dataset.ledMode = probe.ok ? (isHostKind(probe.kind) ? "orbit" : "link") : "cross";
      inspLED.dataset.ledColor = probe.ok ? "ok" : "danger";
    }
    if ($("insp-kind-chip")) $("insp-kind-chip").textContent = PROBE_KINDS[probe.kind]?.label || probe.kind;
    if ($("insp-status-badge")) {
      $("insp-status-badge").textContent = probe.ok ? "OPÉRATIONNEL" : "EN PANNE";
      $("insp-status-badge").className = "badge " + (probe.ok ? "ok" : "danger");
    }
    if ($("insp-latency-label")) $("insp-latency-label").textContent = probe.latency_ms + " ms";
    if ($("insp-title")) $("insp-title").textContent = probe.id;
    if ($("insp-summary")) $("insp-summary").textContent = probe.summary || probeTargetLabel(cfg);

    const resCount =
      (m.nodes?.length || 0) +
      (m.guests?.length || 0) +
      (m.disks?.length || 0) +
      (m.services?.length || 0) +
      (m.containers?.length || 0) +
      (m.sensors?.length || 0);
    const rc = $("insp-res-count");
    if (rc) {
      rc.textContent = String(resCount);
      rc.hidden = resCount === 0;
    }

    document.querySelectorAll(".tab[data-insp-tab]").forEach((t) => {
      t.classList.toggle("active", t.dataset.inspTab === state.inspectorTab);
    });

    if (state.inspectorTab === "resources") {
      renderInspectorResources(body, probe, m);
    } else if (state.inspectorTab === "history") {
      renderInspectorHistory(body, probe, hist, st.incidents || []);
    } else {
      renderInspectorOverview(body, probe, m, hist, cfg);
    }
  }

  function renderInspectorOverview(body, probe, m, hist, cfg) {
    let html = "";

    html +=
      '<div class="res-item">' +
      '<div class="res-group-title">Disponibilité sur les derniers contrôles (' + hist.length + " pts)</div>" +
      MW().uptimeStripHTML(hist, false, 28) +
      "</div>";

    const rings = [];
    if (typeof m.cpu_percent === "number") {
      rings.push(MW().ringHTML(m.cpu_percent, { size: 78, sub: "CPU" }));
    }
    if (typeof m.ram_percent === "number") {
      rings.push(MW().ringHTML(m.ram_percent, { size: 78, sub: "RAM", warnAt: 80, dangerAt: 92 }));
    }
    if (typeof m.disk_max_pct === "number") {
      rings.push(MW().ringHTML(m.disk_max_pct, { size: 78, sub: "DISQUE", warnAt: 85, dangerAt: 95 }));
    }
    if (typeof m.temp_c === "number") {
      const tPct = Math.min(100, (m.temp_c / 85) * 100);
      rings.push(MW().ringHTML(tPct, { size: 78, display: Math.round(m.temp_c) + "°C", sub: "TEMP", warnAt: 70, dangerAt: 85 }));
    }
    if (typeof m.tls_days === "number") {
      const tlsPct = Math.min(100, (m.tls_days / 90) * 100);
      rings.push(MW().ringHTML(tlsPct, { size: 78, display: m.tls_days + "j", sub: "TLS", color: m.tls_days < 14 ? "var(--danger)" : "var(--ok)" }));
    }

    if (rings.length) {
      html += '<div style="display:flex;gap:14px;flex-wrap:wrap;justify-content:space-around;padding:8px 0;">' + rings.join("") + "</div>";
    }

    html += '<div id="insp-chart-latency"></div>';
    if (hist.some((pt) => typeof pt.cpu === "number")) html += '<div id="insp-chart-cpu"></div>';
    if (hist.some((pt) => typeof pt.ram === "number")) html += '<div id="insp-chart-ram"></div>';
    if (hist.some((pt) => typeof pt.disk === "number")) html += '<div id="insp-chart-disk"></div>';
    if (hist.some((pt) => typeof pt.temp === "number")) html += '<div id="insp-chart-temp"></div>';

    const kvs = [
      ["Cible", m.target || probeTargetLabel(cfg)],
      ["Hôte / OS", [m.hostname, m.os].filter(Boolean).join(" · ") || null],
      ["RAM détaillée", m.ram_total_mb ? fmtMB(m.ram_used_mb) + " / " + fmtMB(m.ram_total_mb) : null],
      ["Load average", typeof m.load_avg === "number" ? m.load_avg.toFixed(2) : null],
      ["Uptime machine", m.uptime_sec ? fmtUptime(m.uptime_sec) : null],
      ["Certificat TLS", m.tls_subject ? m.tls_subject + (m.tls_expiry ? " (exp. " + m.tls_expiry + ")" : "") : null],
      ["Valeur SNMP", m.snmp_value || null],
      ["Cadence sonde", cfg ? (cfg.interval || "1m") + " (timeout " + (cfg.timeout || "10s") + ")" : null]
    ].filter((pair) => pair[1]);

    if (kvs.length) {
      html += '<div class="res-item"><div class="res-group-title">Détails techniques</div><dl class="kv">' +
        kvs.map(([k, v]) => "<dt>" + esc(k) + '</dt><dd class="mono">' + esc(v) + "</dd>").join("") +
        "</dl></div>";
    }

    body.innerHTML = html;
    renderInspectorCharts(probe, hist);
  }

  function renderInspectorCharts(probe, hist) {
    const latBox = $("insp-chart-latency");
    if (latBox && MW().renderLineChart) {
      MW().renderLineChart(latBox, {
        title: "Latence de sonde",
        data: hist.map((p) => ({ ts: p.ts, v: p.latency_ms })),
        latest: probe.latency_ms + " ms",
        color: "var(--info)",
        height: 118,
        format: (v) => Math.round(v) + " ms"
      });
    }

    const cpuBox = $("insp-chart-cpu");
    if (cpuBox && MW().renderLineChart) {
      const pts = hist.filter((p) => typeof p.cpu === "number").map((p) => ({ ts: p.ts, v: p.cpu }));
      const latest = pts.length ? pts[pts.length - 1].v.toFixed(1) + "%" : "—";
      MW().renderLineChart(cpuBox, {
        title: "Utilisation CPU",
        data: pts,
        latest,
        color: "var(--action)",
        height: 118,
        max: 100,
        format: (v) => v.toFixed(1) + "%"
      });
    }

    const ramBox = $("insp-chart-ram");
    if (ramBox && MW().renderLineChart) {
      const pts = hist.filter((p) => typeof p.ram === "number").map((p) => ({ ts: p.ts, v: p.ram }));
      const latest = pts.length ? pts[pts.length - 1].v.toFixed(1) + "%" : "—";
      MW().renderLineChart(ramBox, {
        title: "Mémoire vive (RAM)",
        data: pts,
        latest,
        color: "var(--ok)",
        height: 118,
        max: 100,
        format: (v) => v.toFixed(1) + "%"
      });
    }

    const diskBox = $("insp-chart-disk");
    if (diskBox && MW().renderLineChart) {
      const pts = hist.filter((p) => typeof p.disk === "number").map((p) => ({ ts: p.ts, v: p.disk }));
      const latest = pts.length ? pts[pts.length - 1].v.toFixed(1) + "%" : "—";
      MW().renderLineChart(diskBox, {
        title: "Disque principal (max %)",
        data: pts,
        latest,
        color: "var(--warn)",
        height: 118,
        max: 100,
        format: (v) => v.toFixed(1) + "%"
      });
    }

    const tempBox = $("insp-chart-temp");
    if (tempBox && MW().renderLineChart) {
      const pts = hist.filter((p) => typeof p.temp === "number").map((p) => ({ ts: p.ts, v: p.temp }));
      const latest = pts.length ? Math.round(pts[pts.length - 1].v) + " °C" : "—";
      MW().renderLineChart(tempBox, {
        title: "Température",
        data: pts,
        latest,
        color: "var(--warn)",
        height: 118,
        format: (v) => Math.round(v) + " °C"
      });
    }
  }

  function renderInspectorResources(body, probe, m) {
    let html = "";

    if (m.nodes && m.nodes.length) {
      html += '<div class="res-group-title">Nœuds Cluster (' + m.nodes.length + ")</div>";
      html += m.nodes.map((n) => (
        '<div class="res-item">' +
          '<div class="res-item-row"><strong>' + esc(n.name) + '</strong><span class="badge ' + (n.online ? "ok" : "danger") + '">' + (n.online ? "EN LIGNE" : "HORS LIGNE") + "</span></div>" +
          '<div class="mono" style="font-size:11px;color:var(--text-muted);">CPU ' + n.cpu_pct.toFixed(1) + "% · RAM " + n.ram_pct.toFixed(1) + "% · Uptime " + fmtUptime(n.uptime_sec) + "</div>" +
          MW().meterHTML(n.cpu_pct, 75, 90) +
        "</div>"
      )).join("");
    }

    if (m.guests && m.guests.length) {
      html += '<div class="res-group-title">VMs &amp; Conteneurs LXC (' + m.guests.length + ")</div>";
      html += m.guests.map((g) => {
        const up = String(g.status || "").toLowerCase() === "running";
        const meta = [];
        if (g.id) meta.push("#" + g.id);
        if (g.type) meta.push(g.type);
        if (typeof g.cpu_pct === "number") meta.push("CPU " + g.cpu_pct.toFixed(1) + "%");
        if (typeof g.ram_pct === "number") meta.push("RAM " + Math.round(g.ram_pct) + "%");
        if (g.uptime_sec) meta.push("Up " + fmtUptime(g.uptime_sec));
        return (
          '<div class="res-item">' +
            '<div class="res-item-row"><strong>' + esc(g.name || g.id) + '</strong><span class="badge ' + (up ? "ok" : "warn") + '">' + esc(g.status || "—") + "</span></div>" +
            '<div class="mono" style="font-size:11px;color:var(--text-faint);">' + esc(meta.join(" · ")) + "</div>" +
          "</div>"
        );
      }).join("");
    }

    if (m.disks && m.disks.length) {
      html += '<div class="res-group-title">Stockage &amp; Disques (' + m.disks.length + ")</div>";
      html += m.disks.map((d) => (
        '<div class="res-item">' +
          '<div class="res-item-row"><strong>' + esc(d.name) + '</strong><span class="mono">' + d.used_pct.toFixed(1) + "%</span></div>" +
          (d.total_gb ? '<div class="mono" style="font-size:11px;color:var(--text-faint);">' + d.used_gb.toFixed(1) + " / " + d.total_gb.toFixed(1) + " Go</div>" : "") +
          MW().meterHTML(d.used_pct, 80, 92) +
        "</div>"
      )).join("");
    }

    if (m.containers && m.containers.length) {
      html += '<div class="res-group-title">Conteneurs Docker (' + m.containers.length + ")</div>";
      html += m.containers.map((c) => {
        const st = String(c.state || "").toLowerCase();
        const cls = st === "running" || st === "healthy" ? "ok" : st === "unhealthy" || st === "exited" ? "danger" : "warn";
        return (
          '<div class="res-item">' +
            '<div class="res-item-row"><strong>' + esc(c.name) + '</strong><span class="badge ' + cls + '">' + esc(c.state || "—") + "</span></div>" +
            (c.health ? '<div class="mono" style="font-size:11px;color:var(--text-faint);">Santé : ' + esc(c.health) + "</div>" : "") +
          "</div>"
        );
      }).join("");
    }

    if (m.services && m.services.length) {
      html += '<div class="res-group-title">Services supervisés (' + m.services.length + ")</div>";
      html += m.services.map((s) => (
        '<div class="res-item">' +
          '<div class="res-item-row"><strong>' + esc(s.name) + '</strong><span class="badge ' + (s.active ? "ok" : "danger") + '">' + esc(s.state || (s.active ? "actif" : "arrêté")) + "</span></div>" +
        "</div>"
      )).join("");
    }

    if (m.sensors && m.sensors.length) {
      html += '<div class="res-group-title">Capteurs &amp; Matériel (' + m.sensors.length + ")</div>";
      html += m.sensors.map((s) => (
        '<div class="res-item">' +
          '<div class="res-item-row"><strong>' + esc(s.name) + '</strong><span class="badge ' + (s.ok ? "ok" : "danger") + '">' + esc(s.status || (s.ok ? "OK" : "ALERTE")) + "</span></div>" +
          (typeof s.temp_c === "number" ? '<div class="mono" style="font-size:11px;color:var(--text-muted);">Température : ' + Math.round(s.temp_c) + " °C</div>" : "") +
        "</div>"
      )).join("");
    }

    if (!html) {
      html = '<div class="empty-state">Aucune sous-ressource détaillée remontée pour cette sonde.<br/><br/><button class="btn sm" id="insp-res-retest" type="button">Exécuter un test complet</button></div>';
    }
    body.innerHTML = html;
    $("insp-res-retest")?.addEventListener("click", () => quickTestProbeByID(probe.id));
  }

  function renderInspectorHistory(body, probe, hist, incidents) {
    const related = (incidents || []).filter((inc) => inc.target === probe.id || inc.source === probe.id);
    let html = "";

    if (related.length) {
      html += '<div class="res-group-title">Incidents sur cette sonde (' + related.length + ")</div>";
      html += related.slice(-8).reverse().map((inc) => (
        '<div class="res-item">' +
          '<div class="res-item-row"><span class="badge ' + (inc.ok ? "ok" : "danger") + '">' + (inc.ok ? "RÉTABLI" : "PANNE") + '</span><span class="mono" style="font-size:11px;color:var(--text-faint);">' + esc(fmtTime(inc.ts)) + "</span></div>" +
          '<div style="font-size:12px;">' + esc(inc.summary) + "</div>" +
        "</div>"
      )).join("");
    }

    html += '<div class="res-group-title">Échantillons récents (' + hist.length + ")</div>";
    if (!hist.length) {
      html += '<div class="empty-state">Pas encore d\'échantillons en mémoire.</div>';
    } else {
      html += hist.slice(-15).reverse().map((pt) => {
        const extra = [];
        if (typeof pt.cpu === "number") extra.push("CPU " + Math.round(pt.cpu) + "%");
        if (typeof pt.ram === "number") extra.push("RAM " + Math.round(pt.ram) + "%");
        if (typeof pt.disk === "number") extra.push("Disk " + Math.round(pt.disk) + "%");
        if (typeof pt.temp === "number") extra.push(Math.round(pt.temp) + "°C");
        return (
          '<div class="res-item">' +
            '<div class="res-item-row">' +
              '<span class="mono">' + esc(fmtTime(pt.ts)) + "</span>" +
              '<span class="mono">' + esc(pt.latency_ms) + " ms · " + (pt.ok ? '<span style="color:var(--ok)">OK</span>' : '<span style="color:var(--danger)">KO</span>') + "</span>" +
            "</div>" +
            (extra.length ? '<div class="mono" style="font-size:11px;color:var(--text-faint);">' + esc(extra.join(" · ")) + "</div>" : "") +
          "</div>"
        );
      }).join("");
    }
    body.innerHTML = html;
  }

  function renderTopologyAndPeers(st) {
    const svg = $("home-topology-svg");
    if (svg && MW().renderTopologySVG) {
      MW().renderTopologySVG(svg, st, {
        onAction: (target) => switchTab(target),
        onPeer: (pk) => openPeerDrawer(pk)
      });
    }

    const peersMini = $("home-peers-mini");
    if (peersMini) {
      const peers = st.peers || [];
      if (!peers.length) {
        peersMini.innerHTML = '<div style="font-size:13px;color:var(--text-muted);">Aucun ami de veille mutuelle configuré.</div>';
      } else {
        peersMini.innerHTML = '<div class="surface-list">' + peers.map((p) => {
          let cls = "is-muted";
          let label = "EN ATTENTE";
          if (p.timed_out) { cls = "is-err"; label = "HORS LIGNE"; }
          else if (p.online && !p.overall_ok) { cls = "is-warn"; label = "ALERTE"; }
          else if (p.online) { cls = "is-ok"; label = "PROTÉGÉ"; }
          return (
            '<div class="surface-row" style="cursor:pointer;" data-open-peer="' + esc(p.pubkey_hex) + '">' +
              '<div class="row-main">' +
                '<div class="row-title-line"><span class="status-dot ' + cls + '"></span><span class="row-title">' + esc(p.name) + "</span></div>" +
                '<div class="row-sub">' + esc(fmtAge(p.last_seen)) + " · " + esc((p.probes || []).length) + " sondes</div>" +
              "</div>" +
              '<div class="row-right"><span class="badge ' + (cls === "is-ok" ? "ok" : cls === "is-warn" ? "warn" : cls === "is-err" ? "danger" : "") + '">' + label + "</span></div>" +
            "</div>"
          );
        }).join("") + "</div>";
        peersMini.querySelectorAll("[data-open-peer]").forEach((el) => {
          el.addEventListener("click", () => openPeerDrawer(el.dataset.openPeer));
        });
      }
    }

    const incBox = $("home-incidents-list");
    if (incBox) {
      const incs = (st.incidents || []).slice(-6).reverse();
      if (!incs.length) {
        incBox.innerHTML = '<div style="font-size:12.5px;color:var(--text-faint);">Aucun incident récent enregistré.</div>';
      } else {
        incBox.innerHTML = '<div class="surface-list">' + incs.map((i) => (
          '<div class="surface-row">' +
            '<div class="row-main">' +
              '<div class="row-title-line">' +
                '<span class="badge ' + (i.ok ? "ok" : "danger") + '">' + (i.ok ? "OK" : "PANNE") + "</span>" +
                '<span class="row-title">' + esc(i.target || i.source) + "</span>" +
              "</div>" +
              '<div class="row-sub">' + esc(i.summary) + "</div>" +
            "</div>" +
            '<span class="mono" style="font-size:11px;color:var(--text-faint);">' + esc(fmtTime(i.ts)) + "</span>" +
          "</div>"
        )).join("") + "</div>";
      }
    }
  }

  function renderTopologyAndInspectorCharts() {
    if (!state.status) return;
    renderTopologyAndPeers(state.status);
    renderInspector(state.status);
  }

  /* -------------------- Quick Probe Actions -------------------- */

  async function runAllProbesNow() {
    triggerLEDBusy("orbit", "Test flotte complète", "EXÉCUTION SONDES", 3200);
    try {
      const res = await apiFetch("/api/probes/run", { method: "POST", body: "{}" });
      await fetchStatus();
      const count = (res.probes || []).length;
      const ok = (res.probes || []).filter((p) => p.ok).length;
      showToast("Tests terminés : " + ok + "/" + count + " sondes opérationnelles.", ok === count ? "ok" : "warn");
    } catch (e) {
      showToast("Erreur exécution sondes : " + e.message, "err");
    }
  }

  async function quickTestProbeByID(id) {
    const cfg = (state.draft?.probes || []).find((p) => p.id === id);
    if (!cfg) {
      await runAllProbesNow();
      return;
    }
    triggerLEDBusy("orbit", "Test " + id, (PROBE_KINDS[cfg.kind]?.badge || cfg.kind).toUpperCase(), 2600);
    try {
      const res = await apiFetch("/api/probes/test", {
        method: "POST",
        body: JSON.stringify({ probe: cfg })
      });
      await fetchStatus();
      showToast((res.ok ? "OK : " : "Échec : ") + id + " — " + (res.summary || ""), res.ok ? "ok" : "err");
    } catch (e) {
      showToast("Test impossible : " + e.message, "err");
    }
  }

  function editProbeByID(id) {
    const idx = (state.draft?.probes || []).findIndex((p) => p.id === id);
    if (idx >= 0) openProbeModal(idx);
  }

  async function deleteProbeByID(id) {
    if (!state.draft?.probes) return;
    const idx = state.draft.probes.findIndex((p) => p.id === id);
    if (idx < 0) return;
    state.draft.probes.splice(idx, 1);
    if (state.selectedProbeID === id) state.selectedProbeID = "";
    await saveConfiguration(false);
    showToast("Sonde supprimée : " + id);
  }

  /* -------------------- View 02: Discovery (Docker, LAN, Managed) -------------------- */

  async function detectDiscoverDefaults() {
    try {
      const info = await apiFetch("/api/discover/info", { method: "GET" });
      if (info.default_subnet && $("lan-subnet-input") && !$("lan-subnet-input").value) {
        $("lan-subnet-input").value = info.default_subnet;
      }
      if (info.docker_socket && $("docker-socket-input")) {
        $("docker-socket-input").value = info.docker_socket;
      }
      if (info.docker_available) {
        runDockerScan(true);
      }
    } catch {
      /* ignore optional failure */
    }
  }

  async function runDockerScan(silent = false) {
    const sock = ($("docker-socket-input")?.value || "/var/run/docker.sock").trim();
    if (!silent) triggerLEDBusy("sweep", "Scan Docker", sock, 2500);
    try {
      const res = await apiFetch("/api/discover/docker", {
        method: "POST",
        body: JSON.stringify({ socket: sock })
      });
      state.dockerContainers = res.containers || [];
      renderDockerContainers();
      const applyBtn = $("docker-apply-btn");
      if (applyBtn) applyBtn.disabled = state.dockerContainers.length === 0;
      if ($("docker-scan-meta")) {
        $("docker-scan-meta").textContent = state.dockerContainers.length + " conteneur(s) détecté(s) sur " + (res.socket || sock);
      }
    } catch (e) {
      if ($("docker-scan-meta")) $("docker-scan-meta").textContent = "Erreur Docker : " + e.message;
      if (!silent) showToast("Erreur scan Docker : " + e.message, "err");
    }
  }

  function renderDockerContainers() {
    const el = $("docker-list");
    if (!el) return;
    if (!state.dockerContainers.length) {
      el.innerHTML = '<div class="empty-state">Aucun conteneur détecté sur ce socket Docker.</div>';
      return;
    }
    el.innerHTML = state.dockerContainers.map((c) => {
      const badgeCls = c.running ? "ok" : "danger";
      return (
        '<label class="surface-row" style="cursor:pointer;">' +
          '<div class="row-main">' +
            '<div class="row-title-line">' +
              '<input type="checkbox" data-docker-name="' + esc(c.name) + '"' + (c.monitored ? " checked" : "") + ' style="width:auto;min-height:auto;" />' +
              '<span class="row-title">' + esc(c.name) + "</span>" +
              '<span class="badge ' + badgeCls + '">' + esc(c.state || (c.running ? "running" : "stopped")) + "</span>" +
              (c.health ? '<span class="chip">' + esc(c.health) + "</span>" : "") +
            "</div>" +
            '<div class="row-sub">' + esc(c.image) + (c.ports && c.ports.length ? " · Ports : " + esc(c.ports.join(", ")) : "") + "</div>" +
          "</div>" +
          '<span class="mono" style="font-size:11px;color:var(--text-faint);">' + esc(c.status || "") + "</span>" +
        "</label>"
      );
    }).join("");
  }

  async function applyDockerSelection() {
    if (!state.draft) state.draft = ensureDraftShape(state.config);
    const selected = Array.from(document.querySelectorAll("[data-docker-name]:checked")).map((cb) => cb.dataset.dockerName);
    const sock = ($("docker-socket-input")?.value || "/var/run/docker.sock").trim();
    let dockerProbe = state.draft.probes.find((p) => p.kind === "docker");
    if (!selected.length) {
      state.draft.probes = state.draft.probes.filter((p) => p.kind !== "docker");
    } else if (dockerProbe) {
      dockerProbe.socket = sock;
      dockerProbe.containers = selected;
    } else {
      state.draft.probes.push({
        id: "conteneurs-docker",
        kind: "docker",
        socket: sock,
        containers: selected,
        interval: "30s",
        timeout: "10s"
      });
    }
    const saved = await saveConfiguration(false);
    if (saved) {
      await runDockerScan(true);
      showToast("Sonde Docker mise à jour (" + selected.length + " conteneurs).");
    }
  }

  async function runLANScan() {
    const subnet = ($("lan-subnet-input")?.value || "").trim();
    triggerLEDBusy("matrix", "Scan réseau LAN", subnet || "AUTO", 5500);
    if ($("lan-scan-meta")) $("lan-scan-meta").textContent = "Analyse du sous-réseau en cours…";
    try {
      const res = await apiFetch("/api/discover/lan", {
        method: "POST",
        body: JSON.stringify({
          subnet,
          docker_socket: ($("docker-socket-input")?.value || "").trim()
        })
      });
      state.lanItems = res.items || [];
      state.lanScanned = true;
      if (res.subnet && $("lan-subnet-input") && !$("lan-subnet-input").value) {
        $("lan-subnet-input").value = res.subnet;
      }
      if ($("lan-scan-meta")) {
        $("lan-scan-meta").textContent =
          state.lanItems.length + " service(s) détecté(s) sur " + (res.subnet || subnet) +
          " (" + (res.scanned_ips || 0) + " IP analysées en " + (res.duration_ms || 0) + " ms)";
      }
      renderLANItems();
    } catch (e) {
      if ($("lan-scan-meta")) $("lan-scan-meta").textContent = "Erreur scan LAN : " + e.message;
      showToast("Erreur scan LAN : " + e.message, "err");
    }
  }

  function matchesLANCategory(item, cat) {
    if (cat === "all") return true;
    const k = item.suggested_probe?.kind || item.category || "";
    if (cat === "hypervisor") return k === "proxmox";
    if (cat === "nas") return k === "synology";
    if (cat === "windows") return k === "windows_winrm" || k === "windows_exporter";
    if (cat === "linux") return k === "linux_ssh" || k === "node_exporter";
    if (cat === "exporter") return k === "node_exporter" || k === "windows_exporter";
    if (cat === "web") return k === "http" || k === "tcp";
    return true;
  }

  function renderLANItems() {
    const el = $("lan-list");
    if (!el) return;
    const cat = $("lan-category-filter")?.value || "all";
    const items = (state.lanItems || []).filter((it) => matchesLANCategory(it, cat));

    if (!state.lanScanned) {
      el.innerHTML = '<div class="empty-state">Lancez un scan pour découvrir Proxmox, NAS Synology, machines Windows/Linux et services HTTP.</div>';
      return;
    }
    if (!items.length) {
      el.innerHTML = '<div class="empty-state">Aucun hôte correspondant dans cette catégorie.</div>';
      return;
    }

    el.innerHTML = items.map((it) => (
      '<div class="surface-row">' +
        '<div class="row-main">' +
          '<div class="row-title-line">' +
            '<span class="row-title">' + esc(it.name || it.hostname || it.ip) + "</span>" +
            '<span class="chip">' + esc(it.category_label || it.suggested_probe?.kind || "Réseau") + "</span>" +
            (it.already_monitored ? '<span class="badge ok">Déjà supervisé</span>' : "") +
          "</div>" +
          '<div class="row-sub">' + esc(it.ip) + (it.hostname && it.hostname !== it.ip ? " (" + esc(it.hostname) + ")" : "") + " · " + esc(it.summary) + "</div>" +
        "</div>" +
        '<div class="row-right">' +
          '<button class="btn primary sm" type="button" data-lan-add="' + esc(it.key) + '">Configurer</button>' +
        "</div>" +
      "</div>"
    )).join("");

    el.querySelectorAll("[data-lan-add]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const found = (state.lanItems || []).find((it) => it.key === btn.dataset.lanAdd);
        if (found?.suggested_probe) openProbeModalFromTemplate(clone(found.suggested_probe));
      });
    });
  }

  function renderManagedProbes() {
    const el = $("managed-list");
    if (!el || !state.draft) return;
    const probes = state.draft.probes || [];
    const q = ($("managed-filter-input")?.value || "").toLowerCase();
    const list = probes.map((p, idx) => ({ p, idx })).filter(({ p }) => {
      if (!q) return true;
      return (p.id + " " + p.kind + " " + probeTargetLabel(p)).toLowerCase().includes(q);
    });
    if (!list.length) {
      el.innerHTML = '<div class="empty-state">Aucune sonde configurée.</div>';
      return;
    }
    const statusMap = {};
    (state.status?.probes || []).forEach((s) => { statusMap[s.id] = s; });

    el.innerHTML = list.map(({ p, idx }) => {
      const rt = statusMap[p.id];
      return (
        '<div class="surface-row">' +
          '<div class="row-main">' +
            '<div class="row-title-line">' +
              '<span class="status-dot ' + (rt ? (rt.ok ? "is-ok" : "is-err") : "is-muted") + '"></span>' +
              '<span class="row-title">' + esc(p.id) + "</span>" +
              '<span class="chip">' + esc(PROBE_KINDS[p.kind]?.label || p.kind) + "</span>" +
            "</div>" +
            '<div class="row-sub">' + esc(probeTargetLabel(p)) + (rt ? " · " + esc(rt.summary) : "") + "</div>" +
          "</div>" +
          '<div class="row-right">' +
            '<button class="inline-action" type="button" data-mg-test="' + esc(p.id) + '">Tester</button>' +
            '<button class="inline-action" type="button" data-mg-edit="' + idx + '">Modifier</button>' +
            '<button class="inline-danger" type="button" data-mg-del="' + idx + '">Supprimer</button>' +
          "</div>" +
        "</div>"
      );
    }).join("");

    el.querySelectorAll("[data-mg-test]").forEach((b) => b.addEventListener("click", () => quickTestProbeByID(b.dataset.mgTest)));
    el.querySelectorAll("[data-mg-edit]").forEach((b) => b.addEventListener("click", () => openProbeModal(Number(b.dataset.mgEdit))));
    el.querySelectorAll("[data-mg-del]").forEach((b) => {
      b.addEventListener("click", async () => {
        const idx = Number(b.dataset.mgDel);
        const removed = state.draft.probes.splice(idx, 1);
        await saveConfiguration(false);
        showToast("Sonde supprimée : " + (removed[0]?.id || ""));
      });
    });
  }

  /* -------------------- Probe Modal (All 10 ProbeDTO Kinds) -------------------- */

  function openProbeModal(editIndex = -1) {
    state.editingIndex = editIndex;
    const modal = $("probe-modal");
    if (!modal) return;
    $("probe-test-banner").hidden = true;

    if (editIndex >= 0 && state.draft?.probes?.[editIndex]) {
      const p = clone(state.draft.probes[editIndex]);
      showProbeForm(p.kind || "http", p, "Modifier « " + p.id + " »");
    } else {
      $("probe-modal-title").textContent = "Nouvelle sonde";
      $("probe-modal-sub").textContent = "Choisissez le type de machine, d'hyperviseur ou de service à surveiller.";
      $("probe-step-kind").hidden = false;
      $("probe-form").hidden = true;
    }
    modal.hidden = false;
  }

  function openProbeModalFromTemplate(tmpl) {
    state.editingIndex = -1;
    const modal = $("probe-modal");
    if (!modal) return;
    $("probe-test-banner").hidden = true;
    showProbeForm(tmpl.kind || "http", tmpl, "Configurer « " + (tmpl.id || "nouvelle sonde") + " »");
    modal.hidden = false;
  }

  function syncSNMPVersionFields() {
    const ver = $("pf-snmp-version")?.value || "2c";
    const v2El = $("pf-snmp-v2");
    const v3El = $("pf-snmp-v3");
    if (v2El) v2El.hidden = ver === "3";
    if (v3El) v3El.hidden = ver !== "3";
  }

  function snmpFieldsHTML(preset) {
    const ver = String(preset.snmp_version || "2c") === "3" ? "3" : "2c";
    const authOpts = ["NONE", "MD5", "SHA", "SHA256", "SHA512"]
      .map((a) => '<option value="' + a + '"' + ((preset.auth_proto || "SHA256").toUpperCase() === a ? " selected" : "") + ">" + a + "</option>")
      .join("");
    const privOpts = ["NONE", "DES", "AES", "AES192", "AES256"]
      .map((a) => '<option value="' + a + '"' + ((preset.priv_proto || "AES").toUpperCase() === a ? " selected" : "") + ">" + a + "</option>")
      .join("");

    return (
      '<div class="form-grid three-col">' +
        '<label class="field"><span class="field-label">IP / Hôte SNMP</span><input type="text" id="pf-host" value="' + esc(preset.host || "") + '" placeholder="192.168.1.20" required /></label>' +
        '<label class="field"><span class="field-label">Port UDP</span><input type="number" id="pf-port" value="' + esc(preset.port || 161) + '" /></label>' +
        '<label class="field"><span class="field-label">Version SNMP</span><select id="pf-snmp-version"><option value="2c"' + (ver === "2c" ? " selected" : "") + '>SNMP v2c</option><option value="3"' + (ver === "3" ? " selected" : "") + ">SNMP v3 (chiffré)</option></select></label>" +
      "</div>" +
      '<div id="pf-snmp-v2"' + (ver === "3" ? " hidden" : "") + ">" +
        '<label class="field"><span class="field-label">Communauté SNMP</span><input type="text" id="pf-community" value="' + esc(preset.community || "public") + '" /></label>' +
      "</div>" +
      '<div id="pf-snmp-v3" class="form-grid"' + (ver === "3" ? "" : " hidden") + ">" +
        '<div class="form-grid three-col">' +
          '<label class="field"><span class="field-label">Utilisateur SNMPv3</span><input type="text" id="pf-snmp-user" value="' + esc(preset.user || "") + '" /></label>' +
          '<label class="field"><span class="field-label">Protocole Auth</span><select id="pf-auth-proto">' + authOpts + "</select></label>" +
          '<label class="field"><span class="field-label">Mot de passe Auth</span><input type="password" id="pf-auth-pass" value="' + esc(preset.auth_pass || "") + '" /></label>' +
        "</div>" +
        '<div class="form-grid two-col">' +
          '<label class="field"><span class="field-label">Protocole Chiffrement</span><select id="pf-priv-proto">' + privOpts + "</select></label>" +
          '<label class="field"><span class="field-label">Mot de passe Priv</span><input type="password" id="pf-priv-pass" value="' + esc(preset.priv_pass || "") + '" /></label>' +
        "</div>" +
      "</div>"
    );
  }

  function showProbeForm(kind, preset = {}, titleOverride = null) {
    state.modalKind = kind;
    $("probe-step-kind").hidden = true;
    $("probe-form").hidden = false;
    $("probe-back-kind-btn").hidden = state.editingIndex >= 0;
    $("probe-modal-title").textContent = titleOverride || ("Nouvelle sonde · " + (PROBE_KINDS[kind]?.label || kind));
    $("probe-modal-sub").textContent = PROBE_KINDS[kind]?.label || kind;

    const guide = PROBE_GUIDES[kind];
    const gBox = $("probe-guide-box");
    if (gBox) {
      gBox.hidden = !guide;
      gBox.textContent = guide || "";
    }

    $("pf-interval").value = preset.interval || (kind === "http" || kind === "tcp" || kind === "docker" ? "30s" : "1m");
    $("pf-timeout").value = preset.timeout || (kind === "windows_winrm" || kind === "linux_ssh" ? "15s" : "10s");
    $("pf-insecure").checked = Boolean(preset.insecure_skip_verify);

    const fields = $("probe-form-fields");
    let html =
      '<label class="field">' +
        '<span class="field-label">Nom affiché (identifiant unique)</span>' +
        '<input type="text" id="pf-id" value="' + esc(preset.id || "") + '" placeholder="Ex. proxmox-principal" required />' +
      "</label>";

    if (kind === "http") {
      html +=
        '<label class="field"><span class="field-label">URL cible</span><input type="url" id="pf-url" value="' + esc(preset.url || "") + '" placeholder="https://mon-service.local" required /></label>' +
        '<div class="form-grid three-col">' +
          '<label class="field"><span class="field-label">Code HTTP attendu</span><input type="number" id="pf-http-status" value="' + esc(preset.expected_status || 200) + '" /></label>' +
          '<label class="field"><span class="field-label">Texte attendu (opt.)</span><input type="text" id="pf-contains" value="' + esc(preset.contains || "") + '" placeholder="healthy" /></label>' +
          '<label class="field"><span class="field-label">Alerte TLS (jours)</span><input type="number" id="pf-tls-days" value="' + esc(preset.tls_min_days != null ? preset.tls_min_days : 14) + '" /></label>' +
        "</div>";
    } else if (kind === "tcp") {
      const hp = preset.host ? { host: preset.host, port: preset.port || 22 } : splitHostPort(preset.address, 22);
      html +=
        '<div class="form-grid two-col">' +
          '<label class="field"><span class="field-label">Hôte / IP</span><input type="text" id="pf-host" value="' + esc(hp.host) + '" placeholder="192.168.1.10" required /></label>' +
          '<label class="field"><span class="field-label">Port TCP</span><input type="number" id="pf-port" value="' + esc(hp.port || 22) + '" required /></label>' +
        "</div>";
    } else if (kind === "docker") {
      html +=
        '<label class="field"><span class="field-label">Socket Docker</span><input type="text" id="pf-socket" value="' + esc(preset.socket || "/var/run/docker.sock") + '" /></label>' +
        '<label class="field"><span class="field-label">Conteneurs à surveiller (séparés par virgule)</span><input type="text" id="pf-containers" value="' + esc((preset.containers || []).join(", ")) + '" placeholder="traefik, postgres, caddy" /></label>' +
        '<div class="form-grid two-col">' +
          '<label class="field"><span class="field-label">Label filtre (opt.)</span><input type="text" id="pf-label" value="' + esc(preset.label || "") + '" placeholder="meshwatch.enable=true" /></label>' +
          '<label class="field"><span class="field-label">Restarts max tolérés (opt.)</span><input type="number" id="pf-max-restarts" value="' + esc(preset.max_restarts || "") + '" placeholder="0" /></label>' +
        "</div>";
    } else if (kind === "synology") {
      html += snmpFieldsHTML(preset) +
        '<label class="field"><span class="field-label">Température maximale disques/système (°C)</span><input type="number" id="pf-max-temp" value="' + esc(preset.max_temp_c || 55) + '" /></label>';
    } else if (kind === "snmp_oid") {
      html += snmpFieldsHTML(preset) +
        '<div class="form-grid two-col">' +
          '<label class="field"><span class="field-label">OID SNMP</span><input type="text" id="pf-oid" class="mono" value="' + esc(preset.oid || ".1.3.6.1.2.1.1.3.0") + '" required /></label>' +
          '<label class="field"><span class="field-label">Valeur attendue (opt.)</span><input type="text" id="pf-expected-value" value="' + esc(preset.expected_value || "") + '" /></label>' +
        "</div>" +
        '<div class="form-grid two-col">' +
          '<label class="field"><span class="field-label">Valeur min (opt.)</span><input type="number" step="any" id="pf-min-value" value="' + esc(preset.min_value != null ? preset.min_value : "") + '" /></label>' +
          '<label class="field"><span class="field-label">Valeur max (opt.)</span><input type="number" step="any" id="pf-max-value" value="' + esc(preset.max_value != null ? preset.max_value : "") + '" /></label>' +
        "</div>";
    } else if (kind === "proxmox") {
      html +=
        '<div class="form-grid two-col">' +
          '<label class="field"><span class="field-label">IP ou URL Proxmox VE</span><input type="text" id="pf-url" value="' + esc(preset.url || "") + '" placeholder="https://192.168.1.10:8006" required /></label>' +
          '<label class="field"><span class="field-label">Nœud Proxmox (opt.)</span><input type="text" id="pf-node" value="' + esc(preset.node || "") + '" placeholder="pve (tous si vide)" /></label>' +
        "</div>" +
        '<div class="form-grid two-col">' +
          '<label class="field"><span class="field-label">Token ID</span><input type="text" id="pf-token-id" class="mono" value="' + esc(preset.token_id || "") + '" placeholder="root@pam!meshwatch" /></label>' +
          '<label class="field"><span class="field-label">Token Secret</span><input type="password" id="pf-token-secret" class="mono" value="' + esc(preset.token_secret || "") + '" /></label>' +
        "</div>" +
        '<div class="form-grid three-col">' +
          '<label class="field"><span class="field-label">Seuil CPU (%)</span><input type="number" id="pf-max-cpu" value="' + esc(preset.max_cpu_percent || 90) + '" /></label>' +
          '<label class="field"><span class="field-label">Seuil RAM (%)</span><input type="number" id="pf-max-ram" value="' + esc(preset.max_ram_percent || 90) + '" /></label>' +
          '<label class="field"><span class="field-label">Seuil Disque (%)</span><input type="number" id="pf-max-disk" value="' + esc(preset.max_disk_percent || 90) + '" /></label>' +
        "</div>" +
        '<div class="form-grid two-col">' +
          '<label class="field"><span class="field-label">VM ou conteneurs LXC critiques (VMID ou noms)</span><input type="text" id="pf-vms" value="' + esc((preset.vms || []).join(", ")) + '" placeholder="100, 101" /></label>' +
          '<label class="field"><span class="field-label">Stockages surveillés (opt.)</span><input type="text" id="pf-disks" value="' + esc((preset.disks || []).join(", ")) + '" placeholder="local, local-lvm" /></label>' +
        "</div>";
    } else if (kind === "windows_winrm") {
      html +=
        '<div class="form-grid three-col">' +
          '<label class="field"><span class="field-label">Hôte ou IP Windows</span><input type="text" id="pf-host" value="' + esc(preset.host || "") + '" placeholder="192.168.1.40" required /></label>' +
          '<label class="field"><span class="field-label">Port WinRM</span><input type="number" id="pf-port" value="' + esc(preset.port || 5985) + '" /></label>' +
          '<label class="field" style="justify-content:flex-end;"><span class="checkbox-line"><input type="checkbox" id="pf-use-https"' + (preset.use_https ? " checked" : "") + ' /><span>WinRM HTTPS (5986)</span></span></label>' +
        "</div>" +
        '<div class="form-grid three-col">' +
          '<label class="field"><span class="field-label">Utilisateur Windows</span><input type="text" id="pf-user" value="' + esc(preset.user || "Administrator") + '" /></label>' +
          '<label class="field"><span class="field-label">Mot de passe</span><input type="password" id="pf-password" value="' + esc(preset.password || "") + '" /></label>' +
          '<label class="field"><span class="field-label">Domaine AD (opt.)</span><input type="text" id="pf-domain" value="' + esc(preset.domain || "") + '" placeholder="CORP" /></label>' +
        "</div>" +
        '<div class="form-grid three-col">' +
          '<label class="field"><span class="field-label">Seuil CPU (%)</span><input type="number" id="pf-max-cpu" value="' + esc(preset.max_cpu_percent || 90) + '" /></label>' +
          '<label class="field"><span class="field-label">Seuil RAM (%)</span><input type="number" id="pf-max-ram" value="' + esc(preset.max_ram_percent || 90) + '" /></label>' +
          '<label class="field"><span class="field-label">Seuil Disque (%)</span><input type="number" id="pf-max-disk" value="' + esc(preset.max_disk_percent || 90) + '" /></label>' +
        "</div>" +
        '<div class="form-grid three-col">' +
          '<label class="field"><span class="field-label">VMs Hyper-V (opt.)</span><input type="text" id="pf-vms" value="' + esc((preset.vms || []).join(", ")) + '" placeholder="DC01, SQL01" /></label>' +
          '<label class="field"><span class="field-label">Services Windows (opt.)</span><input type="text" id="pf-services" value="' + esc((preset.services || []).join(", ")) + '" placeholder="W3SVC, Spooler" /></label>' +
          '<label class="field"><span class="field-label">Lecteurs (opt.)</span><input type="text" id="pf-disks" value="' + esc((preset.disks || []).join(", ")) + '" placeholder="C:, D:" /></label>' +
        "</div>";
    } else if (kind === "linux_ssh") {
      html +=
        '<div class="form-grid three-col">' +
          '<label class="field"><span class="field-label">Hôte ou IP SSH</span><input type="text" id="pf-host" value="' + esc(preset.host || "") + '" placeholder="192.168.1.45" required /></label>' +
          '<label class="field"><span class="field-label">Port SSH</span><input type="number" id="pf-port" value="' + esc(preset.port || 22) + '" /></label>' +
          '<label class="field"><span class="field-label">Utilisateur SSH</span><input type="text" id="pf-user" value="' + esc(preset.user || "root") + '" /></label>' +
        "</div>" +
        '<label class="field"><span class="field-label">Mot de passe SSH (ou laissez vide si clé)</span><input type="password" id="pf-password" value="' + esc(preset.password || "") + '" /></label>' +
        '<label class="field"><span class="field-label">Clé privée SSH PEM / OpenSSH (optionnel)</span><textarea id="pf-ssh-key" rows="3" class="mono" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----">' + esc(preset.ssh_key || "") + "</textarea></label>" +
        '<div class="form-grid three-col">' +
          '<label class="field"><span class="field-label">Seuil CPU (%)</span><input type="number" id="pf-max-cpu" value="' + esc(preset.max_cpu_percent || 90) + '" /></label>' +
          '<label class="field"><span class="field-label">Seuil RAM (%)</span><input type="number" id="pf-max-ram" value="' + esc(preset.max_ram_percent || 90) + '" /></label>' +
          '<label class="field"><span class="field-label">Seuil Disque (%)</span><input type="number" id="pf-max-disk" value="' + esc(preset.max_disk_percent || 90) + '" /></label>' +
        "</div>" +
        '<div class="form-grid two-col">' +
          '<label class="field"><span class="field-label">Services systemd critiques (opt.)</span><input type="text" id="pf-services" value="' + esc((preset.services || []).join(", ")) + '" placeholder="docker, nginx" /></label>' +
          '<label class="field"><span class="field-label">Points de montage (opt.)</span><input type="text" id="pf-disks" value="' + esc((preset.disks || []).join(", ")) + '" placeholder="/, /var" /></label>' +
        "</div>";
    } else if (kind === "node_exporter" || kind === "windows_exporter") {
      const defPort = kind === "windows_exporter" ? "9182" : "9100";
      html +=
        '<label class="field"><span class="field-label">URL Metrics Exporter</span><input type="url" id="pf-url" value="' + esc(preset.url || "") + '" placeholder="http://192.168.1.10:' + defPort + '/metrics" required /></label>' +
        '<div class="form-grid three-col">' +
          '<label class="field"><span class="field-label">Seuil RAM (%)</span><input type="number" id="pf-max-ram" value="' + esc(preset.max_ram_percent || 92) + '" /></label>' +
          '<label class="field"><span class="field-label">Seuil Disque (%)</span><input type="number" id="pf-max-disk" value="' + esc(preset.max_disk_percent || 90) + '" /></label>' +
          '<label class="field"><span class="field-label">Disques / montages (opt.)</span><input type="text" id="pf-disks" value="' + esc((preset.disks || []).join(", ")) + '" placeholder="' + (kind === "windows_exporter" ? "C:, D:" : "/, /home") + '" /></label>' +
        "</div>";
      if (kind === "windows_exporter") {
        html += '<label class="field"><span class="field-label">Services Windows critiques (opt.)</span><input type="text" id="pf-services" value="' + esc((preset.services || []).join(", ")) + '" placeholder="W3SVC, W32Time" /></label>';
      }
    }

    fields.innerHTML = html;
    $("pf-snmp-version")?.addEventListener("change", syncSNMPVersionFields);
  }

  function readSNMPFields(obj) {
    obj.host = ($("pf-host")?.value || "").trim();
    obj.port = Number($("pf-port")?.value) || 161;
    obj.snmp_version = $("pf-snmp-version")?.value || "2c";
    if (obj.snmp_version === "3") {
      obj.user = ($("pf-snmp-user")?.value || "").trim();
      obj.auth_proto = $("pf-auth-proto")?.value || "SHA256";
      obj.auth_pass = $("pf-auth-pass")?.value || "";
      obj.priv_proto = $("pf-priv-proto")?.value || "AES";
      obj.priv_pass = $("pf-priv-pass")?.value || "";
    } else {
      obj.community = ($("pf-community")?.value || "public").trim();
    }
  }

  function readProbeFormObject() {
    const kind = state.modalKind;
    const obj = {
      id: ($("pf-id")?.value || "").trim(),
      kind,
      interval: ($("pf-interval")?.value || "").trim() || "1m",
      timeout: ($("pf-timeout")?.value || "").trim() || "10s"
    };

    if (kind === "http") {
      obj.url = ($("pf-url")?.value || "").trim();
      obj.expected_status = Number($("pf-http-status")?.value) || 200;
      const contains = ($("pf-contains")?.value || "").trim();
      if (contains) obj.contains = contains;
      const tlsRaw = ($("pf-tls-days")?.value || "").trim();
      if (tlsRaw !== "") obj.tls_min_days = Number(tlsRaw);
      obj.insecure_skip_verify = Boolean($("pf-insecure")?.checked);
    } else if (kind === "tcp") {
      const hostVal = ($("pf-host")?.value || "").trim();
      const portVal = Number($("pf-port")?.value) || 22;
      obj.host = hostVal;
      obj.port = portVal;
      obj.address = hostVal ? hostVal + ":" + portVal : "";
    } else if (kind === "docker") {
      obj.socket = ($("pf-socket")?.value || "/var/run/docker.sock").trim();
      obj.containers = splitCSV($("pf-containers")?.value);
      const lbl = ($("pf-label")?.value || "").trim();
      if (lbl) obj.label = lbl;
      const mr = Number($("pf-max-restarts")?.value);
      if (mr > 0) obj.max_restarts = mr;
    } else if (kind === "synology") {
      readSNMPFields(obj);
      obj.max_temp_c = Number($("pf-max-temp")?.value) || 55;
    } else if (kind === "snmp_oid") {
      readSNMPFields(obj);
      obj.oid = ($("pf-oid")?.value || "").trim();
      const ev = ($("pf-expected-value")?.value || "").trim();
      if (ev) obj.expected_value = ev;
      const minRaw = ($("pf-min-value")?.value || "").trim();
      if (minRaw !== "" && !Number.isNaN(Number(minRaw))) obj.min_value = Number(minRaw);
      const maxRaw = ($("pf-max-value")?.value || "").trim();
      if (maxRaw !== "" && !Number.isNaN(Number(maxRaw))) obj.max_value = Number(maxRaw);
    } else if (kind === "proxmox") {
      obj.url = ($("pf-url")?.value || "").trim();
      const node = ($("pf-node")?.value || "").trim();
      if (node) obj.node = node;
      obj.insecure_skip_verify = Boolean($("pf-insecure")?.checked);
      obj.token_id = ($("pf-token-id")?.value || "").trim();
      obj.token_secret = ($("pf-token-secret")?.value || "").trim();
      obj.max_cpu_percent = Number($("pf-max-cpu")?.value) || 0;
      obj.max_ram_percent = Number($("pf-max-ram")?.value) || 0;
      obj.max_disk_percent = Number($("pf-max-disk")?.value) || 0;
      obj.vms = splitCSV($("pf-vms")?.value);
      obj.disks = splitCSV($("pf-disks")?.value);
    } else if (kind === "windows_winrm") {
      obj.host = ($("pf-host")?.value || "").trim();
      obj.port = Number($("pf-port")?.value) || ($("pf-use-https")?.checked ? 5986 : 5985);
      obj.use_https = Boolean($("pf-use-https")?.checked);
      obj.insecure_skip_verify = Boolean($("pf-insecure")?.checked);
      obj.domain = ($("pf-domain")?.value || "").trim();
      obj.user = ($("pf-user")?.value || "").trim();
      obj.password = $("pf-password")?.value || "";
      obj.max_cpu_percent = Number($("pf-max-cpu")?.value) || 0;
      obj.max_ram_percent = Number($("pf-max-ram")?.value) || 0;
      obj.max_disk_percent = Number($("pf-max-disk")?.value) || 0;
      obj.vms = splitCSV($("pf-vms")?.value);
      obj.services = splitCSV($("pf-services")?.value);
      obj.disks = splitCSV($("pf-disks")?.value);
    } else if (kind === "linux_ssh") {
      obj.host = ($("pf-host")?.value || "").trim();
      obj.port = Number($("pf-port")?.value) || 22;
      obj.user = ($("pf-user")?.value || "").trim();
      obj.password = $("pf-password")?.value || "";
      obj.ssh_key = $("pf-ssh-key")?.value || "";
      obj.max_cpu_percent = Number($("pf-max-cpu")?.value) || 0;
      obj.max_ram_percent = Number($("pf-max-ram")?.value) || 0;
      obj.max_disk_percent = Number($("pf-max-disk")?.value) || 0;
      obj.services = splitCSV($("pf-services")?.value);
      obj.disks = splitCSV($("pf-disks")?.value);
    } else if (kind === "node_exporter" || kind === "windows_exporter") {
      obj.url = ($("pf-url")?.value || "").trim();
      obj.max_ram_percent = Number($("pf-max-ram")?.value) || 0;
      obj.max_disk_percent = Number($("pf-max-disk")?.value) || 0;
      obj.disks = splitCSV($("pf-disks")?.value);
      if (kind === "windows_exporter") obj.services = splitCSV($("pf-services")?.value);
    }
    return obj;
  }

  async function runModalProbeTest() {
    const probe = readProbeFormObject();
    const banner = $("probe-test-banner");
    if (!banner) return;
    banner.hidden = false;
    banner.className = "test-banner";
    banner.textContent = "Test de connexion en cours…";
    triggerLEDBusy("orbit", "Test sonde", probe.id || probe.kind, 2400);

    try {
      const res = await apiFetch("/api/probes/test", {
        method: "POST",
        body: JSON.stringify({ probe })
      });
      banner.className = "test-banner " + (res.ok ? "is-ok" : "is-err");
      let details = (res.ok ? "Succès : " : "Échec : ") + (res.summary || "—") + " (" + res.latency_ms + " ms)";
      if (res.metrics) {
        const m = res.metrics;
        const extras = [];
        if (typeof m.cpu_percent === "number") extras.push("CPU " + m.cpu_percent.toFixed(1) + "%");
        if (typeof m.ram_percent === "number") extras.push("RAM " + m.ram_percent.toFixed(1) + "%");
        if (typeof m.disk_max_pct === "number") extras.push("Disque " + m.disk_max_pct.toFixed(1) + "%");
        if (m.guests?.length) extras.push(m.guests.length + " VM(s)");
        if (m.disks?.length) extras.push(m.disks.length + " volume(s)");
        if (extras.length) details += "\nTélémétrie : " + extras.join(" · ");
      }
      banner.textContent = details;
      banner.style.whiteSpace = "pre-line";
    } catch (e) {
      banner.className = "test-banner is-err";
      banner.textContent = "Erreur test : " + e.message;
    }
  }

  async function submitProbeModal(e) {
    e.preventDefault();
    const probe = readProbeFormObject();
    if (!probe.id) {
      showToast("Indiquez un nom de sonde.", "warn");
      return;
    }
    state.draft = ensureDraftShape(state.draft || state.config);
    if (state.editingIndex >= 0) {
      state.draft.probes[state.editingIndex] = probe;
    } else {
      state.draft.probes.push(probe);
    }
    $("probe-modal").hidden = true;
    selectProbe(probe.id, false);
    const saved = await saveConfiguration(false);
    if (saved) showToast("Sonde « " + probe.id + " » enregistrée.");
  }

  /* -------------------- View 03: Friends & Invites + Peer Drawer -------------------- */

  function encodeInvite(cfg) {
    const node = cfg?.node;
    if (!node || !node.private_key_hex || !node.group_psk_hex) return "";
    const pub = state.status?.pubkey_hex || node.pubkey_hex || "";
    if (!pub) return "";
    const payload = {
      name: node.name || "MeshWatch",
      pubkey: pub,
      psk: node.group_psk_hex
    };
    const json = JSON.stringify(payload);
    const bytes = new TextEncoder().encode(json);
    let bin = "";
    bytes.forEach((b) => { bin += String.fromCharCode(b); });
    return "MW1-" + btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decodeInvite(raw) {
    const clean = String(raw || "").trim();
    if (!clean) return null;
    if (/^[0-9a-fA-F]{64}$/.test(clean)) {
      return { name: "", pubkey_hex: clean.toLowerCase(), group_psk_hex: "" };
    }
    if (!clean.startsWith("MW1-")) return null;
    try {
      let b64 = clean.slice(4).replace(/-/g, "+").replace(/_/g, "/");
      while (b64.length % 4) b64 += "=";
      const bin = atob(b64);
      const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      const obj = JSON.parse(new TextDecoder().decode(bytes));
      const pub = obj.pubkey || obj.pubkey_hex || obj.pk || "";
      const psk = obj.psk || obj.group_psk_hex || "";
      if (!/^[0-9a-fA-F]{64}$/.test(pub)) return null;
      return {
        name: String(obj.name || "Ami MeshWatch").trim() || "Ami MeshWatch",
        pubkey_hex: pub.toLowerCase(),
        group_psk_hex: /^[0-9a-fA-F]{64}$/.test(psk) ? psk.toLowerCase() : ""
      };
    } catch {
      return null;
    }
  }

  function renderFriendsView(st) {
    const inviteEl = $("my-invite-code");
    if (inviteEl && state.config) {
      inviteEl.value = encodeInvite(state.config) || "Clés non encore initialisées";
    }
    const peers = st.peers || [];
    if ($("friends-count")) $("friends-count").textContent = String(peers.length);

    const listEl = $("friends-list");
    if (!listEl) return;
    if (!peers.length) {
      listEl.innerHTML = '<div class="empty-state">Aucun ami connecté. Partagez votre code d\'invitation ci-dessus ou acceptez le sien.</div>';
      return;
    }

    listEl.innerHTML = peers.map((p) => {
      let badgeCls = "";
      let statusLabel = "EN ATTENTE";
      if (p.timed_out) { badgeCls = "danger"; statusLabel = "HORS LIGNE"; }
      else if (p.online && !p.overall_ok) { badgeCls = "warn"; statusLabel = "ALERTE CHEZ LUI"; }
      else if (p.online) { badgeCls = "ok"; statusLabel = "EN LIGNE"; }

      return (
        '<div class="surface-row">' +
          '<div class="row-main">' +
            '<div class="row-title-line">' +
              '<span class="row-title">' + esc(p.name) + "</span>" +
              '<span class="badge ' + badgeCls + '">' + statusLabel + "</span>" +
              '<span class="chip">' + esc((p.probes || []).length) + " sondes</span>" +
            "</div>" +
            '<div class="row-sub">' + esc((p.pubkey_hex || "").slice(0, 18)) + "… · Dernier signal : " + esc(fmtAge(p.last_seen)) + " · Uptime " + esc(fmtUptime(p.uptime_sec)) + "</div>" +
          "</div>" +
          '<div class="row-right">' +
            MW().uptimeStripHTML(p.history || [], true, 14) +
            '<button class="inline-action" type="button" data-peer-inspect="' + esc(p.pubkey_hex) + '">Inspecter</button>' +
            '<button class="inline-danger" type="button" data-peer-remove="' + esc(p.pubkey_hex) + '">Retirer</button>' +
          "</div>" +
        "</div>"
      );
    }).join("");

    listEl.querySelectorAll("[data-peer-inspect]").forEach((b) => {
      b.addEventListener("click", () => openPeerDrawer(b.dataset.peerInspect));
    });
    listEl.querySelectorAll("[data-peer-remove]").forEach((b) => {
      b.addEventListener("click", async () => {
        if (!state.draft?.peers) return;
        state.draft.peers = state.draft.peers.filter((pr) => pr.pubkey_hex !== b.dataset.peerRemove);
        await saveConfiguration(false);
        showToast("Pair retiré de votre liste.");
      });
    });
  }

  function openPeerDrawer(pubkeyHex) {
    const peer = (state.status?.peers || []).find((p) => p.pubkey_hex === pubkeyHex);
    if (!peer) return;
    $("peer-drawer-name").textContent = peer.name || "Ami MeshWatch";
    $("peer-drawer-sub").textContent = (peer.node_name ? peer.node_name + " · " : "") + pubkeyHex.slice(0, 22) + "…";

    let bodyHTML =
      '<div class="res-item" style="margin-bottom:14px;">' +
        '<div class="res-group-title">Historique de présence (derniers battements)</div>' +
        MW().uptimeStripHTML(peer.history || [], true, 28) +
      "</div>" +
      '<div class="res-item" style="margin-bottom:14px;"><dl class="kv">' +
        "<dt>Statut</dt><dd>" + (peer.timed_out ? "Hors ligne (timeout)" : peer.online ? (peer.overall_ok ? "Opérationnel" : "Alerte détectée") : "En attente du 1er signal") + "</dd>" +
        "<dt>Dernier battement</dt><dd>" + esc(fmtAge(peer.last_seen)) + "</dd>" +
        "<dt>Uptime nœud</dt><dd>" + esc(fmtUptime(peer.uptime_sec)) + "</dd>" +
        '<dt>Clé Nostr</dt><dd class="mono">' + esc(pubkeyHex) + "</dd>" +
      "</dl></div>";

    const probes = peer.probes || [];
    bodyHTML += '<div class="res-group-title">Sondes reçues de cet ami (' + probes.length + ")</div>";
    if (!probes.length) {
      bodyHTML += '<div class="empty-state">Aucune sonde transmise pour le moment.</div>';
    } else {
      bodyHTML += probes.map((pr) => (
        '<div class="res-item" style="margin-bottom:8px;">' +
          '<div class="res-item-row"><strong>' + esc(pr.id) + '</strong><span class="badge ' + (pr.ok ? "ok" : "danger") + '">' + (pr.ok ? "OK" : "PANNE") + "</span></div>" +
          '<div class="mono" style="font-size:11px;color:var(--text-muted);">' + esc(pr.summary) + " (" + esc(pr.latency_ms) + " ms)</div>" +
        "</div>"
      )).join("");
    }

    $("peer-drawer-body").innerHTML = bodyHTML;
    $("peer-drawer-backdrop").hidden = false;
    $("peer-drawer").hidden = false;
  }

  function closePeerDrawer() {
    $("peer-drawer-backdrop").hidden = true;
    $("peer-drawer").hidden = true;
  }

  /* -------------------- Forms Sync (Alerts & Settings -> ConfigDTO) -------------------- */

  function inferPhotonMode(ph) {
    if (!ph) return "cloud";
    const m = String(ph.mode || "").toLowerCase().trim();
    if (m === "cloud" || m === "spectrum") return "cloud";
    if (m === "proxy" || m === "custom") return m;
    if (ph.project_id || String(ph.api_key || "").startsWith("pho_")) return "cloud";
    if (ph.server_url || String(ph.url || "").includes("imessage-swagger.photon.codes")) return "proxy";
    if (ph.url && ph.recipient) return "custom";
    return "cloud";
  }

  function syncPhotonFieldsVisibility() {
    const mode = $("photon-mode")?.value || "cloud";
    if ($("photon-mode-cloud")) $("photon-mode-cloud").hidden = mode !== "cloud";
    if ($("photon-mode-proxy")) $("photon-mode-proxy").hidden = mode !== "proxy";
    if ($("photon-mode-custom")) $("photon-mode-custom").hidden = mode !== "custom";
  }

  function renderConfigForms() {
    const cfg = ensureDraftShape(state.draft);
    state.draft = cfg;

    const ntfy = cfg.notifications.ntfy || {};
    if ($("ntfy-enabled")) $("ntfy-enabled").checked = Boolean(ntfy.enabled);
    if ($("ntfy-url")) $("ntfy-url").value = ntfy.url || "";
    if ($("ntfy-topic")) $("ntfy-topic").value = ntfy.topic || "";
    if ($("ntfy-token")) $("ntfy-token").value = ntfy.token || "";

    const ph = cfg.notifications.photon_imessage || {};
    if ($("photon-enabled")) $("photon-enabled").checked = Boolean(ph.enabled);
    const pMode = inferPhotonMode(ph);
    if ($("photon-mode")) $("photon-mode").value = pMode;
    syncPhotonFieldsVisibility();

    if ($("photon-project-id")) $("photon-project-id").value = ph.project_id || "";
    if ($("photon-api-key")) $("photon-api-key").value = ph.api_key || (pMode === "cloud" ? ph.token || "" : "");
    if ($("photon-recipient")) $("photon-recipient").value = ph.recipient || "";
    if ($("photon-cloud-url")) $("photon-cloud-url").value = pMode === "cloud" ? (ph.url || "") : "";
    if ($("photon-sender-id")) $("photon-sender-id").value = ph.sender_id || "";
    if ($("photon-space-id")) $("photon-space-id").value = ph.space_id || "";

    if ($("photon-server-url")) $("photon-server-url").value = ph.server_url || "";
    if ($("photon-proxy-key")) $("photon-proxy-key").value = pMode === "proxy" ? (ph.api_key || "") : "";
    if ($("photon-proxy-recipient")) $("photon-proxy-recipient").value = ph.recipient || "";
    if ($("photon-proxy-url")) $("photon-proxy-url").value = pMode === "proxy" ? (ph.url || "https://imessage-swagger.photon.codes") : "https://imessage-swagger.photon.codes";
    if ($("photon-proxy-token")) $("photon-proxy-token").value = pMode === "proxy" ? (ph.token || "") : "";

    if ($("photon-custom-url")) $("photon-custom-url").value = pMode === "custom" ? (ph.url || "") : "";
    if ($("photon-custom-recipient")) $("photon-custom-recipient").value = ph.recipient || "";
    if ($("photon-custom-token")) $("photon-custom-token").value = pMode === "custom" ? (ph.token || "") : "";
    if ($("photon-rec-field")) $("photon-rec-field").value = ph.recipient_field || "recipient";
    if ($("photon-msg-field")) $("photon-msg-field").value = ph.message_field || "message";

    const node = cfg.node || {};
    if ($("set-node-name")) $("set-node-name").value = node.name || "";
    if ($("set-pubkey")) $("set-pubkey").value = state.status?.pubkey_hex || node.pubkey_hex || "";
    if ($("set-privkey")) $("set-privkey").value = node.private_key_hex || "";
    if ($("set-group-psk")) $("set-group-psk").value = node.group_psk_hex || "";
    if ($("set-hb-interval")) $("set-hb-interval").value = node.heartbeat_interval || "30s";
    if ($("set-peer-timeout")) $("set-peer-timeout").value = node.peer_timeout || "1m30s";

    if ($("set-relays")) $("set-relays").value = (cfg.nostr?.relays || []).join("\n");
    if ($("set-automute-targets")) $("set-automute-targets").value = (cfg.auto_mute?.targets || []).join("\n");
    if ($("set-automute-timeout")) $("set-automute-timeout").value = cfg.auto_mute?.timeout || "3s";

    if ($("raw-yaml-editor")) $("raw-yaml-editor").value = state.rawYAML || "";
    if ($("settings-config-path")) $("settings-config-path").textContent = state.status?.config_path || "config.yaml";
  }

  function readPhotonDTO() {
    const mode = $("photon-mode")?.value || "cloud";
    const enabled = Boolean($("photon-enabled")?.checked);
    if (mode === "cloud") {
      return {
        enabled,
        mode: "cloud",
        url: ($("photon-cloud-url")?.value || "").trim(),
        project_id: ($("photon-project-id")?.value || "").trim(),
        api_key: ($("photon-api-key")?.value || "").trim(),
        recipient: ($("photon-recipient")?.value || "").trim(),
        sender_id: ($("photon-sender-id")?.value || "").trim(),
        space_id: ($("photon-space-id")?.value || "").trim()
      };
    }
    if (mode === "proxy") {
      return {
        enabled,
        mode: "proxy",
        url: ($("photon-proxy-url")?.value || "").trim() || "https://imessage-swagger.photon.codes",
        server_url: ($("photon-server-url")?.value || "").trim(),
        api_key: ($("photon-proxy-key")?.value || "").trim(),
        token: ($("photon-proxy-token")?.value || "").trim(),
        recipient: ($("photon-proxy-recipient")?.value || "").trim()
      };
    }
    return {
      enabled,
      mode: "custom",
      url: ($("photon-custom-url")?.value || "").trim(),
      recipient: ($("photon-custom-recipient")?.value || "").trim(),
      token: ($("photon-custom-token")?.value || "").trim(),
      recipient_field: ($("photon-rec-field")?.value || "").trim() || "recipient",
      message_field: ($("photon-msg-field")?.value || "").trim() || "message"
    };
  }

  function pullConfigFormsIntoDraft() {
    state.draft = ensureDraftShape(state.draft);
    const d = state.draft;

    if ($("set-node-name")) d.node.name = $("set-node-name").value.trim() || "mon-homelab";
    if ($("set-privkey")) {
      const pk = $("set-privkey").value.trim();
      if (pk) d.node.private_key_hex = pk;
    }
    if ($("set-group-psk")) {
      const psk = $("set-group-psk").value.trim();
      if (psk) d.node.group_psk_hex = psk;
    }
    if ($("set-hb-interval")) d.node.heartbeat_interval = $("set-hb-interval").value.trim() || "30s";
    if ($("set-peer-timeout")) d.node.peer_timeout = $("set-peer-timeout").value.trim() || "1m30s";

    if ($("set-relays")) d.nostr.relays = splitLines($("set-relays").value);
    if ($("set-automute-targets")) d.auto_mute.targets = splitLines($("set-automute-targets").value);
    if ($("set-automute-timeout")) d.auto_mute.timeout = $("set-automute-timeout").value.trim() || "3s";

    d.notifications = {
      ntfy: {
        enabled: Boolean($("ntfy-enabled")?.checked),
        url: ($("ntfy-url")?.value || "").trim(),
        topic: ($("ntfy-topic")?.value || "").trim(),
        token: ($("ntfy-token")?.value || "").trim()
      },
      photon_imessage: readPhotonDTO()
    };
  }

  async function runTestNotify() {
    pullConfigFormsIntoDraft();
    const banner = $("alerts-test-banner");
    if (banner) {
      banner.hidden = false;
      banner.innerHTML = "Envoi des notifications de test en cours…";
    }
    triggerLEDBusy("wave", "Envoi alerte test", "NTFY / PHOTON", 2400);
    try {
      const res = await apiFetch("/api/test-notify", {
        method: "POST",
        body: JSON.stringify({
          node_name: state.draft.node?.name || "MeshWatch",
          notifications: state.draft.notifications
        })
      });
      const lines = res.results || [];
      if (banner) {
        banner.innerHTML = lines.map((l) => {
          const detail = l.error || (l.ok ? "Envoyé (" + (l.latency_ms || 0) + " ms)" : "Échec");
          return (
            '<div class="test-output-line">' +
              "<span><strong>" + esc(l.channel) + "</strong> — " + esc(detail) + "</span>" +
              '<span class="badge ' + (l.ok ? "ok" : "danger") + '">' + (l.ok ? "ENVOYÉ" : "ÉCHEC") + "</span>" +
            "</div>"
          );
        }).join("") || "Aucun canal actif configuré.";
      }
    } catch (e) {
      if (banner) banner.innerHTML = '<span style="color:var(--danger)">Erreur : ' + esc(e.message) + "</span>";
    }
  }

  /* -------------------- Updates & Setup & Backup -------------------- */

  async function checkUpdates(force = false) {
    try {
      const info = await apiFetch("/api/update/check" + (force ? "?force=1" : ""), { method: "GET" });
      state.updateInfo = info;
      renderUpdateState(info);
    } catch {
      /* optional offline */
    }
  }

  function renderUpdateState(info) {
    if (!info) return;
    const avail = Boolean(info.update_available);
    if ($("nav-update-dot")) $("nav-update-dot").hidden = !avail;
    if ($("home-update-banner")) $("home-update-banner").hidden = !avail;
    if (avail && $("home-update-version")) {
      $("home-update-version").textContent = info.latest_version || info.latest_commit || "Nouvelle image";
    }
    if ($("home-update-desc")) {
      $("home-update-desc").textContent = "Version actuelle : " + (info.current_version || "dev") + " → Disponible : " + (info.latest_version || "latest");
    }
    if ($("home-update-link") && info.release_url) {
      $("home-update-link").href = info.release_url;
    }

    if ($("settings-version-badge")) {
      $("settings-version-badge").textContent = info.current_version || "dev";
      $("settings-version-badge").className = "badge " + (avail ? "warn" : "ok") + " right";
    }
    if ($("settings-update-title")) {
      $("settings-update-title").textContent = avail
        ? "Mise à jour disponible : " + (info.latest_version || info.latest_commit)
        : "Votre instance MeshWatch est à jour";
    }
    if ($("settings-update-meta")) {
      $("settings-update-meta").textContent = "Actuelle : " + (info.current_version || "—") + (info.current_commit ? " (" + info.current_commit.slice(0, 7) + ")" : "");
    }
    if ($("settings-apply-update-btn")) {
      $("settings-apply-update-btn").hidden = !avail;
    }
  }

  async function triggerUpdate() {
    const overlay = $("updating-overlay");
    if (overlay) overlay.hidden = false;
    try {
      await apiFetch("/api/update/apply", {
        method: "POST",
        body: JSON.stringify({ image: state.updateInfo?.image || state.updateInfo?.docker_image || "" })
      });
      if ($("updating-progress")) $("updating-progress").style.width = "65%";
      if ($("updating-phase-sub")) $("updating-phase-sub").textContent = "Redémarrage du conteneur…";

      let tries = 0;
      clearInterval(state.updatePollTimer);
      state.updatePollTimer = setInterval(async () => {
        tries++;
        try {
          const st = await apiFetch("/api/status", { method: "GET" });
          if (st && st.version && st.version !== state.status?.version) {
            clearInterval(state.updatePollTimer);
            window.location.reload();
          } else if (tries > 20) {
            clearInterval(state.updatePollTimer);
            window.location.reload();
          }
        } catch {
          if (tries > 25) {
            clearInterval(state.updatePollTimer);
            window.location.reload();
          }
        }
      }, 2000);
    } catch (e) {
      if (overlay) overlay.hidden = true;
      showToast("Mise à jour impossible : " + e.message, "err");
    }
  }

  async function runQuickSetup() {
    const name = ($("setup-node-name")?.value || "").trim() || "MeshWatch";
    triggerLEDBusy("wave", "Génération des clés", "AES-256-GCM", 2500);
    try {
      const keys = await apiFetch("/api/keygen", { method: "POST", body: "{}" });
      state.draft = ensureDraftShape(state.draft || state.config);
      state.draft.node.name = name;
      state.draft.node.private_key_hex = keys.private_key_hex;
      state.draft.node.group_psk_hex = keys.group_psk_hex;
      if ($("set-node-name")) $("set-node-name").value = name;
      if ($("set-privkey")) $("set-privkey").value = keys.private_key_hex;
      if ($("set-group-psk")) $("set-group-psk").value = keys.group_psk_hex;
      const saved = await saveConfiguration(false);
      if (saved) showToast("Nœud « " + name + " » initialisé !");
    } catch (e) {
      showToast("Erreur initialisation : " + e.message, "err");
    }
  }

  function exportBackup() {
    const blob = new Blob([state.rawYAML || ""], { type: "text/yaml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "meshwatch-config.yaml";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function importBackupFile(file) {
    if (!file) return;
    const text = await file.text();
    try {
      const res = await apiFetch("/api/config", {
        method: "PUT",
        body: JSON.stringify({ yaml: text })
      });
      state.config = ensureDraftShape(res.config);
      state.draft = clone(state.config);
      state.rawYAML = res.yaml || text;
      state.dirty = false;
      syncUnsavedBar();
      renderConfigForms();
      await fetchStatus();
      showToast("Configuration YAML importée !");
    } catch (e) {
      showToast("YAML invalide : " + e.message, "err");
    }
  }

  /* -------------------- Command Palette & Keyboard Shortcuts -------------------- */

  function openPalette() {
    const pal = $("cmd-palette");
    if (!pal) return;
    state.paletteOpen = true;
    pal.hidden = false;
    const inp = $("palette-input");
    if (inp) {
      inp.value = "";
      renderPaletteList("");
      setTimeout(() => inp.focus(), 20);
    }
  }

  function closePalette() {
    const pal = $("cmd-palette");
    if (pal) pal.hidden = true;
    state.paletteOpen = false;
  }

  function buildPaletteItems() {
    const items = [
      { label: "01 · Supervision", sub: "Vue d'ensemble & inspecteur", tag: "VUE", run: () => switchTab("home") },
      { label: "02 · Découverte", sub: "Docker, LAN & sondes configurées", tag: "VUE", run: () => switchTab("discover") },
      { label: "03 · Mes amis", sub: "Invitations MW1 & veille mutuelle", tag: "VUE", run: () => switchTab("friends") },
      { label: "04 · Alertes", sub: "ntfy & Photon iMessage", tag: "VUE", run: () => switchTab("alerts") },
      { label: "05 · Système", sub: "Identité, relais & mises à jour", tag: "VUE", run: () => switchTab("settings") },
      { label: "Tester toutes les sondes", sub: "Exécuter immédiatement tous les contrôles", tag: "ACTION", run: runAllProbesNow },
      { label: "Ajouter une sonde", sub: "Ouvrir l'assistant de configuration", tag: "ACTION", run: () => openProbeModal(-1) },
      { label: "Scanner le réseau local (LAN)", sub: "Aller dans Découverte LAN et analyser", tag: "ACTION", run: () => { switchTab("discover", "lan"); runLANScan(); } },
      { label: "Basculer le thème clair / sombre", sub: "Signal Noir ↔ Papier Chaud", tag: "THÈME", run: () => applyTheme(state.theme === "dark" ? "light" : "dark") }
    ];
    (state.status?.probes || []).forEach((p) => {
      items.push({
        label: p.id,
        sub: (PROBE_KINDS[p.kind]?.label || p.kind) + " · " + (p.ok ? "OK" : "PANNE") + " · " + p.latency_ms + " ms",
        tag: "SONDE",
        run: () => { selectProbe(p.id); switchTab("home"); }
      });
    });
    (state.status?.peers || []).forEach((pr) => {
      items.push({
        label: pr.name,
        sub: pr.online ? "Pair en ligne" : "Pair hors ligne",
        tag: "AMI",
        run: () => openPeerDrawer(pr.pubkey_hex)
      });
    });
    return items;
  }

  function renderPaletteList(query) {
    const q = (query || "").toLowerCase().trim();
    const all = buildPaletteItems();
    const filtered = q ? all.filter((it) => (it.label + " " + it.sub + " " + it.tag).toLowerCase().includes(q)) : all;
    state.paletteItems = filtered.slice(0, 14);
    state.paletteIndex = 0;

    const listEl = $("palette-list");
    if (!listEl) return;
    if (!state.paletteItems.length) {
      listEl.innerHTML = '<div class="empty-state">Aucun résultat.</div>';
      return;
    }
    listEl.innerHTML = state.paletteItems.map((it, idx) => (
      '<button type="button" class="palette-item' + (idx === 0 ? " active" : "") + '" data-pal-idx="' + idx + '">' +
        '<span class="chip">' + esc(it.tag) + "</span>" +
        '<span style="font-weight:600;color:var(--text);">' + esc(it.label) + "</span>" +
        '<span style="margin-left:auto;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);">' + esc(it.sub) + "</span>" +
      "</button>"
    )).join("");

    listEl.querySelectorAll("[data-pal-idx]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const idx = Number(btn.dataset.palIdx);
        const item = state.paletteItems[idx];
        closePalette();
        if (item) item.run();
      });
    });
  }

  function highlightPaletteItem(idx) {
    const rows = document.querySelectorAll("#palette-list .palette-item");
    rows.forEach((r, i) => r.classList.toggle("active", i === idx));
    rows[idx]?.scrollIntoView({ block: "nearest" });
  }

  /* -------------------- Events -------------------- */

  function bindStaticEvents() {
    document.querySelectorAll(".space-link[data-tab]").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.tab));
    });
    document.querySelectorAll("[data-goto-tab]").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.gotoTab));
    });
    document.querySelectorAll("#space-tabs button[data-subtab]").forEach((btn) => {
      btn.addEventListener("click", () => switchDiscoverSubtab(btn.dataset.subtab));
    });

    $("sidebar-toggle")?.addEventListener("click", () => $("sidebar")?.classList.toggle("open"));
    $("theme-dark-btn")?.addEventListener("click", () => applyTheme("dark"));
    $("theme-light-btn")?.addEventListener("click", () => applyTheme("light"));

    $("auth-submit-btn")?.addEventListener("click", submitAuthToken);
    $("auth-token-input")?.addEventListener("keydown", (e) => { if (e.key === "Enter") submitAuthToken(); });

    $("top-run-btn")?.addEventListener("click", runAllProbesNow);
    $("home-run-btn")?.addEventListener("click", runAllProbesNow);
    $("managed-run-btn")?.addEventListener("click", runAllProbesNow);

    $("top-add-btn")?.addEventListener("click", () => openProbeModal(-1));
    $("home-add-probe-btn")?.addEventListener("click", () => openProbeModal(-1));
    $("fleet-empty-add")?.addEventListener("click", () => openProbeModal(-1));
    $("discover-new-btn")?.addEventListener("click", () => openProbeModal(-1));
    $("managed-add-btn")?.addEventListener("click", () => openProbeModal(-1));

    $("setup-create-btn")?.addEventListener("click", runQuickSetup);
    $("home-update-apply")?.addEventListener("click", triggerUpdate);
    $("settings-check-update-btn")?.addEventListener("click", () => checkUpdates(true));
    $("settings-apply-update-btn")?.addEventListener("click", triggerUpdate);

    $("fleet-seg")?.querySelectorAll("button[data-filter]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.fleetFilter = btn.dataset.filter;
        $("fleet-seg").querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
        if (state.status) renderFleetTable(state.status);
      });
    });
    $("fleet-filter-input")?.addEventListener("input", (e) => {
      state.fleetSearch = e.target.value;
      if (state.status) renderFleetTable(state.status);
    });
    $("fleet-sort")?.addEventListener("change", (e) => {
      state.fleetSort = e.target.value;
      if (state.status) renderFleetTable(state.status);
    });

    document.querySelectorAll(".tab[data-insp-tab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.inspectorTab = btn.dataset.inspTab;
        localStorage.setItem(STORAGE.inspTab, state.inspectorTab);
        if (state.status) renderInspector(state.status);
      });
    });
    $("insp-test-btn")?.addEventListener("click", () => state.selectedProbeID && quickTestProbeByID(state.selectedProbeID));
    $("insp-edit-btn")?.addEventListener("click", () => state.selectedProbeID && editProbeByID(state.selectedProbeID));
    $("insp-del-btn")?.addEventListener("click", () => state.selectedProbeID && deleteProbeByID(state.selectedProbeID));

    $("docker-scan-btn")?.addEventListener("click", () => runDockerScan(false));
    $("docker-apply-btn")?.addEventListener("click", applyDockerSelection);
    $("lan-scan-btn")?.addEventListener("click", runLANScan);
    $("lan-category-filter")?.addEventListener("change", renderLANItems);
    $("managed-filter-input")?.addEventListener("input", renderManagedProbes);

    $("probe-modal-close")?.addEventListener("click", () => { $("probe-modal").hidden = true; });
    $("probe-back-kind-btn")?.addEventListener("click", () => {
      $("probe-step-kind").hidden = false;
      $("probe-form").hidden = true;
    });
    document.querySelectorAll("[data-pick-kind]").forEach((card) => {
      card.addEventListener("click", () => showProbeForm(card.dataset.pickKind, {}));
    });
    $("probe-test-modal-btn")?.addEventListener("click", runModalProbeTest);
    $("probe-form")?.addEventListener("submit", submitProbeModal);

    $("copy-invite-btn")?.addEventListener("click", async () => {
      const val = $("my-invite-code")?.value || "";
      if (!val.startsWith("MW1-")) { showToast("Initialisez le nœud d'abord.", "warn"); return; }
      try { await navigator.clipboard.writeText(val); showToast("Code MW1 copié !"); }
      catch { showToast("Sélectionnez et copiez le code manuellement.", "warn"); }
    });
    $("refresh-invite-btn")?.addEventListener("click", renderConfigForms);
    $("accept-invite-input")?.addEventListener("input", (e) => {
      const dec = decodeInvite(e.target.value);
      const pv = $("accept-invite-preview");
      if (!pv) return;
      if (!dec) { pv.hidden = true; return; }
      pv.hidden = false;
      pv.textContent = "Ami détecté : " + dec.name + " · Clé " + dec.pubkey_hex.slice(0, 14) + "…";
    });
    $("accept-invite-btn")?.addEventListener("click", async () => {
      const dec = decodeInvite($("accept-invite-input")?.value);
      if (!dec) { showToast("Code MW1 ou clé hex invalide.", "err"); return; }
      state.draft = ensureDraftShape(state.draft || state.config);
      if (!state.draft.peers.some((p) => (p.pubkey_hex || "").toLowerCase() === dec.pubkey_hex)) {
        state.draft.peers.push({ name: dec.name || "Ami " + (state.draft.peers.length + 1), pubkey_hex: dec.pubkey_hex });
      }
      if (dec.group_psk_hex && (!state.draft.node.group_psk_hex || state.draft.peers.length <= 1)) {
        state.draft.node.group_psk_hex = dec.group_psk_hex;
        if ($("set-group-psk")) $("set-group-psk").value = dec.group_psk_hex;
      }
      $("accept-invite-input").value = "";
      $("accept-invite-preview").hidden = true;
      const saved = await saveConfiguration(false);
      if (saved) showToast("Ami « " + (dec.name || "Pair") + " » ajouté !");
    });
    $("friends-manual-btn")?.addEventListener("click", () => { $("friend-modal").hidden = false; });
    $("friend-modal-close")?.addEventListener("click", () => { $("friend-modal").hidden = true; });
    $("friend-modal-cancel")?.addEventListener("click", () => { $("friend-modal").hidden = true; });
    $("friend-modal-save")?.addEventListener("click", async () => {
      const name = ($("fm-name")?.value || "").trim() || "Ami";
      const pk = ($("fm-pubkey")?.value || "").trim();
      if (!/^[0-9a-fA-F]{64}$/.test(pk)) { showToast("Clé publique invalide (64 hex).", "err"); return; }
      state.draft = ensureDraftShape(state.draft || state.config);
      state.draft.peers.push({ name, pubkey_hex: pk.toLowerCase() });
      $("friend-modal").hidden = true;
      const saved = await saveConfiguration(false);
      if (saved) showToast("Ami ajouté !");
    });
    $("peer-drawer-backdrop")?.addEventListener("click", closePeerDrawer);
    $("peer-drawer-close")?.addEventListener("click", closePeerDrawer);

    $("alerts-save-btn")?.addEventListener("click", () => saveConfiguration(true));
    $("settings-save-btn")?.addEventListener("click", () => saveConfiguration(true));
    $("alerts-test-btn")?.addEventListener("click", runTestNotify);
    $("photon-mode")?.addEventListener("change", () => { syncPhotonFieldsVisibility(); markDirty(); });
    $("ntfy-gen-topic")?.addEventListener("click", () => {
      const rand = Math.random().toString(36).slice(2, 10) + "-" + Math.random().toString(36).slice(2, 6);
      $("ntfy-topic").value = "meshwatch-" + rand;
      markDirty();
    });
    $("copy-pubkey-btn")?.addEventListener("click", async () => {
      const pk = $("set-pubkey")?.value || "";
      if (pk) { try { await navigator.clipboard.writeText(pk); showToast("Clé publique copiée."); } catch {} }
    });
    $("regen-keys-btn")?.addEventListener("click", async () => {
      const keys = await apiFetch("/api/keygen", { method: "POST", body: "{}" });
      state.draft = ensureDraftShape(state.draft || state.config);
      state.draft.node.private_key_hex = keys.private_key_hex;
      state.draft.node.group_psk_hex = keys.group_psk_hex;
      if ($("set-privkey")) $("set-privkey").value = keys.private_key_hex;
      if ($("set-group-psk")) $("set-group-psk").value = keys.group_psk_hex;
      markDirty();
      showToast("Nouvelles clés générées — cliquez sur Enregistrer.", "warn");
    });
    $("test-automute-btn")?.addEventListener("click", async () => {
      const res = await apiFetch("/api/check-automute", { method: "POST", body: "{}" });
      if ($("automute-result")) {
        $("automute-result").textContent = res.muted ? "Internet coupé (auto-mute)" : "Internet joignable";
      }
    });
    $("backup-export-btn")?.addEventListener("click", exportBackup);
    $("backup-import-input")?.addEventListener("change", (e) => importBackupFile(e.target.files?.[0]));
    $("raw-yaml-save-btn")?.addEventListener("click", async () => {
      try {
        const res = await apiFetch("/api/config", { method: "PUT", body: JSON.stringify({ yaml: $("raw-yaml-editor").value }) });
        state.config = ensureDraftShape(res.config);
        state.draft = clone(state.config);
        state.rawYAML = res.yaml || "";
        state.dirty = false;
        syncUnsavedBar();
        renderConfigForms();
        await fetchStatus();
        showToast("YAML brut appliqué.");
      } catch (e) {
        showToast("Erreur YAML : " + e.message, "err");
      }
    });

    document.querySelectorAll("[data-toggle-secret]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const inp = $(btn.dataset.toggleSecret);
        if (!inp) return;
        const hide = inp.type === "text";
        inp.type = hide ? "password" : "text";
        btn.textContent = hide ? "Afficher" : "Masquer";
      });
    });

    ["#view-alerts input, #view-alerts select, #view-settings input, #view-settings textarea"].forEach((sel) => {
      document.querySelectorAll(sel).forEach((el) => {
        if (el.type === "file" || el.readOnly) return;
        el.addEventListener("change", markDirty);
      });
    });
    $("unsaved-save-btn")?.addEventListener("click", () => saveConfiguration(true));
    $("unsaved-discard-btn")?.addEventListener("click", () => {
      state.draft = clone(state.config || {});
      state.dirty = false;
      renderConfigForms();
      syncUnsavedBar();
    });

    $("cmd-palette-btn")?.addEventListener("click", openPalette);
    $("cmd-palette")?.addEventListener("click", (e) => { if (e.target === $("cmd-palette")) closePalette(); });
    $("palette-input")?.addEventListener("input", (e) => renderPaletteList(e.target.value));
    $("palette-input")?.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        state.paletteIndex = Math.min(state.paletteItems.length - 1, state.paletteIndex + 1);
        highlightPaletteItem(state.paletteIndex);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        state.paletteIndex = Math.max(0, state.paletteIndex - 1);
        highlightPaletteItem(state.paletteIndex);
      } else if (e.key === "Enter") {
        e.preventDefault();
        const item = state.paletteItems[state.paletteIndex];
        closePalette();
        if (item) item.run();
      } else if (e.key === "Escape") {
        closePalette();
      }
    });
    $("shortcut-modal-close")?.addEventListener("click", () => { $("shortcut-modal").hidden = true; });

    document.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        state.paletteOpen ? closePalette() : openPalette();
        return;
      }
      if (e.key === "Escape") {
        closePalette();
        closePeerDrawer();
        if ($("probe-modal")) $("probe-modal").hidden = true;
        if ($("friend-modal")) $("friend-modal").hidden = true;
        if ($("shortcut-modal")) $("shortcut-modal").hidden = true;
        return;
      }
      const tag = (e.target?.tagName || "").toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select" || e.metaKey || e.ctrlKey || e.altKey) return;

      const k = e.key.toLowerCase();
      if (state.keySeq === "g") {
        state.keySeq = "";
        clearTimeout(state.keySeqTimer);
        if (k === "1") return switchTab("home");
        if (k === "2") return switchTab("discover");
        if (k === "3") return switchTab("friends");
        if (k === "4") return switchTab("alerts");
        if (k === "5") return switchTab("settings");
      }
      if (k === "g") {
        state.keySeq = "g";
        clearTimeout(state.keySeqTimer);
        state.keySeqTimer = setTimeout(() => { state.keySeq = ""; }, 900);
        return;
      }
      if (k === "?") {
        if ($("shortcut-modal")) $("shortcut-modal").hidden = false;
      } else if (k === "r") {
        runAllProbesNow();
      } else if (k === "t" && state.tab === "home" && state.selectedProbeID) {
        quickTestProbeByID(state.selectedProbeID);
      } else if (k === "e" && state.tab === "home" && state.selectedProbeID) {
        editProbeByID(state.selectedProbeID);
      } else if ((k === "j" || k === "k") && state.tab === "home") {
        const rows = Array.from(document.querySelectorAll("#fleet-tbody tr[data-select-probe]"));
        if (!rows.length) return;
        const cur = rows.findIndex((r) => r.dataset.selectProbe === state.selectedProbeID);
        const nextIdx = k === "j" ? Math.min(rows.length - 1, cur + 1) : Math.max(0, cur - 1);
        selectProbe(rows[nextIdx].dataset.selectProbe);
      }
    });
  }

  window.runDockerScan = runDockerScan;

  document.addEventListener("DOMContentLoaded", bootstrap);
})();
