(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const MW = () => window.MWViz || {};

  const STORAGE = {
    theme: "mw_theme",
    token: "mw_ui_token",
    device: "mw_selected_probe",
    dtab: "mw_device_tab"
  };

  /* Types d'appareils : libellés pensés pour l'utilisateur, pas pour le protocole. */
  const KINDS = {
    http: { label: "Site ou application web", icon: "language", desc: "Il répond, assez vite, avec un certificat valide.", host: false },
    synology: { label: "NAS Synology", icon: "storage", desc: "Disques, RAID, température.", host: true },
    proxmox: { label: "Proxmox", icon: "dns", desc: "Le serveur et chacune de ses VM.", host: true },
    linux_ssh: { label: "Serveur Linux", icon: "terminal", desc: "Processeur, mémoire, disques, services.", host: true },
    windows_winrm: { label: "PC ou serveur Windows", icon: "desktop_windows", desc: "Ressources, services, VM Hyper-V.", host: true },
    docker: { label: "Conteneurs Docker", icon: "deployed_code", desc: "Ceux de cette machine, sans rien saisir.", host: false },
    node_exporter: { label: "Linux (node_exporter)", icon: "monitoring", desc: "Lit les métriques Prometheus d'un serveur Linux.", host: true, advanced: true },
    windows_exporter: { label: "Windows (windows_exporter)", icon: "monitoring", desc: "Lit les métriques Prometheus sans identifiant Windows.", host: true, advanced: true },
    snmp_oid: { label: "Équipement SNMP", icon: "router", desc: "Routeur, switch ou onduleur : lit une valeur précise (OID).", host: false, advanced: true },
    tcp: { label: "Port réseau", icon: "lan", desc: "Vérifie seulement qu'un port répond.", host: false, advanced: true }
  };

  const GUIDES = {
    proxmox: "Dans Proxmox : Datacenter → Permissions → API Tokens → Add (par exemple root@pam!meshwatch). Décochez « Privilege Separation », ou donnez le rôle PVEAuditor sur /. Copiez ensuite l'identifiant et le secret ici.",
    synology: "Dans DSM : Panneau de configuration → Terminal et SNMP → onglet SNMP → activez le service. La version v2c suffit sur votre réseau local.",
    windows_winrm: "Sur le PC Windows, dans PowerShell en administrateur : « winrm quickconfig » puis « Enable-PSRemoting -Force ». Sans HTTPS, autorisez aussi l'authentification de base.",
    linux_ssh: "Un compte SSH en lecture suffit. MeshWatch lit seulement /proc, df et systemctl : il ne modifie rien.",
    docker: "MeshWatch lit l'état des conteneurs par le socket Docker, monté en lecture seule."
  };

  const CHECK = '<span class="ms" style="font-size:16px" aria-label="fait">check</span>';

  /* -------------------- État -------------------- */

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
      /* stockage indisponible */
    }
  }

  function storedTheme() {
    try {
      const t = localStorage.getItem(STORAGE.theme);
      if (t === "light" || t === "dark") return t;
    } catch {}
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  const state = {
    tab: "home",
    theme: storedTheme(),
    token: loadStoredToken(),
    status: null,
    config: null,
    draft: null,
    rawYAML: "",
    updateInfo: null,
    discoverInfo: null,
    dockerContainers: [],
    dockerSocket: "/var/run/docker.sock",
    lanItems: [],
    lanScanned: false,
    lanScanning: false,
    homeFilter: "all",
    deviceSearch: "",
    selectedID: (() => { try { return localStorage.getItem(STORAGE.device) || ""; } catch { return ""; } })(),
    deviceTab: (() => { try { return localStorage.getItem(STORAGE.dtab) || "overview"; } catch { return "overview"; } })(),
    wizard: { open: false, step: 1, kind: "", editIndex: -1, testedOK: false },
    dirty: false,
    paletteItems: [],
    paletteIndex: 0,
    keySeq: "",
    keySeqTimer: null,
    statusTimer: null,
    toastTimer: null,
    updatePollTimer: null,
    confirmResolve: null,
    peerOpen: "",
    lastFocus: null
  };

  /* -------------------- Utilitaires -------------------- */

  function esc(val) {
    return String(val == null ? "" : val)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function clone(obj) {
    return JSON.parse(JSON.stringify(obj == null ? {} : obj));
  }

  function plural(n, one, many) {
    return n + " " + (n > 1 ? many : one);
  }

  function ensureDraftShape(cfg) {
    const d = cfg && typeof cfg === "object" ? clone(cfg) : {};
    if (!d.node || typeof d.node !== "object") {
      d.node = { name: "", private_key_hex: "", group_psk_hex: "", heartbeat_interval: "30s", peer_timeout: "1m30s" };
    }
    if (!d.logging || typeof d.logging !== "object") d.logging = { level: "info", format: "text" };
    if (!d.nostr || typeof d.nostr !== "object") d.nostr = { relays: ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"] };
    if (!Array.isArray(d.nostr.relays)) d.nostr.relays = [];
    if (!d.auto_mute || typeof d.auto_mute !== "object") d.auto_mute = { targets: ["1.1.1.1:443", "9.9.9.9:443"], timeout: "3s" };
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

  function toSec(ts) {
    if (ts == null || ts === "") return 0;
    if (typeof ts === "number") return ts > 1e12 ? Math.floor(ts / 1000) : ts;
    const parsed = Date.parse(ts);
    return Number.isNaN(parsed) ? 0 : Math.floor(parsed / 1000);
  }

  function fmtDuration(sec) {
    const s = Math.max(0, Math.round(Number(sec) || 0));
    if (s < 60) return s + " s";
    const m = Math.floor(s / 60);
    if (m < 60) return m + " min";
    const h = Math.floor(m / 60);
    if (h < 24) return h + " h" + (m % 60 ? " " + (m % 60) + " min" : "");
    const d = Math.floor(h / 24);
    return d + " j" + (h % 24 ? " " + (h % 24) + " h" : "");
  }

  function fmtAgo(ts) {
    const sec = toSec(ts);
    if (!sec) return "jamais";
    const diff = Math.max(0, Math.round(Date.now() / 1000 - sec));
    if (diff < 5) return "à l'instant";
    return "il y a " + fmtDuration(diff);
  }

  function fmtClock(ts) {
    const sec = toSec(ts);
    if (!sec) return "—";
    const d = new Date(sec * 1000);
    const today = new Date();
    const sameDay = d.toDateString() === today.toDateString();
    const time = d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
    return sameDay ? time : d.toLocaleDateString("fr-FR", { day: "numeric", month: "short" }) + " " + time;
  }

  function fmtMB(mb) {
    const v = Number(mb) || 0;
    if (v >= 1024) return (v / 1024).toFixed(1).replace(".", ",") + " Go";
    return Math.round(v) + " Mo";
  }

  function fmtPct(v) {
    return Math.round(Number(v) || 0) + " %";
  }

  function fmtGoDuration(raw) {
    const s = String(raw || "").trim();
    if (!s) return "";
    let total = 0;
    const re = /(\d+(?:\.\d+)?)(h|ms|m|s)/g;
    let m;
    let matched = false;
    while ((m = re.exec(s))) {
      matched = true;
      const n = parseFloat(m[1]);
      if (m[2] === "h") total += n * 3600;
      else if (m[2] === "m") total += n * 60;
      else if (m[2] === "s") total += n;
    }
    if (!matched) return s;
    if (total < 60) return Math.round(total) + " s";
    const min = Math.floor(total / 60);
    const rest = Math.round(total % 60);
    return min + " min" + (rest ? " " + rest + " s" : "");
  }

  function splitCSV(text) {
    return String(text || "").split(/[,\n]+/).map((s) => s.trim()).filter(Boolean);
  }

  function splitLines(text) {
    return String(text || "").split(/\r?\n+/).map((s) => s.trim()).filter(Boolean);
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

  /* Traduit les messages techniques les plus courants en phrases simples. */
  function humanize(raw) {
    const s = String(raw || "").trim();
    if (!s) return "";
    let m;
    if ((m = s.match(/^(\d+)\/(\d+) up$/i))) return m[1] + " sur " + m[2] + " en marche";
    if (/no route to host|host is unreachable|network is unreachable/i.test(s)) return "Injoignable sur le réseau";
    if (/connection refused/i.test(s)) return "Connexion refusée : le service est peut-être arrêté";
    if (/no such host|server misbehaving/i.test(s)) return "Adresse introuvable";
    if (/timeout|deadline exceeded|timed out/i.test(s)) return "Pas de réponse à temps";
    if (/x509|certificate/i.test(s)) return "Certificat refusé";
    if (/unauthorized|authentication|permission denied|\b401\b|\b403\b/i.test(s)) return "Identifiants refusés";
    if ((m = s.match(/^HTTP (\d{3})\b/)) && m[1].startsWith("2")) return "Répond (code " + m[1] + ")";
    if ((m = s.match(/^HTTP (\d{3})\b/))) return "Répond avec une erreur (code " + m[1] + ")";
    return s;
  }

  function kindLabel(kind) {
    return KINDS[kind]?.label || kind || "Appareil";
  }

  function kindIcon(kind) {
    return KINDS[kind]?.icon || "sensors";
  }

  function probeTarget(p) {
    if (!p) return "";
    if (p.kind === "docker") {
      return p.containers && p.containers.length ? plural(p.containers.length, "conteneur choisi", "conteneurs choisis") : "Tous les conteneurs";
    }
    if (p.url) return p.url.replace(/^https?:\/\//, "").replace(/\/$/, "");
    if (p.address) return p.address;
    if (p.host) return p.port ? p.host + ":" + p.port : p.host;
    return "";
  }

  function slugify(text) {
    return String(text || "")
      .toLowerCase()
      .normalize("NFD").replace(/[̀-ͯ]/g, "")
      .replace(/^https?:\/\//, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 40);
  }

  function randomTopic() {
    const bytes = new Uint8Array(6);
    if (window.crypto && window.crypto.getRandomValues) window.crypto.getRandomValues(bytes);
    else bytes.forEach((_, i) => { bytes[i] = Math.floor(Math.random() * 256); });
    return "meshwatch-" + Array.from(bytes, (b) => b.toString(36).padStart(2, "0")).join("").slice(0, 10);
  }

  async function copyText(text, okMsg) {
    try {
      await navigator.clipboard.writeText(text);
      toast(okMsg || "Copié.");
      return true;
    } catch {
      toast("Copie impossible : sélectionnez le texte à la main.", "warn");
      return false;
    }
  }

  function toast(msg, tone = "ok") {
    const el = $("toast");
    if (!el) return;
    const icon = tone === "err" ? "error" : tone === "warn" ? "warning" : "check_circle";
    el.className = "toast " + tone;
    el.innerHTML = '<span class="ms" aria-hidden="true">' + icon + "</span><span>" + esc(msg) + "</span>";
    el.hidden = false;
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => { el.hidden = true; }, tone === "err" ? 7000 : 4000);
  }

  function setBusy(btn, busy) {
    if (!btn) return;
    btn.classList.toggle("busy", Boolean(busy));
    btn.disabled = Boolean(busy);
  }

  /* -------------------- Thème -------------------- */

  function applyTheme(theme) {
    state.theme = theme === "dark" ? "dark" : "light";
    try { localStorage.setItem(STORAGE.theme, state.theme); } catch {}
    document.documentElement.setAttribute("data-theme", state.theme);
    const icon = $("theme-icon");
    if (icon) icon.textContent = state.theme === "dark" ? "light_mode" : "dark_mode";
    const btn = $("theme-btn");
    if (btn) btn.setAttribute("aria-label", state.theme === "dark" ? "Passer en thème clair" : "Passer en thème sombre");
    if (state.status && state.tab === "devices") renderDevices();
  }

  /* -------------------- API & accès -------------------- */

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
      try { data = JSON.parse(text); } catch { data = { raw: text }; }
    }
    if (!res.ok) {
      const msg = (data.errors && data.errors.join(" · ")) || data.error || data.message || ("Erreur HTTP " + res.status);
      throw new Error(msg);
    }
    return data;
  }

  function openAuthGate(errText = "") {
    const gate = $("auth-gate");
    if (!gate) return;
    gate.hidden = false;
    const err = $("auth-error");
    if (err) {
      err.textContent = errText;
      err.hidden = !errText;
    }
    setTimeout(() => $("auth-token")?.focus(), 40);
  }

  async function submitAuth(e) {
    e.preventDefault();
    const val = ($("auth-token")?.value || "").trim();
    if (!val) return;
    try {
      const res = await fetch("/api/auth/check", { headers: { "Content-Type": "application/json", "Authorization": "Bearer " + val } });
      const check = await res.json().catch(() => ({}));
      if (check.auth_required && !check.authenticated) {
        openAuthGate("Ce jeton n'est pas le bon.");
        return;
      }
      state.token = val;
      persistToken(val);
      $("auth-gate").hidden = true;
      await loadInitialData();
    } catch (err) {
      openAuthGate(err.message || "Connexion impossible.");
    }
  }

  /* -------------------- Chargement -------------------- */

  async function bootstrap() {
    applyTheme(state.theme);
    bindEvents();
    routeFromHash();
    try {
      const check = await apiFetch("/api/auth/check", { method: "GET" });
      if (check.auth_required && !check.authenticated) {
        openAuthGate();
        return;
      }
      if (state.token && check.authenticated) persistToken(state.token);
      await loadInitialData();
    } catch (e) {
      if (!String(e.message || "").includes("401")) {
        setHeroError("Impossible de joindre MeshWatch : " + e.message);
      }
    }
  }

  function setHeroError(msg) {
    const hero = $("hero");
    if (hero) hero.dataset.tone = "down";
    if ($("hero-pill-text")) $("hero-pill-text").textContent = "Hors connexion";
    if ($("home-title")) $("home-title").textContent = "L'interface ne joint plus MeshWatch.";
    if ($("hero-sub")) $("hero-sub").textContent = msg;
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
      state.status = await apiFetch("/api/status", { method: "GET" });
      renderAll();
    } catch (e) {
      if (!String(e.message || "").includes("401") && !state.status) setHeroError(e.message);
    }
  }

  async function fetchConfig() {
    const res = await apiFetch("/api/config", { method: "GET" });
    state.config = ensureDraftShape(res.config);
    state.draft = clone(state.config);
    state.rawYAML = res.yaml || "";
    setDirty(false);
    renderConfigForms();
    renderAll();
  }

  function setDirty(on) {
    state.dirty = Boolean(on);
    const bar = $("savebar");
    if (bar) bar.hidden = !state.dirty;
  }

  async function saveConfiguration(showMsg = true) {
    if (!state.draft) return false;
    pullFormsIntoDraft();
    try {
      const res = await apiFetch("/api/config", { method: "PUT", body: JSON.stringify({ config: state.draft }) });
      state.config = ensureDraftShape(res.config || state.draft);
      state.draft = clone(state.config);
      state.rawYAML = res.yaml || "";
      setDirty(false);
      renderConfigForms();
      await fetchStatus();
      if (showMsg) {
        if (res.persisted === false) toast("Appliqué, mais pas enregistré sur le disque (fichier en lecture seule).", "warn");
        else toast("Modifications enregistrées.");
      }
      return true;
    } catch (e) {
      toast("Enregistrement impossible : " + e.message, "err");
      return false;
    }
  }

  /* -------------------- Navigation -------------------- */

  const TABS = ["home", "devices", "friends", "alerts", "settings"];

  function routeFromHash() {
    const raw = decodeURIComponent((location.hash || "").replace(/^#\/?/, ""));
    const [tab, ...rest] = raw.split("/");
    if (tab === "devices" && rest.length) {
      state.selectedID = rest.join("/");
    }
    switchTab(TABS.includes(tab) ? tab : "home", false);
  }

  function switchTab(tab, pushHash = true) {
    if (!TABS.includes(tab)) tab = "home";
    state.tab = tab;
    $$(".navlink[data-tab]").forEach((b) => {
      const on = b.dataset.tab === tab;
      b.classList.toggle("on", on);
      if (on) b.setAttribute("aria-current", "page");
      else b.removeAttribute("aria-current");
    });
    $$(".view[data-view]").forEach((v) => { v.hidden = v.dataset.view !== tab; });
    if (pushHash) {
      const target = "#/" + tab + (tab === "devices" && state.selectedID ? "/" + encodeURIComponent(state.selectedID) : "");
      if (location.hash !== target) history.replaceState(null, "", target);
    }
    renderAll();
    window.scrollTo({ top: 0 });
  }

  function openDevice(id) {
    state.selectedID = id;
    try { localStorage.setItem(STORAGE.device, id); } catch {}
    switchTab("devices");
  }

  /* -------------------- Données dérivées -------------------- */

  function deviceList() {
    const st = state.status || {};
    const runtime = {};
    (st.probes || []).forEach((p) => { runtime[p.id] = p; });
    const cfg = state.draft?.probes || [];
    const seen = new Set();
    const list = cfg.map((c, idx) => {
      seen.add(c.id);
      const r = runtime[c.id];
      return { id: c.id, kind: c.kind, cfg: c, idx, rt: r || null, ok: r ? r.ok : null, summary: r ? r.summary : "", latency: r ? r.latency_ms : null };
    });
    (st.probes || []).forEach((r) => {
      if (!seen.has(r.id)) list.push({ id: r.id, kind: r.kind, cfg: null, idx: -1, rt: r, ok: r.ok, summary: r.summary, latency: r.latency_ms });
    });
    return list;
  }

  function sortDevices(list) {
    return list.slice().sort((a, b) => {
      const ra = a.ok === false ? 0 : a.ok === null ? 1 : 2;
      const rb = b.ok === false ? 0 : b.ok === null ? 1 : 2;
      if (ra !== rb) return ra - rb;
      return (a.id || "").localeCompare(b.id || "", "fr");
    });
  }

  function peerState(p) {
    if (p.timed_out) return { tone: "down", label: "Ne répond plus" };
    if (p.online && !p.overall_ok) {
      const bad = (p.probes || []).filter((x) => !x.ok).length;
      return { tone: "warn", label: bad ? plural(bad, "souci", "soucis") : "Un souci" };
    }
    if (p.online) return { tone: "ok", label: "En ligne" };
    return { tone: "off", label: "En attente" };
  }

  function initials(name) {
    const parts = String(name || "?").replace(/[-_.]/g, " ").trim().split(/\s+/);
    return ((parts[0] || "?")[0] + (parts[1] ? parts[1][0] : (parts[0] || "")[1] || "")).toUpperCase();
  }

  function lastCheckTs() {
    const ph = state.status?.probe_history || {};
    let max = 0;
    Object.values(ph).forEach((arr) => (arr || []).forEach((p) => { if (p.ts > max) max = p.ts; }));
    return max;
  }

  function hasAlertChannel() {
    const n = state.status?.notifications;
    if (n) return Boolean(n.ntfy_enabled || n.photon_enabled);
    const d = state.draft?.notifications;
    return Boolean(d?.ntfy?.enabled || d?.photon_imessage?.enabled);
  }

  function uptimePct(hist) {
    if (!hist || !hist.length) return null;
    return Math.round((hist.filter((p) => p.ok).length / hist.length) * 1000) / 10;
  }

  /* -------------------- Rendu global -------------------- */

  function renderAll() {
    const st = state.status;
    if (!st) return;
    renderWelcome(st);
    renderNav(st);
    if (state.tab === "home") renderHome(st);
    if (state.tab === "devices") renderDevices();
    if (state.tab === "friends") renderFriends(st);
    if (state.tab === "settings") renderSettingsLive(st);
    if (state.wizard.open && state.wizard.step === 1) renderFound();
  }

  function renderWelcome(st) {
    const w = $("welcome");
    if (!w) return;
    const show = st.mode === "setup";
    if (show && w.hidden) {
      w.hidden = false;
      setTimeout(() => $("welcome-name")?.focus(), 60);
    } else if (!show) {
      w.hidden = true;
    }
  }

  function renderNav(st) {
    const down = deviceList().filter((d) => d.ok === false).length;
    const nd = $("nav-devices-alert");
    if (nd) {
      nd.hidden = !down;
      nd.textContent = String(down);
      nd.className = "nav-count down";
      nd.title = plural(down, "appareil ne répond plus", "appareils ne répondent plus");
    }
    const badPeers = (st.peers || []).filter((p) => peerState(p).tone === "down" || peerState(p).tone === "warn").length;
    const nf = $("nav-friends-alert");
    if (nf) {
      nf.hidden = !badPeers;
      nf.textContent = String(badPeers);
      nf.className = "nav-count";
    }
  }

  /* -------------------- Accueil -------------------- */

  function renderHome(st) {
    const devices = deviceList();
    const down = devices.filter((d) => d.ok === false);
    const peers = st.peers || [];
    const onlinePeers = peers.filter((p) => p.online);
    const relays = st.relays || [];
    const connRelays = relays.filter((r) => r.connected).length;

    /* Bandeau principal : une phrase dit d'abord si tout va bien. */
    let tone = "ok";
    let pill = "Tout va bien";
    let title;
    let sub;
    const lastTs = lastCheckTs();
    const checkTxt = lastTs ? "Dernière vérification " + fmtAgo(lastTs) + "." : "";
    const friendsTxt = onlinePeers.length
      ? " Si votre connexion tombe, " + (onlinePeers.length > 1 ? onlinePeers.length + " amis le verront" : "1 ami le verra") + " et vous préviendr" + (onlinePeers.length > 1 ? "ont" : "a") + " sur votre téléphone."
      : " Aucun ami ne veille encore sur vous si votre connexion tombe.";

    if (st.mode === "setup") {
      tone = "off"; pill = "À configurer";
      title = "Donnons un nom à cette maison.";
      sub = "Il faut une minute pour démarrer.";
    } else if (!devices.length) {
      tone = "off"; pill = "Rien n'est surveillé";
      title = "Ajoutez votre premier appareil.";
      sub = "On cherche d'abord ce qui tourne sur votre réseau : conteneurs Docker, NAS, serveurs.";
    } else if (down.length) {
      tone = "down"; pill = down.length > 1 ? down.length + " problèmes" : "1 problème";
      title = down.length === 1 ? down[0].id + " ne répond plus." : down.length + " appareils ne répondent plus.";
      sub = (devices.length - down.length) + " sur " + devices.length + " fonctionnent normalement. " + checkTxt;
    } else if (st.muted) {
      tone = "warn"; pill = "Connexion coupée";
      title = "Votre connexion Internet semble coupée.";
      sub = "Vos alertes attendent son retour. Vos amis, eux, voient que vous ne répondez plus.";
    } else {
      title = devices.length === 1 ? "Votre appareil répond." : "Vos " + devices.length + " appareils répondent.";
      sub = checkTxt + friendsTxt;
    }
    const hero = $("hero");
    if (hero) hero.dataset.tone = tone;
    $("hero-pill-text").textContent = pill;
    $("home-title").textContent = title;
    $("hero-sub").textContent = sub.trim() || " ";

    /* Ce qui demande votre attention */
    const items = [];
    down.forEach((d) => {
      items.push({
        tone: "down", icon: "error",
        html: "<b>" + esc(d.id) + " ne répond plus.</b><span class=\"muted\" title=\"" + esc(d.summary || "") + "\">" + esc(humanize(d.summary)) + "</span>",
        actions: '<button class="btn sm" type="button" data-open-device="' + esc(d.id) + '">Voir</button>'
      });
    });
    peers.forEach((p) => {
      const ps = peerState(p);
      if (ps.tone === "down") {
        items.push({
          tone: "warn", icon: "person_off",
          html: "<b>" + esc(p.name) + " ne donne plus de nouvelles</b> depuis " + esc(fmtAgo(p.last_seen).replace("il y a ", "")) + '.<span class="muted">Sa connexion ou son serveur est peut-être tombé. Une alerte a été envoyée.</span>',
          actions: '<button class="btn sm" type="button" data-open-peer="' + esc(p.pubkey_hex) + '">Voir</button>'
        });
      } else if (ps.tone === "warn") {
        const bad = (p.probes || []).filter((x) => !x.ok);
        const what = bad.length ? bad.slice(0, 2).map((x) => x.id + (x.summary ? " (" + humanize(x.summary) + ")" : "")).join(", ") : "un appareil";
        items.push({
          tone: "warn", icon: "visibility",
          html: "<b>Chez " + esc(p.name) + " : " + esc(what) + ".</b><span class=\"muted\">Ce n'est pas chez vous.</span>",
          actions: '<button class="btn sm" type="button" data-open-peer="' + esc(p.pubkey_hex) + '">Voir</button>'
        });
      }
    });
    if (st.mode !== "setup" && devices.length && !hasAlertChannel()) {
      items.push({
        tone: "warn", icon: "notifications_off",
        html: "<b>Vous ne recevrez aucune alerte.</b><span class=\"muted\">Aucun moyen de vous prévenir n'est activé.</span>",
        actions: '<button class="btn sm" type="button" data-goto="alerts">Configurer</button>'
      });
    }
    if (st.mode !== "setup" && relays.length && !connRelays) {
      items.push({
        tone: "warn", icon: "cloud_off",
        html: "<b>Vos amis ne vous voient plus.</b><span class=\"muted\">Aucun relais du réseau privé n'est joignable.</span>",
        actions: '<button class="btn sm" type="button" data-goto="settings">Réglages</button>'
      });
    }
    if (st.setup_error) {
      items.push({ tone: "down", icon: "error", html: "<b>Configuration incomplète.</b><span class=\"muted\">" + esc(st.setup_error) + "</span>", actions: "" });
    }
    $("attention-list").innerHTML = items.map((it) => (
      '<div class="attention">' +
        '<span class="pill ' + it.tone + '"><span class="ms">' + it.icon + "</span>" + (it.tone === "down" ? "Problème" : "À regarder") + "</span>" +
        "<p>" + it.html + "</p>" + it.actions +
      "</div>"
    )).join("");

    /* Pour bien démarrer */
    const gsDevices = devices.length > 0;
    const gsAlerts = hasAlertChannel();
    const gsFriends = peers.length > 0;
    const gs = $("getting-started");
    gs.hidden = st.mode === "setup" || (gsDevices && gsAlerts && gsFriends);
    [["gs-devices", gsDevices], ["gs-alerts", gsAlerts], ["gs-friends", gsFriends]].forEach(([id, done], i) => {
      const li = $(id);
      li.classList.toggle("done", done);
      li.querySelector(".step-num").innerHTML = done ? CHECK : String(i + 1);
    });

    /* Résumé */
    const ok = devices.filter((d) => d.ok === true).length;
    $("sum-devices").textContent = devices.length ? ok + " sur " + devices.length + " en ligne" : "Aucun";
    const allHist = Object.values(st.probe_history || {}).flat();
    const up = uptimePct(allHist);
    $("sum-devices-sub").textContent = devices.length ? (up != null ? "Disponibilité " + String(up).replace(".", ",") + " % sur les dernières vérifications" : "Première vérification en cours") : "Ajoutez un premier appareil";
    $("sum-friends").textContent = peers.length ? onlinePeers.length + " en ligne" : "Aucun";
    $("sum-friends-sub").textContent = peers.length ? (onlinePeers.length === peers.length ? "Vous veillez aussi sur eux" : plural(peers.length - onlinePeers.length, "ami ne répond pas", "amis ne répondent pas")) : "Invitez un ami à veiller sur vous";
    const n = st.notifications || {};
    const chans = [n.ntfy_enabled ? "ntfy" : "", n.photon_enabled ? "iMessage" : ""].filter(Boolean);
    $("sum-alerts").textContent = chans.length ? "Activées" : "Désactivées";
    $("sum-alerts-sub").textContent = chans.length ? "Par " + chans.join(" et ") : "Choisissez comment être prévenu";

    /* Liste des appareils */
    $("hf-all").textContent = String(devices.length);
    $("hf-down").textContent = String(down.length);
    $$("#home-filter button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.filter === state.homeFilter)));
    const ph = st.probe_history || {};
    const shown = sortDevices(devices).filter((d) => state.homeFilter !== "down" || d.ok === false);
    const box = $("home-devices");
    if (!devices.length) {
      box.innerHTML = '<div class="empty"><span>Aucun appareil pour l\'instant.</span><button class="btn sm primary" type="button" data-action="add"><span class="ms">add</span>Ajouter un appareil</button></div>';
    } else if (!shown.length) {
      box.innerHTML = '<div class="empty">Aucun problème en ce moment.</div>';
    } else {
      box.innerHTML = shown.map((d) => deviceRowHTML(d, ph[d.id] || [])).join("");
    }

    const notWatched = state.dockerContainers.filter((c) => !c.monitored).length;
    const foot = $("home-devices-foot");
    foot.hidden = !notWatched || st.mode === "setup";
    $("home-devices-foot-text").textContent = notWatched ? plural(notWatched, "conteneur Docker de cette machine n'est pas encore surveillé.", "conteneurs Docker de cette machine ne sont pas encore surveillés.") : "";

    /* Amis */
    const fbox = $("home-friends");
    if (!peers.length) {
      fbox.innerHTML = '<div class="empty"><span>Personne ne veille encore sur vous.</span><button class="btn sm" type="button" data-goto="friends">Inviter un ami</button></div>';
    } else {
      fbox.innerHTML = peers.map((p) => {
        const ps = peerState(p);
        const bad = (p.probes || []).filter((x) => !x.ok);
        const line = ps.tone === "warn" && bad.length ? bad[0].id + " : " + humanize(bad[0].summary) : "Signal reçu " + fmtAgo(p.last_seen);
        return (
          '<button class="row" type="button" data-open-peer="' + esc(p.pubkey_hex) + '">' +
            '<span class="avatar" aria-hidden="true">' + esc(initials(p.name)) + "</span>" +
            '<span class="row-main"><span class="row-title"><b>' + esc(p.name) + '</b></span><span class="row-sub"><span>' + esc(line) + "</span></span></span>" +
            '<span class="pill ' + ps.tone + '">' + esc(ps.label) + "</span>" +
          "</button>"
        );
      }).join("");
    }

    /* Activité */
    const incs = (st.incidents || []).slice(-6).reverse();
    $("home-activity").innerHTML = incs.length
      ? incs.map((i) => (
        "<li>" +
          '<span class="ms ' + (i.ok ? "ok" : "down") + '" aria-hidden="true">' + (i.ok ? "check_circle" : "error") + "</span>" +
          "<span>" + esc(incidentText(i)) + "<time>" + esc(fmtAgo(i.ts)) + "</time></span>" +
        "</li>"
      )).join("")
      : '<li class="muted">Rien à signaler pour l\'instant.</li>';

    /* Détails techniques */
    $("tech-summary").textContent = "Détails techniques · " + (connRelays ? "connexion privée active, aucun port ouvert" : "connexion privée en attente");
    const techs = [
      ["Relais Nostr", connRelays + " sur " + relays.length + " joignables"],
      ["Chiffrement", "AES-256-GCM, de bout en bout"],
      ["Signal envoyé", "Toutes les " + fmtDuration(st.heartbeat_interval_sec || 30) + (st.last_heartbeat_at ? " · dernier " + fmtAgo(st.last_heartbeat_at) : "")],
      ["Allumé depuis", fmtDuration(st.uptime_sec || 0)],
      ["Version", (st.version || "dev") + (st.commit ? " (" + st.commit.slice(0, 7) + ")" : "")]
    ];
    $("tech-grid").innerHTML = techs.map(([k, v]) => "<div><dt>" + esc(k) + "</dt><dd>" + esc(v) + "</dd></div>").join("");
  }

  function incidentText(i) {
    const who = i.source === "peer" ? "Chez un ami, " : "";
    const target = i.target || "";
    if (i.ok) return who + target + " répond à nouveau";
    return who + target + " : " + (humanize(i.summary) || "ne répond plus");
  }

  function deviceRowHTML(d, hist) {
    const dot = d.ok === true ? "ok" : d.ok === false ? "down" : "";
    const summary = d.ok === null ? "Première vérification en cours…" : (humanize(d.summary) || (d.ok ? "Répond" : "Ne répond pas"));
    const strip = MW().uptimeStripHTML ? MW().uptimeStripHTML(hist, false, 24) : "";
    const pct = uptimePct(hist);
    return (
      '<button class="row" type="button" data-open-device="' + esc(d.id) + '">' +
        '<span class="row-icon" aria-hidden="true"><span class="ms">' + kindIcon(d.kind) + "</span></span>" +
        '<span class="row-main">' +
          '<span class="row-title"><b>' + esc(d.id) + "</b><small>" + esc(kindLabel(d.kind)) + "</small></span>" +
          '<span class="row-sub" title="' + esc(d.summary || "") + '"><span class="sdot ' + dot + '" aria-hidden="true"></span><span>' + esc(summary) + "</span></span>" +
        "</span>" +
        '<span class="col-bars" aria-label="' + (pct != null ? esc(String(pct).replace(".", ",") + " % des dernières vérifications réussies") : "Pas encore d'historique") + '">' + strip + "</span>" +
        '<span class="col-ms">' + (d.latency != null && d.ok !== null ? esc(d.latency) + " ms" : "—") + "</span>" +
        '<span class="ms chev col-chev" aria-hidden="true">chevron_right</span>' +
      "</button>"
    );
  }

  /* -------------------- Appareils -------------------- */

  function renderDevices() {
    const st = state.status || {};
    const all = sortDevices(deviceList());
    const q = state.deviceSearch.toLowerCase();
    const list = q ? all.filter((d) => (d.id + " " + kindLabel(d.kind) + " " + probeTarget(d.cfg)).toLowerCase().includes(q)) : all;

    if (all.length && !all.some((d) => d.id === state.selectedID)) state.selectedID = all[0].id;

    $("device-nav-count").textContent = plural(all.length, "appareil", "appareils");
    $("device-nav-list").innerHTML = list.map((d) => (
      '<button class="side' + (d.id === state.selectedID ? " on" : "") + '" type="button" data-select-device="' + esc(d.id) + '"' + (d.id === state.selectedID ? ' aria-current="true"' : "") + ">" +
        '<span class="sdot ' + (d.ok === true ? "ok" : d.ok === false ? "down" : "") + '" aria-hidden="true"></span>' +
        '<span class="grow">' + esc(d.id) + "</span>" +
        '<span class="ms" aria-hidden="true">' + kindIcon(d.kind) + "</span>" +
      "</button>"
    )).join("") || '<p class="muted small" style="padding:8px 12px">Aucun résultat.</p>';

    const dev = all.find((d) => d.id === state.selectedID);
    $("device-empty").hidden = Boolean(dev);
    $("device-body").hidden = !dev;
    if (!dev) return;

    const hist = (st.probe_history || {})[dev.id] || [];
    const m = (st.probe_metrics || {})[dev.id] || {};
    const cfg = dev.cfg || {};
    const tone = dev.ok === true ? "ok" : dev.ok === false ? "down" : "off";

    const meta = [kindLabel(dev.kind), probeTarget(cfg), cfg.interval ? "vérifié toutes les " + fmtGoDuration(cfg.interval) : ""].filter(Boolean);
    $("dd-meta").textContent = meta.join(" · ");
    $("dd-name").textContent = dev.id;
    const pill = $("dd-pill");
    pill.className = "pill " + tone;
    $("dd-pill-text").textContent = dev.ok === true ? "Répond normalement" : dev.ok === false ? "Ne répond plus" : "En attente";
    $("dd-summary").textContent = stateSentence(dev, hist);

    $("dd-edit").disabled = dev.idx < 0;
    $("dd-delete").disabled = dev.idx < 0;

    const resCount = (m.nodes?.length || 0) + (m.guests?.length || 0) + (m.disks?.length || 0) + (m.services?.length || 0) + (m.containers?.length || 0) + (m.sensors?.length || 0);
    const rc = $("dd-res-count");
    rc.hidden = !resCount;
    rc.textContent = String(resCount);

    $$(".tab[data-dtab]").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.dtab === state.deviceTab)));
    const panel = $("dd-panel");
    if (state.deviceTab === "details") panel.innerHTML = deviceDetailsHTML(dev, m, cfg);
    else if (state.deviceTab === "history") panel.innerHTML = deviceHistoryHTML(dev, hist, st.incidents || []);
    else {
      panel.innerHTML = deviceOverviewHTML(dev, m, hist, cfg);
      renderDeviceCharts(dev, hist);
    }
  }

  function stateSentence(dev, hist) {
    if (dev.ok === null) return "Première vérification en cours.";
    if (!hist.length) return humanize(dev.summary);
    const cur = hist[hist.length - 1].ok;
    let i = hist.length - 1;
    while (i > 0 && hist[i - 1].ok === cur) i--;
    const outages = [];
    for (let k = 1; k < hist.length; k++) if (!hist[k].ok && hist[k - 1].ok) outages.push(hist[k]);
    if (!cur) {
      return (i > 0 ? "Depuis " + fmtAgo(hist[i].ts).replace("il y a ", "") + ". " : "") + humanize(dev.summary);
    }
    if (i === 0) return hist.length > 1 ? "Aucune coupure sur les " + hist.length + " dernières vérifications." : "Première vérification réussie.";
    return "Depuis " + fmtAgo(hist[i].ts).replace("il y a ", "") + ". " + plural(outages.length || 1, "coupure", "coupures") + " récemment, la dernière à " + fmtClock(hist[i].ts) + ".";
  }

  function gaugeHTML(label, valueTxt, pct, note, warnAt = 80, downAt = 92) {
    const p = Math.max(0, Math.min(100, Number(pct) || 0));
    const cls = p >= downAt ? "down" : p >= warnAt ? "warn" : "";
    return (
      '<div class="card gauge">' +
        '<span class="gauge-label">' + esc(label) + "</span>" +
        '<span class="gauge-value">' + esc(valueTxt) + "</span>" +
        (pct != null ? '<span class="gauge-bar ' + cls + '" aria-hidden="true"><span style="width:' + p + '%"></span></span>' : "") +
        (note ? '<span class="gauge-note">' + esc(note) + "</span>" : "") +
      "</div>"
    );
  }

  function deviceOverviewHTML(dev, m, hist, cfg) {
    const g = [];
    if (typeof m.cpu_percent === "number") g.push(gaugeHTML("Processeur", fmtPct(m.cpu_percent), m.cpu_percent, typeof m.load_avg === "number" ? "Charge " + m.load_avg.toFixed(2).replace(".", ",") : "", (cfg.max_cpu_percent || 90) - 10, cfg.max_cpu_percent || 90));
    if (typeof m.ram_percent === "number") g.push(gaugeHTML("Mémoire", fmtPct(m.ram_percent), m.ram_percent, m.ram_total_mb ? fmtMB(m.ram_used_mb) + " sur " + fmtMB(m.ram_total_mb) : "", (cfg.max_ram_percent || 90) - 10, cfg.max_ram_percent || 90));
    if (typeof m.disk_max_pct === "number") g.push(gaugeHTML("Disque le plus plein", fmtPct(m.disk_max_pct), m.disk_max_pct, "", (cfg.max_disk_percent || 90) - 10, cfg.max_disk_percent || 90));
    if (typeof m.temp_c === "number") g.push(gaugeHTML("Température", Math.round(m.temp_c) + " °C", (m.temp_c / 85) * 100, cfg.max_temp_c ? "Alerte au-delà de " + cfg.max_temp_c + " °C" : "", 70, 85));
    if (typeof m.tls_days === "number") g.push(gaugeHTML("Certificat valide encore", plural(m.tls_days, "jour", "jours"), null, m.tls_expiry ? "Expire le " + m.tls_expiry : ""));
    if (typeof m.http_status === "number") g.push(gaugeHTML("Réponse du site", "Code " + m.http_status, null, ""));
    if (m.containers?.length) {
      const run = m.containers.filter((c) => /running|healthy/i.test(c.state || "")).length;
      g.push(gaugeHTML("Conteneurs", run + " sur " + m.containers.length, null, "en marche"));
    }
    if (m.uptime_sec) g.push(gaugeHTML("Allumé depuis", fmtDuration(m.uptime_sec), null, m.hostname || ""));
    if (dev.latency != null && dev.ok !== null) g.push(gaugeHTML("Temps de réponse", dev.latency + " ms", null, ""));

    const strip = MW().uptimeStripHTML ? MW().uptimeStripHTML(hist, false, 60) : "";
    const pct = uptimePct(hist);

    const rules = [];
    rules.push(["wifi_off", "il ne répond plus lors d'une vérification"]);
    if (cfg.max_cpu_percent) rules.push(["speed", "le processeur dépasse " + cfg.max_cpu_percent + " %"]);
    if (cfg.max_ram_percent) rules.push(["memory", "la mémoire dépasse " + cfg.max_ram_percent + " %"]);
    if (cfg.max_disk_percent) rules.push(["hard_drive", "un disque dépasse " + cfg.max_disk_percent + " %"]);
    if (cfg.max_temp_c) rules.push(["device_thermostat", "la température dépasse " + cfg.max_temp_c + " °C"]);
    if (cfg.tls_min_days != null && dev.kind === "http") rules.push(["lock", "le certificat expire dans moins de " + cfg.tls_min_days + " jours"]);
    if (cfg.contains) rules.push(["text_fields", "la page ne contient plus « " + cfg.contains + " »"]);
    if (cfg.vms?.length) rules.push(["dns", "une de ces VM s'arrête : " + cfg.vms.join(", ")]);
    if (cfg.services?.length) rules.push(["settings", "un de ces services s'arrête : " + cfg.services.join(", ")]);

    return (
      (g.length ? '<section class="gauge-grid" aria-label="Ressources">' + g.join("") + "</section>" : "") +
      '<section class="card chart-card" aria-labelledby="dd-avail-title">' +
        '<div class="chart-card-head"><h2 id="dd-avail-title" class="grow">Disponibilité</h2><span class="muted small">' + (pct != null ? String(pct).replace(".", ",") + " % " + (hist.length > 1 ? "sur les " + hist.length + " dernières vérifications" : "sur la première vérification") : "Pas encore d'historique") + "</span></div>" +
        '<div class="uptime-big">' + strip + "</div>" +
      "</section>" +
      '<section class="card chart-card" aria-label="Graphiques"><div class="chart-grid" id="dd-charts"></div></section>' +
      '<section class="card pad-lg stack" aria-labelledby="dd-rules-title">' +
        '<h2 id="dd-rules-title">Vous êtes prévenu si…</h2>' +
        '<ul class="timeline">' + rules.map(([ic, t]) => '<li><span class="ms muted" aria-hidden="true">' + ic + "</span><span>" + esc(t) + "</span></li>").join("") + "</ul>" +
        (dev.idx >= 0 ? '<div><button class="link-btn" type="button" data-edit-device="' + esc(dev.id) + '">Changer ces seuils</button></div>' : "") +
      "</section>"
    );
  }

  function renderDeviceCharts(dev, hist) {
    const box = $("dd-charts");
    if (!box || !MW().renderLineChart) return;
    const series = [
      { key: "latency_ms", title: "Temps de réponse", color: "var(--ink)", fmt: (v) => Math.round(v) + " ms" },
      { key: "cpu", title: "Processeur", color: "var(--info)", max: 100, fmt: (v) => Math.round(v) + " %" },
      { key: "ram", title: "Mémoire", color: "var(--live)", max: 100, fmt: (v) => Math.round(v) + " %" },
      { key: "disk", title: "Disque", color: "var(--warn)", max: 100, fmt: (v) => Math.round(v) + " %" },
      { key: "temp", title: "Température", color: "var(--error)", fmt: (v) => Math.round(v) + " °C" }
    ].filter((s) => s.key === "latency_ms" || hist.some((p) => typeof p[s.key] === "number"));
    box.innerHTML = series.map((s, i) => '<div id="dd-chart-' + i + '"></div>').join("");
    series.forEach((s, i) => {
      const pts = hist.filter((p) => typeof p[s.key] === "number").map((p) => ({ ts: p.ts, v: p[s.key] }));
      MW().renderLineChart($("dd-chart-" + i), {
        title: s.title,
        data: pts,
        latest: pts.length ? s.fmt(pts[pts.length - 1].v) : "—",
        color: s.color,
        height: 140,
        max: s.max,
        format: s.fmt
      });
    });
  }

  function resStateClass(okish, warnish) {
    return okish ? "state-ok" : warnish ? "state-warn" : "state-down";
  }

  function deviceDetailsHTML(dev, m, cfg) {
    const sections = [];
    const section = (title, rows) => '<section class="card list-card res-section"><h3>' + esc(title) + "</h3>" + rows.join("") + "</section>";
    const meter = (pct) => {
      const v = Math.max(0, Math.min(100, Number(pct) || 0));
      return '<span class="gauge-bar meter ' + (v >= 92 ? "down" : v >= 80 ? "warn" : "") + '" aria-hidden="true"><span style="width:' + v.toFixed(1) + '%"></span></span>';
    };

    if (m.nodes?.length) {
      sections.push(section("Serveurs du cluster", m.nodes.map((n) => (
        '<div class="res-row"><span class="sdot ' + (n.online ? "ok" : "down") + '"></span><div class="grow"><b>' + esc(n.name) + "</b><small>Processeur " + fmtPct(n.cpu_pct) + " · mémoire " + fmtPct(n.ram_pct) + " · allumé depuis " + fmtDuration(n.uptime_sec) + "</small></div>" +
        '<span class="' + resStateClass(n.online) + '">' + (n.online ? "En ligne" : "Hors ligne") + "</span></div>"
      ))));
    }
    if (m.guests?.length) {
      sections.push(section("Machines virtuelles et conteneurs LXC", m.guests.map((g) => {
        const up = String(g.status || "").toLowerCase() === "running";
        const meta = [g.id ? "#" + g.id : "", g.type || "", typeof g.cpu_pct === "number" ? "processeur " + fmtPct(g.cpu_pct) : "", typeof g.ram_pct === "number" ? "mémoire " + fmtPct(g.ram_pct) : ""].filter(Boolean).join(" · ");
        return '<div class="res-row"><span class="sdot ' + (up ? "ok" : "warn") + '"></span><div class="grow"><b>' + esc(g.name || g.id) + "</b><small>" + esc(meta) + '</small></div><span class="' + resStateClass(up, true) + '">' + (up ? "En marche" : esc(g.status || "Arrêtée")) + "</span></div>";
      })));
    }
    if (m.disks?.length) {
      sections.push(section("Disques et stockage", m.disks.map((d) => (
        '<div class="res-row"><div class="grow"><b class="mono">' + esc(d.name) + "</b><small>" + (d.total_gb ? d.used_gb.toFixed(0) + " Go utilisés sur " + d.total_gb.toFixed(0) + " Go" : "") + "</small></div>" + meter(d.used_pct) + '<span class="mono">' + fmtPct(d.used_pct) + "</span></div>"
      ))));
    }
    if (m.containers?.length) {
      sections.push(section("Conteneurs", m.containers.map((c) => {
        const s = String(c.state || "").toLowerCase();
        const okc = s === "running" || s === "healthy";
        const bad = s === "unhealthy" || s === "exited" || s === "dead";
        return '<div class="res-row"><span class="sdot ' + (okc ? "ok" : bad ? "down" : "warn") + '"></span><div class="grow"><b class="mono">' + esc(c.name) + "</b>" + (c.health ? "<small>Santé : " + esc(c.health) + "</small>" : "") + '</div><span class="' + resStateClass(okc, !bad) + '">' + esc(okc ? "En marche" : c.state || "—") + "</span></div>";
      })));
    }
    if (m.services?.length) {
      sections.push(section("Services", m.services.map((s) => (
        '<div class="res-row"><span class="sdot ' + (s.active ? "ok" : "down") + '"></span><div class="grow"><b class="mono">' + esc(s.name) + '</b></div><span class="' + resStateClass(s.active) + '">' + (s.active ? "Actif" : esc(s.state || "Arrêté")) + "</span></div>"
      ))));
    }
    if (m.sensors?.length) {
      sections.push(section("Capteurs et matériel", m.sensors.map((s) => (
        '<div class="res-row"><span class="sdot ' + (s.ok ? "ok" : "down") + '"></span><div class="grow"><b>' + esc(s.name) + "</b>" + (typeof s.temp_c === "number" ? "<small>" + Math.round(s.temp_c) + " °C</small>" : "") + '</div><span class="' + resStateClass(s.ok) + '">' + esc(s.status || (s.ok ? "OK" : "Alerte")) + "</span></div>"
      ))));
    }

    const kv = [
      ["Dernier message", dev.summary || ""],
      ["Adresse", m.target || probeTarget(cfg)],
      ["Machine", [m.hostname, m.os].filter(Boolean).join(" · ")],
      ["Certificat", m.tls_subject ? m.tls_subject + (m.tls_expiry ? " (expire le " + m.tls_expiry + ")" : "") : ""],
      ["Valeur SNMP", m.snmp_value || ""],
      ["Vérification", cfg.interval ? "toutes les " + fmtGoDuration(cfg.interval) + ", abandon après " + fmtGoDuration(cfg.timeout || "10s") : ""],
      ["Type", kindLabel(dev.kind)]
    ].filter((p) => p[1]);
    sections.push('<section class="card pad-lg stack"><h3>Informations techniques</h3><dl class="kv">' + kv.map(([k, v]) => "<dt>" + esc(k) + '</dt><dd class="mono">' + esc(v) + "</dd>").join("") + "</dl></section>");

    if (sections.length === 1) {
      sections.unshift('<div class="empty-big"><span class="ms">info</span><p>Ce type d\'appareil ne remonte pas de détail supplémentaire.</p></div>');
    }
    return sections.join("");
  }

  function deviceHistoryHTML(dev, hist, incidents) {
    const related = incidents.filter((i) => i.target === dev.id).slice(-15).reverse();
    const samples = hist.slice(-20).reverse();
    return (
      '<section class="card pad-lg stack"><h2>Événements</h2>' +
        (related.length
          ? '<ol class="timeline">' + related.map((i) => '<li><span class="ms ' + (i.ok ? "ok" : "down") + '" aria-hidden="true">' + (i.ok ? "check_circle" : "error") + "</span><span>" + esc(i.ok ? "Répond à nouveau" : "Ne répond plus") + (!i.ok && i.summary ? " · " + esc(humanize(i.summary)) : "") + "<time>" + esc(fmtClock(i.ts)) + "</time></span></li>").join("") + "</ol>"
          : '<p class="muted">Aucune coupure enregistrée depuis le démarrage.</p>') +
      "</section>" +
      '<section class="card list-card res-section"><h3>Dernières vérifications</h3>' +
        (samples.length
          ? samples.map((p) => {
            const extra = [typeof p.cpu === "number" ? "processeur " + fmtPct(p.cpu) : "", typeof p.ram === "number" ? "mémoire " + fmtPct(p.ram) : "", typeof p.disk === "number" ? "disque " + fmtPct(p.disk) : "", typeof p.temp === "number" ? Math.round(p.temp) + " °C" : ""].filter(Boolean).join(" · ");
            return '<div class="res-row"><span class="sdot ' + (p.ok ? "ok" : "down") + '"></span><div class="grow"><b class="mono">' + esc(fmtClock(p.ts)) + "</b>" + (extra ? "<small>" + esc(extra) + "</small>" : "") + '</div><span class="mono muted">' + esc(p.latency_ms || 0) + ' ms</span><span class="' + (p.ok ? "state-ok" : "state-down") + '">' + (p.ok ? "OK" : "Échec") + "</span></div>";
          }).join("")
          : '<div class="empty">Pas encore de vérification enregistrée.</div>') +
      "</section>"
    );
  }

  /* -------------------- Actions sur les appareils -------------------- */

  async function runAllNow(btn) {
    setBusy(btn, true);
    try {
      const res = await apiFetch("/api/probes/run", { method: "POST", body: "{}" });
      await fetchStatus();
      const list = res.probes || [];
      const ok = list.filter((p) => p.ok).length;
      toast(ok === list.length ? "Tout répond (" + plural(list.length, "appareil", "appareils") + ")." : (list.length - ok) + " sur " + list.length + " ne répondent pas.", ok === list.length ? "ok" : "warn");
    } catch (e) {
      toast("Vérification impossible : " + e.message, "err");
    } finally {
      setBusy(btn, false);
    }
  }

  async function testDevice(id, btn) {
    const cfg = (state.draft?.probes || []).find((p) => p.id === id);
    if (!cfg) return runAllNow(btn);
    setBusy(btn, true);
    try {
      const res = await apiFetch("/api/probes/test", { method: "POST", body: JSON.stringify({ probe: cfg }) });
      await fetchStatus();
      toast(id + " : " + (res.ok ? "répond" : "ne répond pas") + (res.summary ? " · " + res.summary : ""), res.ok ? "ok" : "err");
    } catch (e) {
      toast("Vérification impossible : " + e.message, "err");
    } finally {
      setBusy(btn, false);
    }
  }

  async function deleteDevice(id) {
    const ok = await confirmDialog("Supprimer " + id + " ?", "MeshWatch arrêtera de surveiller cet appareil. Son historique sera perdu.", "Supprimer");
    if (!ok) return;
    const idx = (state.draft?.probes || []).findIndex((p) => p.id === id);
    if (idx < 0) return;
    state.draft.probes.splice(idx, 1);
    state.selectedID = "";
    if (await saveConfiguration(false)) toast(id + " n'est plus surveillé.");
  }

  /* -------------------- Découverte -------------------- */

  async function detectDiscoverDefaults() {
    try {
      const info = await apiFetch("/api/discover/info", { method: "GET" });
      state.discoverInfo = info;
      if (info.docker_socket) state.dockerSocket = info.docker_socket;
      if (info.docker_available) runDockerScan(true);
    } catch {
      /* découverte facultative */
    }
  }

  async function runDockerScan(silent = false) {
    try {
      const res = await apiFetch("/api/discover/docker", { method: "POST", body: JSON.stringify({ socket: state.dockerSocket }) });
      state.dockerContainers = res.containers || [];
      if (res.socket) state.dockerSocket = res.socket;
    } catch (e) {
      state.dockerContainers = [];
      if (!silent) toast("Docker inaccessible : " + e.message, "err");
    }
    if (state.status && state.tab === "home") renderHome(state.status);
    if (state.wizard.open) renderFound();
  }

  async function runLANScan() {
    if (state.lanScanning) return;
    state.lanScanning = true;
    renderFound();
    try {
      const res = await apiFetch("/api/discover/lan", {
        method: "POST",
        body: JSON.stringify({ subnet: state.discoverInfo?.default_subnet || "", docker_socket: state.dockerSocket })
      });
      state.lanItems = res.items || [];
      state.lanScanned = true;
      state.lanMeta = (res.subnet || "") + " · " + plural(res.scanned_ips || 0, "adresse vérifiée", "adresses vérifiées");
    } catch (e) {
      toast("Recherche sur le réseau impossible : " + e.message, "err");
    } finally {
      state.lanScanning = false;
      renderFound();
    }
  }

  async function watchContainers(names) {
    state.draft = ensureDraftShape(state.draft || state.config);
    let probe = state.draft.probes.find((p) => p.kind === "docker");
    if (probe) {
      const set = new Set(probe.containers || []);
      names.forEach((n) => set.add(n));
      probe.containers = Array.from(set);
      probe.socket = probe.socket || state.dockerSocket;
    } else {
      state.draft.probes.push({ id: "conteneurs-docker", kind: "docker", socket: state.dockerSocket, containers: names.slice(), interval: "30s", timeout: "10s" });
    }
    if (await saveConfiguration(false)) {
      toast(names.length > 1 ? plural(names.length, "conteneur ajouté", "conteneurs ajoutés") + "." : names[0] + " est maintenant surveillé.");
      await runDockerScan(true);
    }
  }

  function renderFound() {
    const box = $("found-list");
    if (!box) return;
    const containers = state.dockerContainers.filter((c) => !c.monitored);
    const lan = (state.lanItems || []).filter((it) => !it.already_monitored && it.suggested_probe);
    const rows = [];

    containers.forEach((c) => {
      rows.push(
        '<div class="found-row">' +
          '<span class="row-icon" aria-hidden="true"><span class="ms">deployed_code</span></span>' +
          '<span class="row-main"><span class="row-title"><b>' + esc(c.name) + "</b></span>" +
          '<span class="row-sub"><span>Conteneur Docker · ' + esc(c.image || "") + "</span></span></span>" +
          '<span class="muted small">' + (c.running ? "Prêt" : "Arrêté") + "</span>" +
          '<button class="btn sm" type="button" data-watch-container="' + esc(c.name) + '">Surveiller</button>' +
        "</div>"
      );
    });
    lan.forEach((it) => {
      const k = it.suggested_probe.kind;
      const needs = k === "proxmox" ? "Jeton requis" : k === "windows_winrm" || k === "linux_ssh" ? "Identifiants requis" : k === "synology" ? "SNMP à activer" : "Prêt";
      rows.push(
        '<div class="found-row">' +
          '<span class="row-icon" aria-hidden="true"><span class="ms">' + kindIcon(k) + "</span></span>" +
          '<span class="row-main"><span class="row-title"><b>' + esc(it.name || it.hostname || it.ip) + "</b></span>" +
          '<span class="row-sub"><span>' + esc(it.category_label || kindLabel(k)) + ' · <span class="mono">' + esc(it.ip) + "</span></span></span></span>" +
          '<span class="muted small">' + esc(needs) + "</span>" +
          '<button class="btn sm" type="button" data-lan-add="' + esc(it.key) + '">Surveiller</button>' +
        "</div>"
      );
    });

    const LIMIT = 5;
    const hiddenCount = Math.max(0, rows.length - LIMIT);
    if (hiddenCount && !state.foundExpanded) {
      rows.length = LIMIT;
      rows.push('<div class="card-foot"><button class="link-btn" type="button" id="found-more">Voir les ' + hiddenCount + " autres</button></div>");
    }
    if (state.lanScanning) {
      rows.push('<div class="empty"><span class="spinner" aria-hidden="true"></span><span>Recherche sur votre réseau… cela prend quelques secondes.</span></div>');
    } else if (!rows.length) {
      rows.push('<div class="empty">' + (state.lanScanned ? "Rien de nouveau trouvé : tout ce qui a été détecté est déjà surveillé." : "Aucun conteneur Docker nouveau. Lancez une recherche sur le réseau pour trouver NAS, serveurs et PC.") + "</div>");
    }
    box.innerHTML = rows.join("");
    $("found-more")?.addEventListener("click", () => { state.foundExpanded = true; renderFound(); });

    $("found-meta").textContent = state.lanScanned ? state.lanMeta || "" : (state.dockerContainers.length ? "Docker de cette machine" : "");
    const scanBtn = $("found-lan-scan");
    if (scanBtn) {
      scanBtn.disabled = state.lanScanning;
      scanBtn.innerHTML = '<span class="ms">wifi_find</span>' + (state.lanScanned ? "Chercher à nouveau" : "Chercher sur le réseau");
    }
    const foot = $("found-foot");
    foot.hidden = containers.length < 2;
    $("found-foot-text").textContent = containers.length >= 2 ? "Les " + containers.length + " conteneurs se surveillent sans rien saisir." : "";
  }

  /* -------------------- Assistant d'ajout -------------------- */

  function openWizard(editIndex = -1, template = null) {
    state.lastFocus = document.activeElement;
    state.wizard = { open: true, step: 1, kind: "", editIndex, testedOK: false };
    state.foundExpanded = false;
    $("wizard").hidden = false;
    renderTypeGrids();
    if (editIndex >= 0 && state.draft?.probes?.[editIndex]) {
      const p = clone(state.draft.probes[editIndex]);
      showWizardForm(p.kind || "http", p);
    } else if (template) {
      showWizardForm(template.kind || "http", template);
    } else {
      showWizardPick();
      if (!state.dockerContainers.length && state.discoverInfo?.docker_available) runDockerScan(true);
    }
  }

  function closeWizard() {
    $("wizard").hidden = true;
    state.wizard.open = false;
    state.lastFocus?.focus?.();
  }

  function setWizardStep(step) {
    state.wizard.step = step;
    $$("#wizard-stepper li[data-step]").forEach((li) => {
      const n = Number(li.dataset.step);
      li.classList.toggle("on", n === step);
      li.classList.toggle("done", n < step);
      li.querySelector(".step-num").innerHTML = n < step ? CHECK : String(n);
      if (n === step) li.setAttribute("aria-current", "step");
      else li.removeAttribute("aria-current");
    });
  }

  function renderTypeGrids() {
    const card = ([k, v]) => '<button class="type" type="button" data-pick-kind="' + k + '"><span class="ms" aria-hidden="true">' + v.icon + "</span><b>" + esc(v.label) + "</b><span>" + esc(v.desc) + "</span></button>";
    $("type-grid").innerHTML = Object.entries(KINDS).filter(([, v]) => !v.advanced).map(card).join("");
    $("type-grid-adv").innerHTML = Object.entries(KINDS).filter(([, v]) => v.advanced).map(card).join("");
  }

  function showWizardPick() {
    setWizardStep(1);
    $("wizard-title").textContent = "Ajouter un appareil";
    $("wizard-sub").textContent = "Que voulez-vous surveiller ? On a déjà cherché sur votre réseau.";
    $("wizard-stepper").hidden = false;
    $("wizard-step-pick").hidden = false;
    $("wizard-step-form").hidden = true;
    $("wizard-back").hidden = true;
    $("wizard-submit").hidden = true;
    $("wizard-save-anyway").hidden = true;
    $("wizard-foot-text").textContent = "Rien n'est ajouté tant que vous n'avez pas testé la connexion.";
    renderFound();
  }

  function fieldHTML(id, label, input, hint) {
    return '<label class="field" for="' + id + '"><span>' + esc(label) + "</span>" + input + (hint ? "<small>" + esc(hint) + "</small>" : "") + "</label>";
  }

  function inp(id, value, opts = {}) {
    const type = opts.type || "text";
    return '<input class="input' + (opts.mono ? " mono" : "") + '" type="' + type + '" id="' + id + '" value="' + esc(value == null ? "" : value) + '"' +
      (opts.placeholder ? ' placeholder="' + esc(opts.placeholder) + '"' : "") +
      (opts.required ? " required" : "") + (opts.step ? ' step="' + opts.step + '"' : "") +
      ' autocomplete="off" spellcheck="false" />';
  }

  function secretInp(id, value, placeholder) {
    return '<span class="input-group">' + inp(id, value, { type: "password", placeholder, mono: true }) + '<button class="btn sm ghost" type="button" data-reveal="' + id + '">Afficher</button></span>';
  }

  function thresholdsHTML(p, which, defaults = {}) {
    const parts = [];
    if (which.includes("cpu")) parts.push(fieldHTML("pf-max-cpu", "Alerte processeur au-delà de (%)", inp("pf-max-cpu", p.max_cpu_percent || defaults.cpu || 90, { type: "number" })));
    if (which.includes("ram")) parts.push(fieldHTML("pf-max-ram", "Alerte mémoire au-delà de (%)", inp("pf-max-ram", p.max_ram_percent || defaults.ram || 90, { type: "number" })));
    if (which.includes("disk")) parts.push(fieldHTML("pf-max-disk", "Alerte disque au-delà de (%)", inp("pf-max-disk", p.max_disk_percent || defaults.disk || 90, { type: "number" })));
    return '<div class="form-3">' + parts.join("") + "</div>";
  }

  function snmpHTML(p) {
    const ver = String(p.snmp_version || "2c") === "3" ? "3" : "2c";
    const opt = (list, cur) => list.map((a) => '<option value="' + a + '"' + (String(cur || "").toUpperCase() === a ? " selected" : "") + ">" + a + "</option>").join("");
    return (
      '<div class="form-3">' +
        fieldHTML("pf-host", "Adresse IP ou nom", inp("pf-host", p.host, { placeholder: "192.168.1.20", required: true })) +
        fieldHTML("pf-port", "Port", inp("pf-port", p.port || 161, { type: "number" })) +
        fieldHTML("pf-snmp-version", "Version SNMP", '<select class="input" id="pf-snmp-version"><option value="2c"' + (ver === "2c" ? " selected" : "") + '>v2c (simple)</option><option value="3"' + (ver === "3" ? " selected" : "") + ">v3 (chiffré)</option></select>") +
      "</div>" +
      '<div id="pf-snmp-v2"' + (ver === "3" ? " hidden" : "") + ">" + fieldHTML("pf-community", "Communauté", inp("pf-community", p.community || "public"), "« public » par défaut sur la plupart des appareils.") + "</div>" +
      '<div id="pf-snmp-v3" class="stack"' + (ver === "3" ? "" : " hidden") + ">" +
        '<div class="form-3">' +
          fieldHTML("pf-snmp-user", "Utilisateur", inp("pf-snmp-user", p.user)) +
          fieldHTML("pf-auth-proto", "Authentification", '<select class="input" id="pf-auth-proto">' + opt(["NONE", "MD5", "SHA", "SHA256", "SHA512"], p.auth_proto || "SHA256") + "</select>") +
          fieldHTML("pf-auth-pass", "Mot de passe", secretInp("pf-auth-pass", p.auth_pass)) +
        "</div>" +
        '<div class="form-2">' +
          fieldHTML("pf-priv-proto", "Chiffrement", '<select class="input" id="pf-priv-proto">' + opt(["NONE", "DES", "AES", "AES192", "AES256"], p.priv_proto || "AES") + "</select>") +
          fieldHTML("pf-priv-pass", "Mot de passe de chiffrement", secretInp("pf-priv-pass", p.priv_pass)) +
        "</div>" +
      "</div>"
    );
  }

  function showWizardForm(kind, p = {}) {
    const w = state.wizard;
    w.kind = kind;
    w.testedOK = false;
    const editing = w.editIndex >= 0;
    setWizardStep(2);
    $("wizard-title").textContent = editing ? "Modifier " + p.id : kindLabel(kind);
    $("wizard-sub").textContent = editing ? kindLabel(kind) : KINDS[kind]?.desc || "";
    $("wizard-stepper").hidden = false;
    $("wizard-step-pick").hidden = true;
    $("wizard-step-form").hidden = false;
    $("wizard-back").hidden = editing;
    $("wizard-submit").hidden = false;
    $("wizard-save-anyway").hidden = true;
    $("wizard-submit-text").textContent = "Tester et enregistrer";
    $("wizard-foot-text").textContent = "";
    $("wizard-test").hidden = true;

    const guide = GUIDES[kind];
    const gb = $("wizard-guide");
    gb.hidden = !guide;
    gb.innerHTML = guide ? '<span class="ms" aria-hidden="true">info</span><span>' + esc(guide) + "</span>" : "";

    $("pf-interval").value = p.interval || (kind === "http" || kind === "tcp" || kind === "docker" ? "30s" : "1m");
    $("pf-timeout").value = p.timeout || (kind === "windows_winrm" || kind === "linux_ssh" ? "15s" : "10s");
    $("pf-insecure").checked = Boolean(p.insecure_skip_verify);

    let h = fieldHTML("pf-id", "Nom affiché", inp("pf-id", p.id, { placeholder: "Ex. nas-salon" }), editing ? "" : "Laissez vide : on le déduira de l'adresse.");

    if (kind === "http") {
      h += fieldHTML("pf-url", "Adresse du site", inp("pf-url", p.url, { type: "url", placeholder: "https://jellyfin.maison.lan", required: true }));
      h += '<details class="fold"><summary>Vérifications en plus</summary><div class="form-3">' +
        fieldHTML("pf-http-status", "Code de réponse attendu", inp("pf-http-status", p.expected_status || 200, { type: "number" })) +
        fieldHTML("pf-contains", "Texte qui doit apparaître", inp("pf-contains", p.contains, { placeholder: "facultatif" })) +
        fieldHTML("pf-tls-days", "Prévenir avant expiration du certificat (jours)", inp("pf-tls-days", p.tls_min_days != null ? p.tls_min_days : 14, { type: "number" })) +
        "</div></details>";
    } else if (kind === "tcp") {
      const hp = p.host ? { host: p.host, port: p.port || 22 } : splitHostPort(p.address, 22);
      h += '<div class="form-2">' + fieldHTML("pf-host", "Adresse IP ou nom", inp("pf-host", hp.host, { placeholder: "192.168.1.10", required: true })) + fieldHTML("pf-port", "Port", inp("pf-port", hp.port || 22, { type: "number", required: true })) + "</div>";
    } else if (kind === "docker") {
      h += fieldHTML("pf-containers", "Conteneurs à surveiller", inp("pf-containers", (p.containers || []).join(", "), { placeholder: "traefik, immich-server" }), "Séparés par des virgules. Laissez vide pour tous.");
      h += '<details class="fold"><summary>Options Docker</summary><div class="form-3">' +
        fieldHTML("pf-socket", "Socket Docker", inp("pf-socket", p.socket || state.dockerSocket, { mono: true })) +
        fieldHTML("pf-label", "Seulement avec l'étiquette", inp("pf-label", p.label, { placeholder: "meshwatch.enable=true" })) +
        fieldHTML("pf-max-restarts", "Redémarrages tolérés", inp("pf-max-restarts", p.max_restarts || "", { type: "number", placeholder: "0" })) +
        "</div></details>";
    } else if (kind === "synology") {
      h += snmpHTML(p) + fieldHTML("pf-max-temp", "Alerte température au-delà de (°C)", inp("pf-max-temp", p.max_temp_c || 55, { type: "number" }));
    } else if (kind === "snmp_oid") {
      h += snmpHTML(p) +
        '<div class="form-2">' + fieldHTML("pf-oid", "OID à lire", inp("pf-oid", p.oid || ".1.3.6.1.2.1.1.3.0", { mono: true, required: true })) + fieldHTML("pf-expected-value", "Valeur attendue", inp("pf-expected-value", p.expected_value, { placeholder: "facultatif" })) + "</div>" +
        '<div class="form-2">' + fieldHTML("pf-min-value", "Minimum", inp("pf-min-value", p.min_value != null ? p.min_value : "", { type: "number", step: "any", placeholder: "facultatif" })) + fieldHTML("pf-max-value", "Maximum", inp("pf-max-value", p.max_value != null ? p.max_value : "", { type: "number", step: "any", placeholder: "facultatif" })) + "</div>";
    } else if (kind === "proxmox") {
      h += '<div class="form-2">' + fieldHTML("pf-url", "Adresse de Proxmox", inp("pf-url", p.url, { placeholder: "https://192.168.1.10:8006", required: true })) + fieldHTML("pf-node", "Nœud", inp("pf-node", p.node, { placeholder: "tous si vide" })) + "</div>";
      h += '<div class="form-2">' + fieldHTML("pf-token-id", "Identifiant du jeton", inp("pf-token-id", p.token_id, { mono: true, placeholder: "root@pam!meshwatch", required: true })) + fieldHTML("pf-token-secret", "Secret du jeton", secretInp("pf-token-secret", p.token_secret)) + "</div>";
      h += '<details class="fold"><summary>Seuils et VM importantes</summary><div class="stack">' + thresholdsHTML(p, ["cpu", "ram", "disk"]) +
        '<div class="form-2">' + fieldHTML("pf-vms", "VM ou LXC qui doivent tourner", inp("pf-vms", (p.vms || []).join(", "), { placeholder: "100, 101 ou leurs noms" })) + fieldHTML("pf-disks", "Stockages à surveiller", inp("pf-disks", (p.disks || []).join(", "), { placeholder: "local, local-lvm" })) + "</div></div></details>";
    } else if (kind === "windows_winrm") {
      h += '<div class="form-3">' + fieldHTML("pf-host", "Adresse IP ou nom", inp("pf-host", p.host, { placeholder: "192.168.1.40", required: true })) + fieldHTML("pf-user", "Utilisateur", inp("pf-user", p.user || "Administrator")) + fieldHTML("pf-password", "Mot de passe", secretInp("pf-password", p.password)) + "</div>";
      h += '<details class="fold"><summary>Connexion, seuils, services</summary><div class="stack">' +
        '<div class="form-3">' + fieldHTML("pf-port", "Port WinRM", inp("pf-port", p.port || 5985, { type: "number" })) + fieldHTML("pf-domain", "Domaine", inp("pf-domain", p.domain, { placeholder: "facultatif" })) + '<label class="check"><input type="checkbox" id="pf-use-https"' + (p.use_https ? " checked" : "") + " /><span>Connexion HTTPS (port 5986)</span></label></div>" +
        thresholdsHTML(p, ["cpu", "ram", "disk"]) +
        '<div class="form-3">' + fieldHTML("pf-vms", "VM Hyper-V qui doivent tourner", inp("pf-vms", (p.vms || []).join(", "), { placeholder: "DC01, SQL01" })) + fieldHTML("pf-services", "Services Windows", inp("pf-services", (p.services || []).join(", "), { placeholder: "W3SVC, Spooler" })) + fieldHTML("pf-disks", "Lecteurs", inp("pf-disks", (p.disks || []).join(", "), { placeholder: "C:, D:" })) + "</div>" +
        "</div></details>";
    } else if (kind === "linux_ssh") {
      h += '<div class="form-3">' + fieldHTML("pf-host", "Adresse IP ou nom", inp("pf-host", p.host, { placeholder: "192.168.1.45", required: true })) + fieldHTML("pf-user", "Utilisateur", inp("pf-user", p.user || "root")) + fieldHTML("pf-password", "Mot de passe", secretInp("pf-password", p.password, "ou une clé ci-dessous")) + "</div>";
      h += '<details class="fold"' + (p.ssh_key ? " open" : "") + '><summary>Se connecter avec une clé SSH</summary>' + fieldHTML("pf-ssh-key", "Clé privée", '<textarea class="input mono" id="pf-ssh-key" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" spellcheck="false">' + esc(p.ssh_key || "") + "</textarea>") + "</details>";
      h += '<details class="fold"><summary>Port, seuils, services</summary><div class="stack">' +
        '<div class="form-3">' + fieldHTML("pf-port", "Port SSH", inp("pf-port", p.port || 22, { type: "number" })) + "</div>" +
        thresholdsHTML(p, ["cpu", "ram", "disk"]) +
        '<div class="form-2">' + fieldHTML("pf-services", "Services qui doivent tourner", inp("pf-services", (p.services || []).join(", "), { placeholder: "docker, nginx" })) + fieldHTML("pf-disks", "Points de montage", inp("pf-disks", (p.disks || []).join(", "), { placeholder: "/, /var" })) + "</div>" +
        "</div></details>";
    } else if (kind === "node_exporter" || kind === "windows_exporter") {
      const port = kind === "windows_exporter" ? "9182" : "9100";
      h += fieldHTML("pf-url", "Adresse des métriques", inp("pf-url", p.url, { type: "url", placeholder: "http://192.168.1.10:" + port + "/metrics", required: true }));
      h += '<details class="fold"><summary>Seuils</summary><div class="stack">' + thresholdsHTML(p, ["ram", "disk"], { ram: 92 }) +
        '<div class="form-2">' + fieldHTML("pf-disks", "Disques", inp("pf-disks", (p.disks || []).join(", "), { placeholder: kind === "windows_exporter" ? "C:, D:" : "/, /home" })) +
        (kind === "windows_exporter" ? fieldHTML("pf-services", "Services Windows", inp("pf-services", (p.services || []).join(", "), { placeholder: "W3SVC" })) : "") + "</div></div></details>";
    }

    $("wizard-fields").innerHTML = h;
    $("pf-snmp-version")?.addEventListener("change", () => {
      const v3 = $("pf-snmp-version").value === "3";
      $("pf-snmp-v2").hidden = v3;
      $("pf-snmp-v3").hidden = !v3;
    });
    $$("#wizard-fields input, #wizard-fields textarea, #wizard-fields select").forEach((el) => el.addEventListener("input", () => {
      if (state.wizard.step === 3) {
        setWizardStep(2);
        $("wizard-test").hidden = true;
        $("wizard-save-anyway").hidden = true;
        $("wizard-submit-text").textContent = "Tester et enregistrer";
      }
      el.classList.remove("invalid");
    }));
    const first = $("wizard-fields").querySelector("[required]") || $("pf-id");
    setTimeout(() => first?.focus(), 40);
  }

  const val = (id) => ($(id)?.value || "").trim();

  function readSNMP(obj) {
    obj.host = val("pf-host");
    obj.port = Number(val("pf-port")) || 161;
    obj.snmp_version = val("pf-snmp-version") || "2c";
    if (obj.snmp_version === "3") {
      obj.user = val("pf-snmp-user");
      obj.auth_proto = val("pf-auth-proto") || "SHA256";
      obj.auth_pass = $("pf-auth-pass")?.value || "";
      obj.priv_proto = val("pf-priv-proto") || "AES";
      obj.priv_pass = $("pf-priv-pass")?.value || "";
    } else {
      obj.community = val("pf-community") || "public";
    }
  }

  function readWizardProbe() {
    const kind = state.wizard.kind;
    const o = { id: val("pf-id"), kind, interval: val("pf-interval") || "1m", timeout: val("pf-timeout") || "10s" };
    const num = (id) => Number(val(id)) || 0;

    if (kind === "http") {
      o.url = val("pf-url");
      o.expected_status = num("pf-http-status") || 200;
      if (val("pf-contains")) o.contains = val("pf-contains");
      if (val("pf-tls-days") !== "") o.tls_min_days = Number(val("pf-tls-days"));
      o.insecure_skip_verify = $("pf-insecure").checked;
    } else if (kind === "tcp") {
      o.host = val("pf-host");
      o.port = num("pf-port") || 22;
      o.address = o.host ? o.host + ":" + o.port : "";
    } else if (kind === "docker") {
      o.socket = val("pf-socket") || state.dockerSocket;
      o.containers = splitCSV(val("pf-containers"));
      if (val("pf-label")) o.label = val("pf-label");
      if (num("pf-max-restarts") > 0) o.max_restarts = num("pf-max-restarts");
    } else if (kind === "synology") {
      readSNMP(o);
      o.max_temp_c = num("pf-max-temp") || 55;
    } else if (kind === "snmp_oid") {
      readSNMP(o);
      o.oid = val("pf-oid");
      if (val("pf-expected-value")) o.expected_value = val("pf-expected-value");
      if (val("pf-min-value") !== "" && !Number.isNaN(Number(val("pf-min-value")))) o.min_value = Number(val("pf-min-value"));
      if (val("pf-max-value") !== "" && !Number.isNaN(Number(val("pf-max-value")))) o.max_value = Number(val("pf-max-value"));
    } else if (kind === "proxmox") {
      o.url = val("pf-url");
      if (o.url && !/^https?:\/\//.test(o.url)) o.url = "https://" + o.url + (/:\d+$/.test(o.url) ? "" : ":8006");
      if (val("pf-node")) o.node = val("pf-node");
      o.insecure_skip_verify = $("pf-insecure").checked;
      o.token_id = val("pf-token-id");
      o.token_secret = val("pf-token-secret");
      o.max_cpu_percent = num("pf-max-cpu");
      o.max_ram_percent = num("pf-max-ram");
      o.max_disk_percent = num("pf-max-disk");
      o.vms = splitCSV(val("pf-vms"));
      o.disks = splitCSV(val("pf-disks"));
    } else if (kind === "windows_winrm") {
      o.host = val("pf-host");
      o.use_https = Boolean($("pf-use-https")?.checked);
      o.port = num("pf-port") || (o.use_https ? 5986 : 5985);
      o.insecure_skip_verify = $("pf-insecure").checked;
      o.domain = val("pf-domain");
      o.user = val("pf-user");
      o.password = $("pf-password")?.value || "";
      o.max_cpu_percent = num("pf-max-cpu");
      o.max_ram_percent = num("pf-max-ram");
      o.max_disk_percent = num("pf-max-disk");
      o.vms = splitCSV(val("pf-vms"));
      o.services = splitCSV(val("pf-services"));
      o.disks = splitCSV(val("pf-disks"));
    } else if (kind === "linux_ssh") {
      o.host = val("pf-host");
      o.port = num("pf-port") || 22;
      o.user = val("pf-user");
      o.password = $("pf-password")?.value || "";
      o.ssh_key = $("pf-ssh-key")?.value || "";
      o.max_cpu_percent = num("pf-max-cpu");
      o.max_ram_percent = num("pf-max-ram");
      o.max_disk_percent = num("pf-max-disk");
      o.services = splitCSV(val("pf-services"));
      o.disks = splitCSV(val("pf-disks"));
    } else if (kind === "node_exporter" || kind === "windows_exporter") {
      o.url = val("pf-url");
      o.max_ram_percent = num("pf-max-ram");
      o.max_disk_percent = num("pf-max-disk");
      o.disks = splitCSV(val("pf-disks"));
      if (kind === "windows_exporter") o.services = splitCSV(val("pf-services"));
    }

    if (!o.id) {
      const src = String(o.url || o.host || kindLabel(kind)).replace(/^[a-z]+:\/\//i, "").replace(/[:/].*$/, "");
      const base = slugify(o.kind === "docker" ? "conteneurs-docker" : src) || kind;
      let id = base;
      let n = 2;
      const taken = new Set((state.draft?.probes || []).filter((_, i) => i !== state.wizard.editIndex).map((p) => p.id));
      while (taken.has(id)) id = base + "-" + n++;
      o.id = id;
    }
    return o;
  }

  function validateWizard() {
    let firstBad = null;
    $$("#wizard-fields [required]").forEach((el) => {
      const bad = !String(el.value || "").trim();
      el.classList.toggle("invalid", bad);
      if (bad && !firstBad) firstBad = el;
    });
    const id = val("pf-id");
    const taken = (state.draft?.probes || []).some((p, i) => i !== state.wizard.editIndex && p.id === id);
    if (id && taken) {
      $("pf-id").classList.add("invalid");
      toast("Un appareil s'appelle déjà « " + id + " ».", "warn");
      return $("pf-id");
    }
    if (firstBad) toast("Il manque une information.", "warn");
    return firstBad;
  }

  async function wizardSubmit() {
    const bad = validateWizard();
    if (bad) { bad.focus(); return; }
    const probe = readWizardProbe();
    setWizardStep(3);
    const box = $("wizard-test");
    box.hidden = false;
    box.className = "test-result pending";
    box.innerHTML = '<span class="spinner" aria-hidden="true"></span><div class="grow"><b>Test de la connexion…</b><span>Cela peut prendre quelques secondes.</span></div>';
    const btn = $("wizard-submit");
    setBusy(btn, true);
    try {
      const res = await apiFetch("/api/probes/test", { method: "POST", body: JSON.stringify({ probe }) });
      if (res.ok) {
        box.className = "test-result ok";
        box.innerHTML = '<span class="ms" aria-hidden="true">check_circle</span><div class="grow"><b>Ça marche.</b><span>' + esc(res.summary || "") + " · " + esc(res.latency_ms) + " ms" + metricsLine(res.metrics) + "</span></div>";
        await saveWizardProbe(probe);
      } else {
        box.className = "test-result err";
        box.innerHTML = '<span class="ms" aria-hidden="true">error</span><div class="grow"><b>La connexion a échoué.</b><span>' + esc(humanize(res.summary) || "Pas de réponse.") + '</span><span class="mono small">' + esc(res.summary || "") + "</span><span>Vérifiez l'adresse et les identifiants, puis réessayez.</span></div>";
        $("wizard-submit-text").textContent = "Tester à nouveau";
        $("wizard-save-anyway").hidden = false;
      }
    } catch (e) {
      box.className = "test-result err";
      box.innerHTML = '<span class="ms" aria-hidden="true">error</span><div class="grow"><b>Test impossible.</b><span>' + esc(e.message) + "</span></div>";
      $("wizard-submit-text").textContent = "Tester à nouveau";
      $("wizard-save-anyway").hidden = false;
    } finally {
      setBusy(btn, false);
    }
  }

  function metricsLine(m) {
    if (!m) return "";
    const x = [];
    if (typeof m.cpu_percent === "number") x.push("processeur " + fmtPct(m.cpu_percent));
    if (typeof m.ram_percent === "number") x.push("mémoire " + fmtPct(m.ram_percent));
    if (typeof m.disk_max_pct === "number") x.push("disque " + fmtPct(m.disk_max_pct));
    if (m.guests?.length) x.push(plural(m.guests.length, "VM", "VM"));
    if (m.containers?.length) x.push(plural(m.containers.length, "conteneur", "conteneurs"));
    return x.length ? " · " + x.join(" · ") : "";
  }

  async function saveWizardProbe(probe) {
    state.draft = ensureDraftShape(state.draft || state.config);
    const editing = state.wizard.editIndex >= 0;
    if (editing) state.draft.probes[state.wizard.editIndex] = probe;
    else state.draft.probes.push(probe);
    const saved = await saveConfiguration(false);
    if (saved) {
      closeWizard();
      toast(editing ? probe.id + " mis à jour." : probe.id + " est maintenant surveillé.");
      openDevice(probe.id);
    } else if (!editing) {
      state.draft.probes.pop();
    }
  }

  /* -------------------- Amis -------------------- */

  function encodeInvite(cfg) {
    const node = cfg?.node;
    if (!node || !node.private_key_hex || !node.group_psk_hex) return "";
    const pub = state.status?.pubkey_hex || node.pubkey_hex || "";
    if (!pub) return "";
    const json = JSON.stringify({ name: node.name || "MeshWatch", pubkey: pub, psk: node.group_psk_hex });
    const bytes = new TextEncoder().encode(json);
    let bin = "";
    bytes.forEach((b) => { bin += String.fromCharCode(b); });
    return "MW1-" + btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decodeInvite(raw) {
    const clean = String(raw || "").trim().replace(/\s+/g, "");
    if (!clean) return null;
    if (/^[0-9a-fA-F]{64}$/.test(clean)) return { name: "", pubkey_hex: clean.toLowerCase(), group_psk_hex: "" };
    if (!clean.startsWith("MW1-")) return null;
    try {
      let b64 = clean.slice(4).replace(/-/g, "+").replace(/_/g, "/");
      while (b64.length % 4) b64 += "=";
      const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
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

  function renderFriends(st) {
    const code = encodeInvite(state.config);
    $("invite-code").textContent = code || "Le code apparaîtra une fois cette maison nommée.";
    $("invite-copy").disabled = !code;
    $("invite-share").hidden = !(code && navigator.share);

    const peers = st.peers || [];
    $("friends-count").textContent = String(peers.length);
    const box = $("friends-list");
    if (!peers.length) {
      box.innerHTML = '<div class="empty">Aucun ami pour l\'instant. Envoyez votre code à quelqu\'un de confiance, ou collez le sien ci-dessus.</div>';
      return;
    }
    box.innerHTML = peers.map((p) => {
      const ps = peerState(p);
      const probes = p.probes || [];
      const bad = probes.filter((x) => !x.ok);
      let line;
      if (ps.tone === "down") line = "Plus de signal depuis " + fmtAgo(p.last_seen).replace("il y a ", "");
      else if (ps.tone === "warn") line = bad.map((x) => x.id + (x.summary ? " : " + humanize(x.summary) : "")).slice(0, 2).join(" · ");
      else if (ps.tone === "off") line = "En attente de son premier signal";
      else line = plural(probes.length, "appareil", "appareils") + (bad.length ? "" : ", tous en ligne") + " · signal reçu " + fmtAgo(p.last_seen);
      return (
        '<div class="friend-row">' +
          '<span class="avatar" aria-hidden="true">' + esc(initials(p.name)) + "</span>" +
          '<span class="row-main"><span class="row-title"><b>' + esc(p.name) + "</b></span><span class=\"row-sub\"><span>" + esc(line) + "</span></span></span>" +
          (MW().uptimeStripHTML ? '<span class="col-bars">' + MW().uptimeStripHTML(p.history || [], true, 20) + "</span>" : "") +
          '<span class="pill ' + ps.tone + '"><span class="dot"></span>' + esc(ps.label) + "</span>" +
          '<button class="btn sm" type="button" data-open-peer="' + esc(p.pubkey_hex) + '">Détails</button>' +
        "</div>"
      );
    }).join("");
  }

  function updateAcceptPreview() {
    const raw = $("accept-input").value;
    const dec = decodeInvite(raw);
    const pv = $("accept-preview");
    const btn = $("accept-btn");
    if (!raw.trim()) { pv.hidden = true; btn.disabled = true; $("accept-btn-text").textContent = "Ajouter cet ami"; return; }
    pv.hidden = false;
    if (!dec) {
      pv.className = "notice err";
      pv.innerHTML = '<span class="ms" aria-hidden="true">error</span><span>Ce code n\'est pas reconnu. Il doit commencer par MW1-.</span>';
      btn.disabled = true;
      return;
    }
    const mine = (state.status?.pubkey_hex || "").toLowerCase() === dec.pubkey_hex;
    const already = (state.draft?.peers || []).find((p) => (p.pubkey_hex || "").toLowerCase() === dec.pubkey_hex);
    if (mine) {
      pv.className = "notice warn";
      pv.innerHTML = '<span class="ms" aria-hidden="true">info</span><span>C\'est votre propre code. Envoyez-le à votre ami, et collez ici le sien.</span>';
      btn.disabled = true;
      return;
    }
    if (already) {
      pv.className = "notice warn";
      pv.innerHTML = '<span class="ms" aria-hidden="true">info</span><span>' + esc(already.name) + " fait déjà partie de vos amis.</span>";
      btn.disabled = true;
      return;
    }
    const name = dec.name || "cet ami";
    pv.className = "notice ok";
    pv.innerHTML = '<span class="ms" aria-hidden="true">check_circle</span><span><b>Code valide :</b> c\'est « ' + esc(name) + " ».</span>";
    btn.disabled = false;
    $("accept-btn-text").textContent = "Ajouter " + (dec.name || "cet ami");
  }

  async function acceptInvite() {
    const dec = decodeInvite($("accept-input").value);
    if (!dec) return;
    state.draft = ensureDraftShape(state.draft || state.config);
    if (!state.draft.peers.some((p) => (p.pubkey_hex || "").toLowerCase() === dec.pubkey_hex)) {
      state.draft.peers.push({ name: dec.name || "Ami " + (state.draft.peers.length + 1), pubkey_hex: dec.pubkey_hex });
    }
    if (dec.group_psk_hex && (!state.draft.node.group_psk_hex || state.draft.peers.length <= 1)) {
      state.draft.node.group_psk_hex = dec.group_psk_hex;
    }
    const btn = $("accept-btn");
    setBusy(btn, true);
    const saved = await saveConfiguration(false);
    setBusy(btn, false);
    if (saved) {
      $("accept-input").value = "";
      updateAcceptPreview();
      toast((dec.name || "Votre ami") + " a été ajouté. Pensez à lui envoyer votre code en retour.");
    }
  }

  function openPeer(pk) {
    const p = (state.status?.peers || []).find((x) => x.pubkey_hex === pk);
    if (!p) return;
    state.peerOpen = pk;
    state.lastFocus = document.activeElement;
    const ps = peerState(p);
    $("peer-title").textContent = p.name || "Ami";
    $("peer-sub").textContent = ps.label + " · signal reçu " + fmtAgo(p.last_seen);
    const probes = p.probes || [];
    $("peer-body").innerHTML =
      '<div class="stack"><span class="caps">Présence récente</span><div class="uptime-big">' + (MW().uptimeStripHTML ? MW().uptimeStripHTML(p.history || [], true, 40) : "") + "</div></div>" +
      '<section class="card list-card res-section"><h3>Ses appareils · ' + probes.length + "</h3>" +
        (probes.length
          ? probes.map((x) => '<div class="res-row"><span class="sdot ' + (x.ok ? "ok" : "down") + '"></span><div class="grow"><b>' + esc(x.id) + "</b><small>" + esc(humanize(x.summary)) + '</small></div><span class="mono muted">' + esc(x.latency_ms || 0) + " ms</span></div>").join("")
          : '<div class="empty">Rien de transmis pour l\'instant.</div>') +
      "</section>" +
      '<details class="fold"><summary>Détails techniques</summary><dl class="kv">' +
        "<dt>Nom de sa maison</dt><dd>" + esc(p.node_name || "—") + "</dd>" +
        "<dt>Allumé depuis</dt><dd>" + esc(fmtDuration(p.uptime_sec)) + "</dd>" +
        '<dt>Clé publique</dt><dd class="mono">' + esc(p.pubkey_hex) + "</dd>" +
      "</dl></details>";
    $("peer-modal").hidden = false;
    setTimeout(() => $("peer-modal").querySelector("[data-close]")?.focus(), 30);
  }

  async function removePeer() {
    const pk = state.peerOpen;
    const p = (state.status?.peers || []).find((x) => x.pubkey_hex === pk);
    const ok = await confirmDialog("Retirer " + (p?.name || "cet ami") + " ?", "Vous ne veillerez plus l'un sur l'autre. Vous pourrez le rajouter plus tard avec son code.", "Retirer");
    if (!ok) return;
    state.draft.peers = (state.draft.peers || []).filter((x) => x.pubkey_hex !== pk);
    closeModal("peer-modal");
    if (await saveConfiguration(false)) toast((p?.name || "L'ami") + " a été retiré.");
  }

  /* -------------------- Formulaires (Alertes & Réglages) -------------------- */

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

  function photonMode() {
    return document.querySelector('input[name="photon-mode"]:checked')?.value || "cloud";
  }

  function syncPhotonMode() {
    const mode = photonMode();
    $$("[data-photon]").forEach((el) => { el.hidden = el.dataset.photon !== mode; });
  }

  function setVal(id, v) {
    const el = $(id);
    if (el) el.value = v == null ? "" : v;
  }

  function renderConfigForms() {
    const cfg = ensureDraftShape(state.draft);
    state.draft = cfg;

    const ntfy = cfg.notifications.ntfy || {};
    $("ntfy-enabled").checked = Boolean(ntfy.enabled);
    setVal("ntfy-url", ntfy.url);
    setVal("ntfy-topic", ntfy.topic);
    setVal("ntfy-token", ntfy.token);

    const ph = cfg.notifications.photon_imessage || {};
    const mode = inferPhotonMode(ph);
    $("photon-enabled").checked = Boolean(ph.enabled);
    $$('input[name="photon-mode"]').forEach((r) => { r.checked = r.value === mode; });
    syncPhotonMode();
    setVal("photon-project-id", ph.project_id);
    setVal("photon-api-key", ph.api_key || (mode === "cloud" ? ph.token : ""));
    setVal("photon-recipient", ph.recipient);
    setVal("photon-cloud-url", mode === "cloud" ? ph.url : "");
    setVal("photon-sender-id", ph.sender_id);
    setVal("photon-space-id", ph.space_id);
    setVal("photon-server-url", ph.server_url);
    setVal("photon-proxy-key", mode === "proxy" ? ph.api_key : "");
    setVal("photon-proxy-recipient", ph.recipient);
    setVal("photon-proxy-url", mode === "proxy" ? ph.url || "https://imessage-swagger.photon.codes" : "https://imessage-swagger.photon.codes");
    setVal("photon-proxy-token", mode === "proxy" ? ph.token : "");
    setVal("photon-custom-url", mode === "custom" ? ph.url : "");
    setVal("photon-custom-recipient", ph.recipient);
    setVal("photon-custom-token", mode === "custom" ? ph.token : "");
    setVal("photon-rec-field", ph.recipient_field || "recipient");
    setVal("photon-msg-field", ph.message_field || "message");

    const sel = $("peer-timeout-select");
    const pt = cfg.node.peer_timeout || "1m30s";
    if (!Array.from(sel.options).some((o) => o.value === pt)) {
      const o = document.createElement("option");
      o.value = pt;
      o.textContent = fmtGoDuration(pt);
      sel.appendChild(o);
    }
    sel.value = pt;
    $("automute-enabled").checked = (cfg.auto_mute.targets || []).length > 0;

    setVal("set-node-name", cfg.node.name);
    setVal("set-pubkey", state.status?.pubkey_hex || cfg.node.pubkey_hex);
    setVal("set-privkey", cfg.node.private_key_hex);
    setVal("set-group-psk", cfg.node.group_psk_hex);
    setVal("set-hb-interval", cfg.node.heartbeat_interval || "30s");
    setVal("set-relays", (cfg.nostr.relays || []).join("\n"));
    setVal("set-automute-targets", (cfg.auto_mute.targets || []).join("\n"));
    setVal("set-automute-timeout", cfg.auto_mute.timeout || "3s");
    setVal("raw-yaml", state.rawYAML);
  }

  function readPhoton() {
    const mode = photonMode();
    const enabled = $("photon-enabled").checked;
    if (mode === "cloud") {
      return { enabled, mode: "cloud", url: val("photon-cloud-url"), project_id: val("photon-project-id"), api_key: val("photon-api-key"), recipient: val("photon-recipient"), sender_id: val("photon-sender-id"), space_id: val("photon-space-id") };
    }
    if (mode === "proxy") {
      return { enabled, mode: "proxy", url: val("photon-proxy-url") || "https://imessage-swagger.photon.codes", server_url: val("photon-server-url"), api_key: val("photon-proxy-key"), token: val("photon-proxy-token"), recipient: val("photon-proxy-recipient") };
    }
    return { enabled, mode: "custom", url: val("photon-custom-url"), recipient: val("photon-custom-recipient"), token: val("photon-custom-token"), recipient_field: val("photon-rec-field") || "recipient", message_field: val("photon-msg-field") || "message" };
  }

  function pullFormsIntoDraft() {
    state.draft = ensureDraftShape(state.draft);
    const d = state.draft;
    d.node.name = val("set-node-name") || d.node.name || "maison";
    if (val("set-privkey")) d.node.private_key_hex = val("set-privkey");
    if (val("set-group-psk")) d.node.group_psk_hex = val("set-group-psk");
    d.node.heartbeat_interval = val("set-hb-interval") || "30s";
    d.node.peer_timeout = $("peer-timeout-select").value || "1m30s";
    d.nostr.relays = splitLines($("set-relays").value);
    let targets = splitLines($("set-automute-targets").value);
    if (!$("automute-enabled").checked) targets = [];
    else if (!targets.length) targets = ["1.1.1.1:443", "9.9.9.9:443"];
    d.auto_mute.targets = targets;
    d.auto_mute.timeout = val("set-automute-timeout") || "3s";
    d.notifications = {
      ntfy: { enabled: $("ntfy-enabled").checked, url: val("ntfy-url"), topic: val("ntfy-topic"), token: val("ntfy-token") },
      photon_imessage: readPhoton()
    };
  }

  async function runTestNotify() {
    pullFormsIntoDraft();
    const box = $("alerts-test-results");
    const btn = $("alerts-test-btn");
    const n = state.draft.notifications;
    if (!n.ntfy.enabled && !n.photon_imessage.enabled) {
      box.hidden = false;
      box.innerHTML = '<div class="notice warn"><span class="ms" aria-hidden="true">info</span><span>Activez d\'abord ntfy ou iMessage ci-dessous.</span></div>';
      return;
    }
    box.hidden = false;
    box.innerHTML = '<div class="test-line"><span class="spinner" aria-hidden="true"></span>Envoi en cours…</div>';
    setBusy(btn, true);
    try {
      const res = await apiFetch("/api/test-notify", { method: "POST", body: JSON.stringify({ node_name: state.draft.node?.name || "MeshWatch", notifications: n }) });
      const lines = res.results || [];
      box.innerHTML = lines.map((l) => (
        '<div class="test-line"><span class="pill ' + (l.ok ? "ok" : "down") + '">' + (l.ok ? "Envoyé" : "Échec") + "</span><b>" + esc(l.channel) + '</b><span class="muted">' + esc(l.error || (l.ok ? "Regardez votre téléphone (" + (l.latency_ms || 0) + " ms)." : "")) + "</span></div>"
      )).join("") || '<div class="test-line">Aucun canal actif.</div>';
    } catch (e) {
      box.innerHTML = '<div class="notice err"><span class="ms" aria-hidden="true">error</span><span>' + esc(e.message) + "</span></div>";
    } finally {
      setBusy(btn, false);
    }
  }

  /* -------------------- Réglages, mises à jour, sauvegarde -------------------- */

  function renderSettingsLive(st) {
    const relays = st.relays || [];
    $("set-node-meta").textContent = "Allumé depuis " + fmtDuration(st.uptime_sec || 0) + " · " + relays.filter((r) => r.connected).length + " relais sur " + relays.length + " joignables";
    $("set-config-path").textContent = st.config_path || "config.yaml";
    if (!$("set-pubkey").value && st.pubkey_hex) $("set-pubkey").value = st.pubkey_hex;
  }

  async function checkUpdates(force) {
    try {
      state.updateInfo = await apiFetch("/api/update/check" + (force ? "?force=1" : ""), { method: "GET" });
      renderUpdate(state.updateInfo);
      if (force) toast(state.updateInfo.update_available ? "Une nouvelle version est disponible." : "MeshWatch est à jour.");
    } catch (e) {
      if (force) toast("Vérification impossible : " + e.message, "err");
    }
  }

  function renderUpdate(info) {
    if (!info) return;
    const avail = Boolean(info.update_available);
    const latest = info.latest_version || (info.latest_commit || "").slice(0, 7) || "nouvelle version";
    $("nav-update-dot").hidden = !avail;
    $("update-strip").hidden = !avail;
    $("update-strip-version").textContent = latest;
    const notes = $("update-strip-notes");
    notes.hidden = !info.release_url;
    if (info.release_url) notes.href = info.release_url;
    $("set-update-title-text").textContent = avail ? "Version " + latest + " disponible" : "MeshWatch est à jour";
    $("set-update-meta").textContent = "Version installée : " + (info.current_version || "dev") + (info.current_commit ? " (" + info.current_commit.slice(0, 7) + ")" : "");
    $("set-update-apply").hidden = !avail;
  }

  async function triggerUpdate() {
    const ok = await confirmDialog("Mettre à jour MeshWatch ?", "Le conteneur va redémarrer avec la nouvelle version. La surveillance s'interrompt une minute environ. En cas d'échec, l'ancienne version est remise en place.", "Mettre à jour");
    if (!ok) return;
    $("updating").hidden = false;
    try {
      await apiFetch("/api/update/apply", { method: "POST", body: JSON.stringify({ image: state.updateInfo?.image || state.updateInfo?.docker_image || "" }) });
      $("updating-bar").style.width = "65%";
      $("updating-sub").textContent = "Redémarrage du conteneur…";
      let tries = 0;
      const before = state.status?.version;
      clearInterval(state.updatePollTimer);
      state.updatePollTimer = setInterval(async () => {
        tries++;
        try {
          const st = await apiFetch("/api/status", { method: "GET" });
          if ((st && st.version && st.version !== before) || tries > 20) {
            clearInterval(state.updatePollTimer);
            location.reload();
          }
        } catch {
          if (tries > 25) { clearInterval(state.updatePollTimer); location.reload(); }
        }
      }, 2000);
    } catch (e) {
      $("updating").hidden = true;
      toast("Mise à jour impossible : " + e.message, "err");
    }
  }

  async function runWelcome(e) {
    e.preventDefault();
    const name = val("welcome-name");
    const err = $("welcome-error");
    if (!name) { $("welcome-name").focus(); return; }
    const btn = $("welcome-submit");
    setBusy(btn, true);
    err.hidden = true;
    try {
      const keys = await apiFetch("/api/keygen", { method: "POST", body: "{}" });
      state.draft = ensureDraftShape(state.draft || state.config);
      state.draft.node.name = name;
      state.draft.node.private_key_hex = keys.private_key_hex;
      state.draft.node.group_psk_hex = keys.group_psk_hex;
      setVal("set-node-name", name);
      setVal("set-privkey", keys.private_key_hex);
      setVal("set-group-psk", keys.group_psk_hex);
      if (!state.draft.notifications.ntfy.topic) {
        state.draft.notifications.ntfy.topic = randomTopic();
        setVal("ntfy-topic", state.draft.notifications.ntfy.topic);
      }
      const saved = await saveConfiguration(false);
      if (saved) {
        $("welcome").hidden = true;
        toast("« " + name + " » est prête. Choisissons maintenant quoi surveiller.");
        switchTab("home");
        openWizard();
      }
    } catch (ex) {
      err.textContent = "Impossible de créer les clés : " + ex.message;
      err.hidden = false;
    } finally {
      setBusy(btn, false);
    }
  }

  function exportBackup() {
    const blob = new Blob([state.rawYAML || ""], { type: "text/yaml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "meshwatch-" + (state.draft?.node?.name || "config") + ".yaml";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function applyYAML(text, okMsg) {
    try {
      const res = await apiFetch("/api/config", { method: "PUT", body: JSON.stringify({ yaml: text }) });
      state.config = ensureDraftShape(res.config);
      state.draft = clone(state.config);
      state.rawYAML = res.yaml || text;
      setDirty(false);
      renderConfigForms();
      await fetchStatus();
      toast(okMsg);
    } catch (e) {
      toast("Fichier refusé : " + e.message, "err");
    }
  }

  async function importBackup(file) {
    if (!file) return;
    const ok = await confirmDialog("Restaurer ce fichier ?", "Toute la configuration actuelle (appareils, amis, alertes, clés) sera remplacée par celle de « " + file.name + " ».", "Restaurer");
    $("backup-import").value = "";
    if (!ok) return;
    await applyYAML(await file.text(), "Configuration restaurée.");
  }

  /* -------------------- Modales -------------------- */

  function closeModal(id) {
    const el = $(id);
    if (!el || el.hidden) return;
    if (id === "wizard") return closeWizard();
    el.hidden = true;
    if (id === "palette") return;
    if (id === "confirm-modal" && state.confirmResolve) {
      state.confirmResolve(false);
      state.confirmResolve = null;
    }
    state.lastFocus?.focus?.();
  }

  function confirmDialog(title, text, okLabel) {
    return new Promise((resolve) => {
      state.confirmResolve = resolve;
      $("confirm-title").textContent = title;
      $("confirm-text").textContent = text;
      $("confirm-ok").textContent = okLabel || "Confirmer";
      $("confirm-modal").hidden = false;
      setTimeout(() => $("confirm-cancel").focus(), 30);
    });
  }

  function topOverlay() {
    return ["confirm-modal", "palette", "shortcuts", "friend-modal", "peer-modal", "wizard", "auth-gate"].find((id) => $(id) && !$(id).hidden);
  }

  /* -------------------- Palette Ctrl K -------------------- */

  function openPalette() {
    state.lastFocus = document.activeElement;
    $("palette").hidden = false;
    $("palette-input").value = "";
    renderPalette("");
    setTimeout(() => $("palette-input").focus(), 20);
  }

  function paletteItems() {
    const items = [
      { group: "Aller à", icon: "home", label: "Accueil", run: () => switchTab("home") },
      { group: "Aller à", icon: "dns", label: "Appareils", run: () => switchTab("devices") },
      { group: "Aller à", icon: "group", label: "Amis", run: () => switchTab("friends") },
      { group: "Aller à", icon: "notifications", label: "Alertes", run: () => switchTab("alerts") },
      { group: "Aller à", icon: "settings", label: "Réglages", run: () => switchTab("settings") },
      { group: "Actions", icon: "add", label: "Ajouter un appareil", run: () => openWizard() },
      { group: "Actions", icon: "refresh", label: "Tout vérifier maintenant", run: () => runAllNow() },
      { group: "Actions", icon: "wifi_find", label: "Chercher sur le réseau", run: () => { openWizard(); runLANScan(); } },
      { group: "Actions", icon: "send", label: "M'envoyer une alerte de test", run: () => { switchTab("alerts"); runTestNotify(); } },
      { group: "Actions", icon: "content_copy", label: "Copier mon code d'invitation", run: () => { const c = encodeInvite(state.config); if (c) copyText(c, "Code copié."); } },
      { group: "Actions", icon: state.theme === "dark" ? "light_mode" : "dark_mode", label: state.theme === "dark" ? "Thème clair" : "Thème sombre", run: () => applyTheme(state.theme === "dark" ? "light" : "dark") }
    ];
    deviceList().forEach((d) => items.push({ group: "Appareils", icon: kindIcon(d.kind), label: d.id, sub: d.ok === false ? "Ne répond plus" : kindLabel(d.kind), run: () => openDevice(d.id) }));
    (state.status?.peers || []).forEach((p) => items.push({ group: "Amis", icon: "person", label: p.name, sub: peerState(p).label, run: () => { switchTab("friends"); openPeer(p.pubkey_hex); } }));
    return items;
  }

  function renderPalette(q) {
    const query = String(q || "").toLowerCase().trim();
    const all = paletteItems();
    state.paletteItems = (query ? all.filter((it) => (it.label + " " + (it.sub || "") + " " + it.group).toLowerCase().includes(query)) : all).slice(0, 16);
    state.paletteIndex = 0;
    const list = $("palette-list");
    if (!state.paletteItems.length) {
      list.innerHTML = '<div class="empty">Aucun résultat.</div>';
      return;
    }
    let html = "";
    let group = "";
    state.paletteItems.forEach((it, i) => {
      if (it.group !== group) { group = it.group; html += '<div class="palette-group">' + esc(group) + "</div>"; }
      html += '<button type="button" role="option" class="palette-item' + (i === 0 ? " active" : "") + '" data-pal="' + i + '" aria-selected="' + (i === 0) + '"><span class="ms" aria-hidden="true">' + it.icon + '</span><span class="grow"><b>' + esc(it.label) + "</b>" + (it.sub ? "<small>" + esc(it.sub) + "</small>" : "") + "</span></button>";
    });
    list.innerHTML = html;
  }

  function movePalette(delta) {
    const n = state.paletteItems.length;
    if (!n) return;
    state.paletteIndex = (state.paletteIndex + delta + n) % n;
    $$("#palette-list .palette-item").forEach((el, i) => {
      el.classList.toggle("active", i === state.paletteIndex);
      el.setAttribute("aria-selected", String(i === state.paletteIndex));
      if (i === state.paletteIndex) el.scrollIntoView({ block: "nearest" });
    });
  }

  function runPalette(i) {
    const it = state.paletteItems[i];
    $("palette").hidden = true;
    if (it) it.run();
  }

  /* -------------------- Événements -------------------- */

  function bindEvents() {
    /* Délégation : navigation, ouverture d'appareils et d'amis, ajout */
    document.addEventListener("click", (e) => {
      const t = e.target.closest("[data-tab],[data-goto],[data-action],[data-open-device],[data-open-peer],[data-select-device],[data-edit-device],[data-close],[data-reveal],[data-pick-kind],[data-watch-container],[data-lan-add],[data-pal]");
      if (!t) {
        if (!e.target.closest(".menu-wrap")) { $("dd-menu").hidden = true; $("dd-more").setAttribute("aria-expanded", "false"); }
        return;
      }
      if (t.dataset.tab) return switchTab(t.dataset.tab);
      if (t.dataset.goto) { closeModal("palette"); return switchTab(t.dataset.goto); }
      if (t.dataset.action === "add") return openWizard();
      if (t.dataset.openDevice) return openDevice(t.dataset.openDevice);
      if (t.dataset.openPeer) return openPeer(t.dataset.openPeer);
      if (t.dataset.selectDevice) {
        state.selectedID = t.dataset.selectDevice;
        try { localStorage.setItem(STORAGE.device, state.selectedID); } catch {}
        history.replaceState(null, "", "#/devices/" + encodeURIComponent(state.selectedID));
        return renderDevices();
      }
      if (t.dataset.editDevice) {
        const idx = (state.draft?.probes || []).findIndex((p) => p.id === t.dataset.editDevice);
        if (idx >= 0) openWizard(idx);
        return;
      }
      if (t.dataset.close) return closeModal(t.dataset.close);
      if (t.dataset.reveal) {
        const input = $(t.dataset.reveal);
        if (!input) return;
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        t.textContent = show ? "Masquer" : "Afficher";
        return;
      }
      if (t.dataset.pickKind) return showWizardForm(t.dataset.pickKind, {});
      if (t.dataset.watchContainer) { setBusy(t, true); return watchContainers([t.dataset.watchContainer]); }
      if (t.dataset.lanAdd) {
        const it = (state.lanItems || []).find((x) => x.key === t.dataset.lanAdd);
        if (it?.suggested_probe) showWizardForm(it.suggested_probe.kind, clone(it.suggested_probe));
        return;
      }
      if (t.dataset.pal != null) return runPalette(Number(t.dataset.pal));
    });

    $$(".modal-backdrop").forEach((bd) => bd.addEventListener("mousedown", (e) => {
      if (e.target === bd && bd.id !== "auth-gate" && bd.id !== "updating") closeModal(bd.id);
    }));

    $("theme-btn").addEventListener("click", () => applyTheme(state.theme === "dark" ? "light" : "dark"));
    $("palette-btn").addEventListener("click", openPalette);
    $("auth-form").addEventListener("submit", submitAuth);
    $("welcome-form").addEventListener("submit", runWelcome);
    window.addEventListener("hashchange", routeFromHash);

    /* Accueil */
    $("hero-run-btn").addEventListener("click", (e) => runAllNow(e.currentTarget));
    $$("#home-filter button").forEach((b) => b.addEventListener("click", () => {
      state.homeFilter = b.dataset.filter;
      if (state.status) renderHome(state.status);
    }));
    $("update-strip-apply").addEventListener("click", triggerUpdate);

    /* Appareils */
    $("device-search").addEventListener("input", (e) => { state.deviceSearch = e.target.value; renderDevices(); });
    $$(".tab[data-dtab]").forEach((t) => t.addEventListener("click", () => {
      state.deviceTab = t.dataset.dtab;
      try { localStorage.setItem(STORAGE.dtab, state.deviceTab); } catch {}
      renderDevices();
    }));
    $("dd-test").addEventListener("click", (e) => testDevice(state.selectedID, e.currentTarget));
    $("dd-edit").addEventListener("click", () => {
      const idx = (state.draft?.probes || []).findIndex((p) => p.id === state.selectedID);
      if (idx >= 0) openWizard(idx);
    });
    $("dd-more").addEventListener("click", () => {
      const menu = $("dd-menu");
      menu.hidden = !menu.hidden;
      $("dd-more").setAttribute("aria-expanded", String(!menu.hidden));
      if (!menu.hidden) menu.querySelector("button")?.focus();
    });
    $("dd-delete").addEventListener("click", () => { $("dd-menu").hidden = true; deleteDevice(state.selectedID); });

    /* Assistant */
    $("wizard-back").addEventListener("click", showWizardPick);
    $("wizard-submit").addEventListener("click", wizardSubmit);
    $("wizard-step-form").addEventListener("submit", (e) => { e.preventDefault(); wizardSubmit(); });
    $("wizard-save-anyway").addEventListener("click", () => saveWizardProbe(readWizardProbe()));
    $("found-lan-scan").addEventListener("click", runLANScan);
    $("found-docker-all").addEventListener("click", (e) => {
      setBusy(e.currentTarget, true);
      watchContainers(state.dockerContainers.filter((c) => !c.monitored).map((c) => c.name)).finally(() => setBusy(e.currentTarget, false));
    });

    /* Amis */
    $("invite-copy").addEventListener("click", () => { const c = encodeInvite(state.config); if (c) copyText(c, "Code copié. Envoyez-le à votre ami."); });
    $("invite-share").addEventListener("click", () => {
      const c = encodeInvite(state.config);
      if (c && navigator.share) navigator.share({ title: "Mon code MeshWatch", text: "Ajoute-moi dans MeshWatch avec ce code : " + c }).catch(() => {});
    });
    $("accept-input").addEventListener("input", updateAcceptPreview);
    $("accept-btn").addEventListener("click", acceptInvite);
    $("manual-friend-btn").addEventListener("click", () => {
      state.lastFocus = document.activeElement;
      $("friend-modal").hidden = false;
      setTimeout(() => $("fm-name").focus(), 30);
    });
    $("friend-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = val("fm-name") || "Ami";
      const pk = val("fm-pubkey");
      if (!/^[0-9a-fA-F]{64}$/.test(pk)) {
        $("fm-pubkey").classList.add("invalid");
        toast("La clé doit faire 64 caractères (0-9, a-f).", "err");
        return;
      }
      state.draft = ensureDraftShape(state.draft || state.config);
      state.draft.peers.push({ name, pubkey_hex: pk.toLowerCase() });
      closeModal("friend-modal");
      if (await saveConfiguration(false)) toast(name + " a été ajouté.");
    });
    $("peer-remove").addEventListener("click", removePeer);

    /* Alertes */
    $("alerts-test-btn").addEventListener("click", runTestNotify);
    $$('input[name="photon-mode"]').forEach((r) => r.addEventListener("change", syncPhotonMode));
    $("ntfy-gen").addEventListener("click", () => { setVal("ntfy-topic", randomTopic()); setDirty(true); });
    $("ntfy-copy").addEventListener("click", () => { if (val("ntfy-topic")) copyText(val("ntfy-topic"), "Nom du canal copié."); });
    $("ntfy-enabled").addEventListener("change", () => {
      if ($("ntfy-enabled").checked && !val("ntfy-topic")) setVal("ntfy-topic", randomTopic());
    });
    $("automute-enabled").addEventListener("change", () => {
      if ($("automute-enabled").checked && !splitLines($("set-automute-targets").value).length) setVal("set-automute-targets", "1.1.1.1:443\n9.9.9.9:443");
    });

    /* Réglages */
    $("set-update-check").addEventListener("click", () => checkUpdates(true));
    $("set-update-apply").addEventListener("click", triggerUpdate);
    $("backup-export").addEventListener("click", exportBackup);
    $("backup-import-btn").addEventListener("click", () => $("backup-import").click());
    $("backup-import").addEventListener("change", (e) => importBackup(e.target.files?.[0]));
    $("copy-pubkey").addEventListener("click", () => { if (val("set-pubkey")) copyText(val("set-pubkey"), "Clé publique copiée."); });
    $("regen-keys").addEventListener("click", async () => {
      const ok = await confirmDialog("Régénérer les clés ?", "Vos amis ne vous reconnaîtront plus tant que vous ne leur aurez pas renvoyé votre nouveau code d'invitation.", "Régénérer");
      if (!ok) return;
      const keys = await apiFetch("/api/keygen", { method: "POST", body: "{}" });
      setVal("set-privkey", keys.private_key_hex);
      setVal("set-group-psk", keys.group_psk_hex);
      setDirty(true);
      toast("Nouvelles clés prêtes. Cliquez sur Enregistrer.", "warn");
    });
    $("automute-test").addEventListener("click", async (e) => {
      setBusy(e.currentTarget, true);
      try {
        const res = await apiFetch("/api/check-automute", { method: "POST", body: "{}" });
        $("automute-result").textContent = res.muted ? "Internet ne répond pas" : "Internet répond";
      } catch (err) {
        $("automute-result").textContent = "Test impossible : " + err.message;
      } finally {
        setBusy(e.currentTarget, false);
      }
    });
    $("raw-yaml-apply").addEventListener("click", async () => {
      const ok = await confirmDialog("Appliquer ce fichier ?", "La configuration sera remplacée par le contenu de l'éditeur.", "Appliquer");
      if (ok) applyYAML($("raw-yaml").value, "Fichier appliqué.");
    });

    /* Modifications non enregistrées */
    $$("[data-dirty]").forEach((el) => {
      el.addEventListener("input", () => setDirty(true));
      el.addEventListener("change", () => setDirty(true));
    });
    $("savebar-save").addEventListener("click", (e) => { setBusy(e.currentTarget, true); saveConfiguration(true).finally(() => setBusy(e.currentTarget, false)); });
    $("savebar-discard").addEventListener("click", () => {
      state.draft = clone(state.config || {});
      renderConfigForms();
      setDirty(false);
    });
    window.addEventListener("beforeunload", (e) => {
      if (state.dirty) { e.preventDefault(); e.returnValue = ""; }
    });

    /* Confirmation */
    $("confirm-ok").addEventListener("click", () => {
      $("confirm-modal").hidden = true;
      if (state.confirmResolve) { state.confirmResolve(true); state.confirmResolve = null; }
    });
    $("confirm-cancel").addEventListener("click", () => closeModal("confirm-modal"));

    /* Palette */
    $("palette-input").addEventListener("input", (e) => renderPalette(e.target.value));
    $("palette-input").addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") { e.preventDefault(); movePalette(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); movePalette(-1); }
      else if (e.key === "Enter") { e.preventDefault(); runPalette(state.paletteIndex); }
    });

    /* Clavier */
    document.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if ($("palette").hidden) openPalette();
        else closeModal("palette");
        return;
      }
      if (e.key === "Escape") {
        if (!$("dd-menu").hidden) { $("dd-menu").hidden = true; $("dd-more").focus(); return; }
        const top = topOverlay();
        if (top && top !== "auth-gate") { e.preventDefault(); closeModal(top); }
        return;
      }
      const tag = (e.target?.tagName || "").toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select" || e.target?.isContentEditable || e.metaKey || e.ctrlKey || e.altKey) return;
      if (topOverlay() || !$("welcome").hidden) return;

      const k = e.key.toLowerCase();
      if (state.keySeq === "g") {
        state.keySeq = "";
        clearTimeout(state.keySeqTimer);
        const idx = Number(k) - 1;
        if (idx >= 0 && idx < TABS.length) switchTab(TABS[idx]);
        return;
      }
      if (k === "g") {
        state.keySeq = "g";
        clearTimeout(state.keySeqTimer);
        state.keySeqTimer = setTimeout(() => { state.keySeq = ""; }, 900);
      } else if (e.key === "?") {
        state.lastFocus = document.activeElement;
        $("shortcuts").hidden = false;
      } else if (k === "n") {
        e.preventDefault();
        openWizard();
      } else if (k === "r") {
        runAllNow();
      } else if ((k === "j" || k === "k") && (state.tab === "devices" || state.tab === "home")) {
        const list = sortDevices(deviceList());
        if (!list.length) return;
        const cur = list.findIndex((d) => d.id === state.selectedID);
        const next = k === "j" ? Math.min(list.length - 1, cur + 1) : Math.max(0, cur - 1);
        openDevice(list[next < 0 ? 0 : next].id);
      } else if (k === "t" && state.tab === "devices" && state.selectedID) {
        testDevice(state.selectedID, $("dd-test"));
      } else if (k === "e" && state.tab === "devices" && state.selectedID) {
        $("dd-edit").click();
      }
    });
  }

  window.runDockerScan = runDockerScan;

  document.addEventListener("DOMContentLoaded", bootstrap);
})();
