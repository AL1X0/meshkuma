(() => {
  "use strict";

  const PALETTES = {
    orange: [247, 115, 43],
    ok: [111, 214, 160],
    info: [98, 182, 255],
    warn: [255, 181, 71],
    danger: [255, 92, 108],
    violet: [167, 139, 250],
    muted: [130, 136, 145]
  };

  const registry = new Map();
  let rafID = null;
  let lastFrame = 0;

  function reducedMotion() {
    return typeof window !== "undefined" &&
      window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function escapeHTML(str) {
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function computeLEDPattern(mode, x, y, n, t) {
    const cx = (n - 1) / 2;
    const cy = (n - 1) / 2;
    const dx = x - cx;
    const dy = y - cy;
    const dist = Math.hypot(dx, dy);
    const maxR = Math.hypot(cx, cy) || 1;
    const angle = Math.atan2(dy, dx);

    switch (mode) {
      case "radar": {
        const wave = ((t * 2.2) % (maxR + 1.4));
        const ring = Math.max(0, 1 - Math.abs(dist - wave) * 1.1);
        const core = dist < 0.7 ? 0.65 + 0.35 * Math.sin(t * 4) : 0;
        return Math.min(1, Math.max(ring, core));
      }
      case "orbit": {
        const rTarget = n >= 7 ? 2.15 : 1.45;
        if (Math.abs(dist - rTarget) > 0.85) return dist < 0.6 ? 0.25 : 0;
        const head = (t * 4.5) % (Math.PI * 2);
        let diff = (head - angle + Math.PI * 4) % (Math.PI * 2);
        return Math.max(0.08, Math.pow(Math.max(0, 1 - diff / (Math.PI * 1.35)), 2.2));
      }
      case "sweep": {
        const scanPos = ((Math.sin(t * 2.6) + 1) * 0.5) * (n - 1);
        const bar = Math.max(0, 1 - Math.abs(x - scanPos) * 0.85);
        const shimmer = 0.7 + 0.3 * Math.sin(t * 6 + y * 0.8);
        return bar * shimmer;
      }
      case "wave": {
        const wavePos = ((t * 3.4) % (n * 2));
        const d = Math.abs((x + y) - wavePos);
        const v = Math.max(0, 1 - d * 0.52);
        return v * v;
      }
      case "cross": {
        const onDiag = Math.abs(x - y) < 0.6 || Math.abs(x + y - (n - 1)) < 0.6;
        const pulse = 0.45 + 0.55 * Math.abs(Math.sin(t * 4.2));
        return onDiag ? pulse : (dist < 1.1 ? 0.3 : 0);
      }
      case "matrix": {
        const speed = 2.6 + ((x * 37) % 5) * 0.55;
        const head = ((t * speed + x * 1.7) % (n + 3));
        const trail = head - y;
        if (trail < 0 || trail > 3.2) return 0;
        return Math.max(0.1, 1 - trail / 3.2);
      }
      case "link": {
        const ping = ((t * 2.4) % 2);
        const pos = ping <= 1 ? ping * (n - 1) : (2 - ping) * (n - 1);
        const onLine = Math.abs(dy) <= 0.6;
        const pulseDot = Math.max(0, 1 - Math.abs(x - pos) * 0.9);
        const endpoints = (x === 0 || x === n - 1) && Math.abs(dy) <= 1.1 ? 0.5 : 0;
        return Math.min(1, Math.max(endpoints, onLine ? pulseDot : pulseDot * 0.45));
      }
      case "idle":
      default: {
        const breath = 0.35 + 0.65 * (0.5 + 0.5 * Math.sin(t * 2.1));
        if (dist < 0.7) return breath;
        if (dist < 1.55) return breath * 0.25;
        return 0;
      }
    }
  }

  function renderLEDFrame(canvas, entry, timeSec) {
    const n = entry.size || 7;
    const dpr = window.devicePixelRatio || 1;
    const cssSize = entry.cssSize || (n >= 7 ? 30 : 20);
    const targetPx = Math.round(cssSize * dpr);
    if (canvas.width !== targetPx || canvas.height !== targetPx) {
      canvas.width = targetPx;
      canvas.height = targetPx;
      canvas.style.width = cssSize + "px";
      canvas.style.height = cssSize + "px";
    }

    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssSize, cssSize);

    const rgb = PALETTES[entry.color] || PALETTES.orange;
    const pad = 2;
    const cell = (cssSize - pad * 2) / n;
    const r = Math.max(1.1, cell * 0.33);
    const t = reducedMotion() ? 1.2 : timeSec * (entry.speed || 1);

    for (let y = 0; y < n; y++) {
      for (let x = 0; x < n; x++) {
        const cx = pad + (x + 0.5) * cell;
        const cy = pad + (y + 0.5) * cell;
        const intensity = computeLEDPattern(entry.mode, x, y, n, t);

        // Recessed socket dot
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(255,255,255,0.075)";
        ctx.fill();

        if (intensity > 0.04) {
          if (intensity > 0.45 && n >= 7) {
            ctx.beginPath();
            ctx.arc(cx, cy, r * 2.1, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${(intensity * 0.22).toFixed(3)})`;
            ctx.fill();
          }
          ctx.beginPath();
          ctx.arc(cx, cy, r, 0, Math.PI * 2);
          const hot = Math.min(1, intensity * 0.35);
          const rr = Math.round(rgb[0] + (255 - rgb[0]) * hot);
          const gg = Math.round(rgb[1] + (255 - rgb[1]) * hot);
          const bb = Math.round(rgb[2] + (255 - rgb[2]) * hot);
          ctx.fillStyle = `rgba(${rr},${gg},${bb},${Math.min(1, 0.16 + intensity * 0.84).toFixed(3)})`;
          ctx.fill();
        }
      }
    }
  }

  function tick(now) {
    if (document.hidden) {
      rafID = null;
      return;
    }
    if (now - lastFrame >= 33) { // ~30 fps smooth hardware LED update
      lastFrame = now;
      const tSec = now / 1000;
      for (const [canvas, entry] of registry.entries()) {
        if (!canvas.isConnected) {
          registry.delete(canvas);
          continue;
        }
        renderLEDFrame(canvas, entry, tSec);
      }
    }
    if (registry.size > 0 && !reducedMotion()) {
      rafID = requestAnimationFrame(tick);
    } else {
      rafID = null;
    }
  }

  function ensureTicker() {
    if (rafID == null && registry.size > 0 && !document.hidden && !reducedMotion()) {
      rafID = requestAnimationFrame(tick);
    }
  }

  function mountLED(canvas, opts = {}) {
    if (!canvas) return;
    const entry = {
      mode: opts.mode || canvas.dataset.ledMode || "radar",
      color: opts.color || canvas.dataset.ledColor || "orange",
      size: Number(opts.size || canvas.dataset.ledSize || 7),
      cssSize: Number(opts.cssSize || canvas.dataset.ledCss || 0),
      speed: Number(opts.speed || canvas.dataset.ledSpeed || 1)
    };
    registry.set(canvas, entry);
    renderLEDFrame(canvas, entry, performance.now() / 1000);
    ensureTicker();
  }

  function syncLEDs(root = document) {
    root.querySelectorAll("canvas[data-led-mode]").forEach((c) => {
      mountLED(c, {
        mode: c.dataset.ledMode,
        color: c.dataset.ledColor,
        size: c.dataset.ledSize,
        cssSize: c.dataset.ledCss,
        speed: c.dataset.ledSpeed
      });
    });
  }

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) ensureTicker();
  });

  /* ---- Charts & SVG Widgets ---- */

  function ringHTML(value, opts = {}) {
    const v = Math.max(0, Math.min(100, Number(value) || 0));
    const size = opts.size || 78;
    const stroke = opts.stroke || 7;
    const r = (size - stroke) / 2;
    const c = 2 * Math.PI * r;
    const offset = c * (1 - v / 100);
    const arc = opts.color || (v >= (opts.dangerAt ?? 90) ? "var(--danger)" : v >= (opts.warnAt ?? 75) ? "var(--warn)" : "var(--ok)");
    const display = opts.display != null ? opts.display : Math.round(v) + "%";
    const sub = opts.sub || "";
    return (
      '<div class="ring" style="width:' + size + "px;height:" + size + 'px">' +
      '<svg width="' + size + '" height="' + size + '" aria-hidden="true">' +
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="var(--surface-muted)" stroke-width="' + stroke + '"/>' +
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="' + arc + '" stroke-width="' + stroke + '" stroke-linecap="round" ' +
      'stroke-dasharray="' + c.toFixed(2) + '" stroke-dashoffset="' + offset.toFixed(2) + '" transform="rotate(-90 ' + size / 2 + " " + size / 2 + ')" ' +
      'style="transition:stroke-dashoffset .75s cubic-bezier(.23,1,.32,1)"/>' +
      "</svg>" +
      '<div class="ring-label">' +
      '<div class="ring-value">' + escapeHTML(display) + "</div>" +
      (sub ? '<div class="ring-sub">' + escapeHTML(sub) + "</div>" : "") +
      "</div>" +
      "</div>"
    );
  }

  function meterHTML(percent, warnAt = 75, dangerAt = 90) {
    const v = Math.max(0, Math.min(100, Number(percent) || 0));
    const tone = v >= dangerAt ? " danger" : v >= warnAt ? " warn" : " ok";
    return (
      '<div class="meter' + tone + '" role="meter" aria-valuenow="' + Math.round(v) + '" aria-valuemin="0" aria-valuemax="100">' +
      '<span style="width:' + v.toFixed(1) + '%"></span>' +
      "</div>"
    );
  }

  function sparklineHTML(values, opts = {}) {
    const w = opts.width || 96;
    const h = opts.height || 28;
    const color = opts.color || "var(--primary)";
    const list = (Array.isArray(values) ? values : []).filter((v) => typeof v === "number" && !Number.isNaN(v));
    if (list.length < 2) {
      return '<svg viewBox="0 0 ' + w + " " + h + '" width="' + w + '" height="' + h + '" aria-hidden="true">' +
        '<line x1="0" y1="' + (h - 4) + '" x2="' + w + '" y2="' + (h - 4) + '" stroke="var(--border)" stroke-dasharray="3 3" stroke-width="1"/></svg>';
    }
    const maxVal = opts.max != null ? opts.max : Math.max(1, ...list) * 1.15;
    const minVal = opts.min != null ? opts.min : 0;
    const span = Math.max(1e-6, maxVal - minVal);
    const coords = list.map((v, i) => {
      const x = (i / (list.length - 1)) * (w - 4) + 2;
      const y = h - 3 - ((Math.max(minVal, Math.min(maxVal, v)) - minVal) / span) * (h - 7);
      return [x, y];
    });
    const pts = coords.map(([x, y]) => x.toFixed(1) + "," + y.toFixed(1)).join(" ");
    const last = coords[coords.length - 1];
    const fillPts = `2,${h} ${pts} ${(w - 2).toFixed(1)},${h}`;
    return (
      '<svg viewBox="0 0 ' + w + " " + h + '" style="width:' + (opts.fluid ? "100%" : w + "px") + ";height:" + h + 'px;display:block" preserveAspectRatio="' + (opts.fluid ? "none" : "xMidYMid meet") + '" aria-hidden="true">' +
      '<polygon points="' + fillPts + '" fill="' + color + '" opacity="0.14"/>' +
      '<polyline points="' + pts + '" fill="none" stroke="' + color + '" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>' +
      '<circle cx="' + last[0].toFixed(1) + '" cy="' + last[1].toFixed(1) + '" r="2.5" fill="' + color + '"/>' +
      "</svg>"
    );
  }

  function uptimeStripHTML(points, isPeer = false, maxSlots = 28) {
    const list = Array.isArray(points) ? points.slice(-maxSlots) : [];
    const pad = Math.max(0, maxSlots - list.length);
    let bars = "";
    for (let i = 0; i < pad; i++) {
      bars += '<span class="uptime-bar" aria-hidden="true"></span>';
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
      const when = pt.ts ? new Date(pt.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
      const tip = when + (pt.latency_ms != null ? " · " + pt.latency_ms + " ms" : "");
      bars += '<span class="uptime-bar ' + cls + '" title="' + escapeHTML(tip) + '"></span>';
    });
    const pct = list.length ? Math.round((okCount / list.length) * 100) + "%" : "100%";
    return (
      '<div class="uptime-strip">' +
      '<div class="uptime-bars">' + bars + "</div>" +
      '<span class="uptime-pct tabular">' + pct + "</span>" +
      "</div>"
    );
  }

  function renderLineChart(container, opts) {
    if (!container) return;
    const data = (opts.data || []).filter((d) => typeof d.v === "number" && !Number.isNaN(d.v));
    const title = opts.title || "";
    const latestText = opts.latest || (data.length ? opts.format(data[data.length - 1].v) : "—");
    const color = opts.color || "var(--primary)";
    const h = opts.height || 145;
    const w = 640;
    const pad = { l: 44, r: 12, t: 10, b: 22 };

    if (data.length < 2) {
      container.innerHTML =
        '<div class="chart-box">' +
        '<div class="chart-head"><span class="chart-title">' + escapeHTML(title) + '</span><span class="chart-val">' + escapeHTML(latestText) + "</span></div>" +
        '<div class="empty" style="padding:26px 8px">Collecte des échantillons en cours… (' + data.length + "/2)</div>" +
        "</div>";
      return;
    }

    const t0 = data[0].ts;
    const t1 = Math.max(t0 + 1, data[data.length - 1].ts);
    const rawMax = Math.max(...data.map((d) => d.v));
    const top = opts.max != null ? opts.max : Math.max(10, Math.ceil(rawMax * 1.2));

    const xOf = (ts) => pad.l + ((ts - t0) / (t1 - t0)) * (w - pad.l - pad.r);
    const yOf = (val) => pad.t + (1 - Math.min(top, Math.max(0, val)) / top) * (h - pad.t - pad.b);

    const pathD = data.map((d, i) => (i ? "L" : "M") + xOf(d.ts).toFixed(1) + "," + yOf(d.v).toFixed(1)).join("");
    const areaD = `${pathD}L${xOf(t1).toFixed(1)},${yOf(0).toFixed(1)}L${xOf(t0).toFixed(1)},${yOf(0).toFixed(1)}Z`;
    const gradID = "grad-" + Math.random().toString(36).slice(2, 8);
    const yTicks = [0, top / 2, top];
    const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

    container.innerHTML =
      '<div class="chart-box">' +
      '<div class="chart-head"><span class="chart-title">' + escapeHTML(title) + '</span><span class="chart-val">' + escapeHTML(latestText) + "</span></div>" +
      '<div style="position:relative">' +
      '<svg class="chart-svg" viewBox="0 0 ' + w + " " + h + '" style="width:100%;height:' + h + 'px;display:block" role="img">' +
      "<defs><linearGradient id='" + gradID + "' x1='0' y1='0' x2='0' y2='1'>" +
      `<stop offset="0%" stop-color="${color}" stop-opacity="0.28"/>` +
      `<stop offset="100%" stop-color="${color}" stop-opacity="0"/>` +
      "</linearGradient></defs>" +
      yTicks.map((v) =>
        `<line x1="${pad.l}" x2="${w - pad.r}" y1="${yOf(v).toFixed(1)}" y2="${yOf(v).toFixed(1)}" stroke="var(--hairline)" stroke-width="1"/>` +
        `<text x="${pad.l - 6}" y="${(yOf(v) + 4).toFixed(1)}" text-anchor="end" font-family="var(--font-mono)" font-size="10" fill="var(--text-faint)">${escapeHTML(opts.format(v))}</text>`
      ).join("") +
      `<text x="${xOf(t0).toFixed(1)}" y="${h - 5}" text-anchor="start" font-family="var(--font-mono)" font-size="10" fill="var(--text-faint)">${escapeHTML(fmtTime(t0))}</text>` +
      `<text x="${xOf(t1).toFixed(1)}" y="${h - 5}" text-anchor="end" font-family="var(--font-mono)" font-size="10" fill="var(--text-faint)">${escapeHTML(fmtTime(t1))}</text>` +
      `<path d="${areaD}" fill="url(#${gradID})"/>` +
      `<path d="${pathD}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke" class="chart-line-anim"/>` +
      `<line class="chart-hover-line" x1="0" x2="0" y1="${pad.t}" y2="${h - pad.b}" stroke="var(--text-faint)" stroke-dasharray="3 3" stroke-width="1" hidden/>` +
      `<circle class="chart-hover-dot" cx="0" cy="0" r="4.5" fill="${color}" stroke="var(--surface)" stroke-width="2" hidden/>` +
      "</svg>" +
      '<div class="chart-tip" hidden></div>' +
      "</div></div>";

    const svg = container.querySelector(".chart-svg");
    const hLine = container.querySelector(".chart-hover-line");
    const hDot = container.querySelector(".chart-hover-dot");
    const tip = container.querySelector(".chart-tip");

    svg.addEventListener("pointermove", (e) => {
      const rect = svg.getBoundingClientRect();
      if (!rect.width) return;
      const px = ((e.clientX - rect.left) / rect.width) * w;
      let best = data[0];
      let bestD = Infinity;
      for (let i = 0; i < data.length; i++) {
        const d = Math.abs(xOf(data[i].ts) - px);
        if (d < bestD) {
          bestD = d;
          best = data[i];
        }
      }
      const cx = xOf(best.ts);
      const cy = yOf(best.v);
      hLine.setAttribute("x1", cx.toFixed(1));
      hLine.setAttribute("x2", cx.toFixed(1));
      hLine.removeAttribute("hidden");
      hDot.setAttribute("cx", cx.toFixed(1));
      hDot.setAttribute("cy", cy.toFixed(1));
      hDot.removeAttribute("hidden");
      tip.style.left = Math.max(12, Math.min(88, (cx / w) * 100)).toFixed(1) + "%";
      tip.innerHTML = `<div class="xs faint mono">${escapeHTML(fmtTime(best.ts))}</div><b>${escapeHTML(opts.format(best.v))}</b>`;
      tip.hidden = false;
    });
    svg.addEventListener("pointerleave", () => {
      hLine.setAttribute("hidden", "");
      hDot.setAttribute("hidden", "");
      tip.hidden = true;
    });
  }

  function renderTopologySVG(svg, st, handlers = {}) {
    if (!svg || !st) return;
    const cs = getComputedStyle(document.documentElement);
    const cSurface = cs.getPropertyValue("--surface").trim();
    const cSunken = cs.getPropertyValue("--surface-sunken").trim();
    const cBorder = cs.getPropertyValue("--border-strong").trim();
    const cText = cs.getPropertyValue("--text").trim();
    const cMuted = cs.getPropertyValue("--text-faint").trim();
    const cAccent = cs.getPropertyValue("--action").trim();
    const cOk = cs.getPropertyValue("--ok").trim();
    const cErr = cs.getPropertyValue("--danger").trim();
    const cWarn = cs.getPropertyValue("--warn").trim();

    const relays = st.relays || [];
    const peers = st.peers || [];
    const probes = st.probes || [];
    const okProbes = probes.filter((p) => p.ok).length;
    const connRelays = relays.filter((r) => r.connected).length;

    const peerCount = Math.max(peers.length, 1);
    const viewH = Math.max(210, 58 + peerCount * 68);
    svg.setAttribute("viewBox", "0 0 960 " + viewH);

    const midY = Math.round(viewH / 2);
    const localColor = st.mode === "setup" ? cWarn : st.overall_ok ? cOk : cErr;
    const relayColor = connRelays > 0 ? cAccent : cMuted;
    const animate = !reducedMotion();

    let out = "";
    const leftPath = `M 276 ${midY} L 372 ${midY}`;
    out += `<path d="${leftPath}" fill="none" stroke="${relayColor}" stroke-width="2" ${connRelays === 0 ? 'stroke-dasharray="5 5"' : ""}/>`;
    if (animate && connRelays > 0) {
      out += `<circle r="3.5" fill="${cAccent}"><animateMotion dur="2.2s" repeatCount="indefinite" path="${leftPath}"/></circle>`;
    }

    const peerStartY = peerCount === 1 ? midY : Math.round((viewH - (peerCount - 1) * 68) / 2);
    if (peers.length === 0) {
      out += `<path d="M 588 ${midY} L 684 ${midY}" fill="none" stroke="${cBorder}" stroke-width="1.6" stroke-dasharray="5 5"/>`;
      out +=
        `<g class="topo-node" data-topo-action="friends">` +
        `<rect x="684" y="${midY - 30}" width="244" height="60" rx="10" fill="${cSunken}" stroke="${cBorder}" stroke-dasharray="4 4" stroke-width="1.4"/>` +
        `<text x="704" y="${midY - 3}" fill="${cText}" font-family="var(--font)" font-size="14" font-weight="600">Inviter un ami</text>` +
        `<text x="704" y="${midY + 16}" fill="${cMuted}" font-family="var(--font-mono)" font-size="11">Partager un code MW1-...</text>` +
        `</g>`;
    } else {
      peers.forEach((peer, i) => {
        const py = peerStartY + i * 68;
        let pColor = cMuted;
        let pState = "EN ATTENTE";
        if (peer.timed_out) {
          pColor = cErr;
          pState = "HORS LIGNE";
        } else if (peer.online && !peer.overall_ok) {
          pColor = cWarn;
          pState = "ALERTE DÉTECTÉE";
        } else if (peer.online) {
          pColor = cOk;
          pState = "EN LIGNE · PROTÉGÉ";
        }
        const curve = `M 588 ${midY} C 636 ${midY}, 636 ${py}, 684 ${py}`;
        out += `<path d="${curve}" fill="none" stroke="${pColor}" stroke-width="2" ${!peer.online ? 'stroke-dasharray="5 5"' : ""}/>`;
        if (animate && peer.online) {
          out += `<circle r="3.2" fill="${pColor}"><animateMotion dur="${(2.6 + i * 0.35).toFixed(2)}s" repeatCount="indefinite" path="${curve}"/></circle>`;
        }
        out +=
          `<g class="topo-node" data-topo-peer="${escapeHTML(peer.pubkey_hex || "")}">` +
          `<rect x="684" y="${py - 28}" width="244" height="56" rx="10" fill="${cSurface}" stroke="${cBorder}" stroke-width="1.4"/>` +
          `<circle cx="704" cy="${py}" r="4.5" fill="${pColor}"/>` +
          `<text x="719" y="${py - 4}" fill="${cText}" font-family="var(--font)" font-size="14" font-weight="600">${escapeHTML((peer.name || "Ami").slice(0, 22))}</text>` +
          `<text x="719" y="${py + 15}" fill="${cMuted}" font-family="var(--font-mono)" font-size="10.5">${escapeHTML(pState)}</text>` +
          `</g>`;
      });
    }

    out +=
      `<g class="topo-node" data-topo-action="settings">` +
      `<rect x="372" y="${midY - 42}" width="216" height="84" rx="10" fill="${cSunken}" stroke="${relayColor}" stroke-width="1.5"/>` +
      `<rect x="406" y="${midY - 21}" width="7" height="7" fill="${cAccent}"/>` +
      `<text x="421" y="${midY - 12}" fill="${cText}" font-family="var(--font-mono)" font-size="12" font-weight="600">RELAIS NOSTR E2E</text>` +
      `<text x="480" y="${midY + 9}" text-anchor="middle" fill="${cText}" font-family="var(--font-mono)" font-size="13" font-weight="600">${connRelays} / ${relays.length} connectés</text>` +
      `<text x="480" y="${midY + 27}" text-anchor="middle" fill="${cMuted}" font-family="var(--font-mono)" font-size="10.5">AES-256-GCM · kind 24242</text>` +
      `</g>`;

    out +=
      `<g class="topo-node" data-topo-action="discover">` +
      `<rect x="32" y="${midY - 42}" width="244" height="84" rx="10" fill="${cSurface}" stroke="${localColor}" stroke-width="1.7"/>` +
      `<circle cx="54" cy="${midY - 15}" r="5" fill="${localColor}"/>` +
      `<text x="69" y="${midY - 10}" fill="${cText}" font-family="var(--font)" font-size="15" font-weight="700">${escapeHTML((st.node_name || "Chez vous").slice(0, 20))}</text>` +
      `<text x="50" y="${midY + 11}" fill="${cText}" font-family="var(--font-mono)" font-size="12">${okProbes} / ${probes.length} sondes actives</text>` +
      `<text x="50" y="${midY + 28}" fill="${cMuted}" font-family="var(--font-mono)" font-size="10.5">${st.muted ? "AUTO-MUTE ACTIF" : "0 PORT ENTRANT"}</text>` +
      `</g>`;

    svg.innerHTML = out;
    svg.querySelectorAll("[data-topo-action]").forEach((n) => {
      n.addEventListener("click", () => handlers.onAction && handlers.onAction(n.dataset.topoAction));
    });
    svg.querySelectorAll("[data-topo-peer]").forEach((n) => {
      n.addEventListener("click", () => handlers.onPeer && handlers.onPeer(n.dataset.topoPeer));
    });
  }

  window.MWViz = {
    mountLED,
    syncLEDs,
    ringHTML,
    meterHTML,
    sparklineHTML,
    uptimeStripHTML,
    renderLineChart,
    renderTopologySVG
  };
})();
