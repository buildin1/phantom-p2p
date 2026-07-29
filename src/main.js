// 检测运行模式：Tauri 或 Web
const isTauriMode = typeof window.__TAURI__ !== "undefined";
const isWebMode = !isTauriMode;

// 统一的 API 接口
const invoke = isTauriMode
  ? window.__TAURI__.core.invoke
  : async (command, args = {}) => {
      // Web 模式：通过 HTTP API 调用
      const response = await fetch(`/api/invoke/${command}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(args),
      });
      if (!response.ok) throw new Error(`API 调用失败: ${command}`);
      return response.json();
    };

// 统一的事件监听接口
const listen = isTauriMode
  ? window.__TAURI__.event.listen
  : (eventName, callback) => {
      // Web 模式：通过 WebSocket 接收事件
      if (!window.__WS__) {
        const ws = new WebSocket(`ws://${window.location.host}/api/ws`);
        ws.onmessage = (event) => {
          const data = JSON.parse(event.data);
          if (window.__WS_HANDLERS__[data.event]) {
            window.__WS_HANDLERS__[data.event].forEach((cb) =>
              cb({ payload: data.data })
            );
          }
        };
        window.__WS__ = ws;
        window.__WS_HANDLERS__ = {};
      }
      if (!window.__WS_HANDLERS__[eventName]) {
        window.__WS_HANDLERS__[eventName] = [];
      }
      window.__WS_HANDLERS__[eventName].push(callback);
      return Promise.resolve(() => {
        // 返回取消监听函数
        const idx = window.__WS_HANDLERS__[eventName].indexOf(callback);
        if (idx > -1) window.__WS_HANDLERS__[eventName].splice(idx, 1);
      });
    };

const $ = (id) => document.getElementById(id);
const MAX_POINTS = 60;
const LOG_LIMIT = 400;
const FLOW_STEPS = ["STUN 探测", "信令交换", "UDP 打洞", "隧道启动"];

// 编译期注入的官方信令服务器地址（见 vite.config.js / official.env）。
// 仅用简单字符串比较区分"官方网络"与"自建/第三方网络"，不做密码学身份校验（后续任务）。
const OFFICIAL_SIGNAL_SERVER =
  typeof __OFFICIAL_SIGNAL_SERVER__ !== "undefined" && __OFFICIAL_SIGNAL_SERVER__
    ? __OFFICIAL_SIGNAL_SERVER__
    : "ws://qx.coreyuan.cn:10112";

/** 当前地址是否为官方信令服务器（简单字符串比较，不做证书/签名校验） */
function isOfficialSignal(url) {
  return String(url || "").trim() === OFFICIAL_SIGNAL_SERVER;
}

const DEFAULT_SETTINGS = {
  signal: OFFICIAL_SIGNAL_SERVER,
  timeout: 8
};

const state = {
  running: true,
  theme: "dark",
  uptime: 0,
  isDevMode: false,
  connected: false,
  authenticated: false,
  roomCode: null,
  isHost: false,
  guestActive: false,
  sessionId: null,
  peerUserId: null,
  relayInfo: null,
  subnet: null,
  virtualIp: null,
  hostVirtualIp: null,
  fixedHostIp: null,
  fixedIpBusy: false,
  monitoringBusy: false,
  diagBusy: false,
  lastStatsErr: "",
  diagProgress: {
    value: 0,
    stage: "待命",
    eta: 0
  },

  hostSeries: { up: [], down: [] },
  guestSeries: { up: [], down: [] },
  diagSeries: {
    ping: Array.from({ length: MAX_POINTS }, () => 0),
    loss: Array.from({ length: MAX_POINTS }, () => 0)
  },

  hostUpMB: 0,
  hostDownMB: 0,
  hostUpNow: 0,
  hostDownNow: 0,

  guest: {
    id: "c_pending",
    ping: 0,
    loss: 0,
    up: 0,
    down: 0,
    jitter: 0,
    addr: "--",
    mode: "待连接"
  },

  players: [],
  logs: [],

  config: null,
  settings: { ...DEFAULT_SETTINGS },
  flags: {
    upnp: true,
    preferIpv6: false,
    verbose: true,
    autoConnect: true,
    smoothCharts: false
  },

  diag: {
    nat: "未检测",
    mapping: "--",
    filtering: "--",
    portPattern: "--",
    confidence: "--",
    public: "--",
    upnp: "--",
    ipv6: "--",
    priority: "--"
  },
  diagMappings: [],
  diagRounds: 0
};

const joinFlow = {
  timer: null,
  progress: 0
};

const diagFlow = {
  timer: null
};

const viewNavItems = [...document.querySelectorAll(".nav-item[data-view]")];
const views = [...document.querySelectorAll(".view")];
const jumpButtons = [...document.querySelectorAll("[data-jump]")];
const settingsToggleRows = [...document.querySelectorAll("#view-settings .toggle[data-flag]")];

function maskSignalUrl(url) {
  const raw = String(url || "").trim();
  if (!raw) return "********";
  const match = raw.match(/^(wss?):\/\/(.+)$/i);
  if (match) return `${match[1].toLowerCase()}://********`;
  return "********";
}

function maskIpEndpoint(value) {
  const raw = String(value || "");
  const maskedIpv4 = raw.replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b/g, (m) => {
    return m.includes(":") ? "***.***.***.***:****" : "***.***.***.***";
  });
  return maskedIpv4.replace(/\b(?:[a-f0-9]{1,4}:){2,}[a-f0-9:]*\b/gi, "****:****:****");
}

function sanitizeSensitiveText(message) {
  let text = String(message || "");
  if (state.isDevMode) return text;
  text = text.replace(/wss?:\/\/[^\s)]+/gi, (url) => maskSignalUrl(url));
  text = text.replace(/(信令(?:服务器)?(?:地址)?\s*[:：]\s*)([^\s|]+)/g, "$1********");
  return maskIpEndpoint(text);
}

function rand(min, max) {
  return Math.random() * (max - min) + min;
}

function seed(count, min, max) {
  return Array.from({ length: count }, () => rand(min, max));
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function fmtClock(date) {
  return date.toLocaleTimeString("zh-CN", { hour12: false });
}

function fmtTime(sec) {
  const h = String(Math.floor(sec / 3600)).padStart(2, "0");
  const m = String(Math.floor((sec % 3600) / 60)).padStart(2, "0");
  const s = String(sec % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

function fmtMB(mb) {
  if (mb < 1024) return `${mb.toFixed(1)} MB`;
  return `${(mb / 1024).toFixed(2)} GB`;
}

function normalizeHistory(history, fallback) {
  if (Array.isArray(history) && history.length) {
    return history.slice(-MAX_POINTS).map((v) => Number(v) || 0);
  }
  return fallback.slice(-MAX_POINTS);
}

function modeToText(mode) {
  const value = String(mode || "").toLowerCase();
  if (value.includes("p2p") && value.includes("tcp")) return "P2P 直连 (TCP)";
  if (value.includes("p2p") && value.includes("udp")) return "P2P 直连 (UDP)";
  if (value === "p2p") return "P2P 直连";
  if (value.includes("relay") || value.includes("quic")) return "P2P 直连 (QUIC)";
  return "待连接";
}

function isRelayMode(mode) {
  const text = String(mode || "");
  return text.includes("QUIC");
}

function pushSeries(arr, value) {
  arr.push(value);
  if (arr.length > MAX_POINTS) arr.shift();
}

function shortId(id) {
  if (!id) return "--";
  return id.length > 12 ? id.slice(0, 12) : id;
}

function zeroSeries() {
  return Array.from({ length: MAX_POINTS }, () => 0);
}

function clearRealtimeStats() {
  state.hostSeries.up = zeroSeries();
  state.hostSeries.down = zeroSeries();
  state.guestSeries.up = zeroSeries();
  state.guestSeries.down = zeroSeries();
  state.diagSeries.ping = zeroSeries();
  state.diagSeries.loss = zeroSeries();

  state.hostUpMB = 0;
  state.hostDownMB = 0;
  state.hostUpNow = 0;
  state.hostDownNow = 0;

  state.players = [];
  state.guest.ping = 0;
  state.guest.loss = 0;
  state.guest.up = 0;
  state.guest.down = 0;
  state.guest.jitter = 0;
}

function updateActionButtons() {
  const hostMainBtn = $("hostMainBtn");
  if (hostMainBtn) {
    const active = state.isHost;
    hostMainBtn.textContent = active ? "关闭房间" : "创建房间";
    hostMainBtn.classList.toggle("pri", !active);
    hostMainBtn.classList.toggle("danger", active);
  }

  const joinMainBtn = $("joinMainBtn");
  if (joinMainBtn) {
    const inGuestSession = !state.isHost && !!state.roomCode;
    joinMainBtn.textContent = inGuestSession ? "离开房间" : "开始连接";
    joinMainBtn.classList.toggle("pri", !inGuestSession);
    joinMainBtn.classList.toggle("warn", inGuestSession);
  }

  const copyCodeBtn = $("copyCodeBtn");
  if (copyCodeBtn) {
    copyCodeBtn.disabled = !(state.isHost && !!state.roomCode);
  }

  const displayedHostIp = state.fixedHostIp || (state.isHost && state.virtualIp) || "127.0.0.1";
  setText("hostPublicIp", displayedHostIp);
  const hostIpMode = $("hostIpMode");
  if (hostIpMode) {
    hostIpMode.textContent = state.fixedHostIp
      ? "固定 IP"
      : state.isHost && state.virtualIp
        ? "动态 IP"
        : "未开房间";
    hostIpMode.classList.toggle("fixed", !!state.fixedHostIp);
  }
  const roomActive = !!state.roomCode;
  const requestFixedIpBtn = $("requestFixedIpBtn");
  if (requestFixedIpBtn) {
    requestFixedIpBtn.textContent = state.fixedIpBusy
      ? "处理中..."
      : state.fixedHostIp
        ? "放弃固定 IP"
        : "申请固定 IP";
    requestFixedIpBtn.disabled = roomActive || state.fixedIpBusy;
    requestFixedIpBtn.classList.toggle("danger", !!state.fixedHostIp);
    requestFixedIpBtn.classList.toggle("sub", !state.fixedHostIp);
  }

  const copyAddrBtn = $("copyAddrBtn");
  if (copyAddrBtn) {
    copyAddrBtn.disabled = !(!state.isHost && !!state.roomCode && !state.guest.addr.includes("----"));
  }
}

function switchView(viewName) {
  views.forEach((view) => view.classList.toggle("active", view.id === `view-${viewName}`));
  viewNavItems.forEach((item) => item.classList.toggle("active", item.dataset.view === viewName));
  refresh();
}

viewNavItems.forEach((item) => {
  item.addEventListener("click", () => switchView(item.dataset.view));
});

jumpButtons.forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.jump));
});

function setText(id, value) {
  const el = $(id);
  if (el) el.textContent = value;
}

function setValue(id, value) {
  const el = $(id);
  if (el) el.value = String(value);
}

const toastQueue = [];
let toastActive = false;

function flushToastQueue() {
  const layer = $("toastLayer");
  if (!layer) {
    toastActive = false;
    return;
  }

  const next = toastQueue.shift();
  if (!next) {
    toastActive = false;
    return;
  }
  toastActive = true;

  const node = document.createElement("div");
  node.className = `toast ${next.type}`;
  node.textContent = next.message;
  layer.innerHTML = "";
  layer.appendChild(node);

  requestAnimationFrame(() => node.classList.add("show"));
  setTimeout(() => {
    node.classList.add("leaving");
    node.classList.remove("show");
    setTimeout(() => {
      node.remove();
      toastActive = false;
      flushToastQueue();
    }, 220);
  }, next.duration);
}

function toast(message, type = "info", duration = 1700) {
  let finalMessage = message
    .replace(/中继回退/g, "P2P 直连")
    .replace(/中继隧道/g, "P2P 隧道")
    .replace(/中继连接/g, "QUIC 连接")
    .replace(/启动中继/g, "建立连接");

  toastQueue.push({ message: finalMessage, type, duration });
  if (!toastActive) flushToastQueue();
}

let confirmResolver = null;

function closeConfirmDialog(accepted) {
  const modal = $("confirmModal");
  if (!modal || modal.hidden) return;
  modal.classList.remove("open");
  const resolve = confirmResolver;
  confirmResolver = null;
  setTimeout(() => {
    modal.hidden = true;
    resolve?.(accepted);
  }, 160);
}

function confirmInApp({ title, message, confirmText = "确认" }) {
  const modal = $("confirmModal");
  if (!modal) return Promise.resolve(false);
  if (confirmResolver) closeConfirmDialog(false);
  setText("confirmTitle", title);
  setText("confirmMessage", message);
  setText("confirmAcceptBtn", confirmText);
  modal.hidden = false;
  requestAnimationFrame(() => {
    modal.classList.add("open");
    $("confirmCancelBtn")?.focus();
  });
  return new Promise((resolve) => {
    confirmResolver = resolve;
  });
}

let customServerResolver = null;

function closeCustomServerDialog(accepted) {
  const modal = $("customServerModal");
  if (!modal || modal.hidden) return;
  modal.classList.remove("open");
  const resolve = customServerResolver;
  customServerResolver = null;
  setTimeout(() => {
    modal.hidden = true;
    resolve?.(accepted);
  }, 160);
}

/**
 * 切换到自建/第三方信令服务器前的强确认弹窗。
 * 用户必须勾选风险确认复选框后，"确认切换"按钮才会启用；不勾选则无法通过点击跳过。
 * 返回 true 表示用户已完成确认流程，可以继续保存新地址；false 表示取消。
 */
function confirmCustomServer() {
  const modal = $("customServerModal");
  if (!modal) return Promise.resolve(false);
  if (customServerResolver) closeCustomServerDialog(false);

  const ackBox = $("customServerAckBox");
  const acceptBtn = $("customServerAcceptBtn");
  if (ackBox) ackBox.checked = false;
  if (acceptBtn) acceptBtn.disabled = true;

  modal.hidden = false;
  requestAnimationFrame(() => {
    modal.classList.add("open");
    ackBox?.focus();
  });
  return new Promise((resolve) => {
    customServerResolver = resolve;
  });
}

/** 顶部持续可见的"自建网络模式"横幅：只要生效的信令地址不是官方地址就一直显示 */
function updateNetworkModeBanner() {
  const banner = $("networkModeBanner");
  if (!banner) return;
  const custom = !isOfficialSignal(state.settings?.signal);
  banner.hidden = !custom;
  if (!custom) return;

  const addrEl = $("networkModeBannerAddr");
  if (addrEl) {
    const displayAddr = state.isDevMode
      ? state.settings.signal
      : maskSignalUrl(state.settings.signal);
    addrEl.textContent = `(${displayAddr})`;
  }
}

function addLog(message, level = "INFO", module = "system") {
  if (level === "INFO" && module !== "system" && !state.flags.verbose) return;

  let finalMessage = message
    .replace(/中继回退/g, "P2P 直连")
    .replace(/中继隧道/g, "P2P 隧道")
    .replace(/中继连接/g, "QUIC 连接")
    .replace(/启动中继/g, "建立连接");

  const entry = {
    id: `${Date.now()}_${Math.random().toString(16).slice(2, 8)}`,
    time: new Date(),
    level,
    module,
    message: sanitizeSensitiveText(finalMessage)
  };
  state.logs.push(entry);
  if (state.logs.length > LOG_LIMIT) state.logs.shift();
  renderLogs();
  renderHomeSummary();
}

function drawSeriesChart(canvasId, data, color, fill, minMax = 1) {
  const canvas = $(canvasId);
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  if (rect.width < 8 || rect.height < 8) return;

  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.floor(rect.width * dpr);
  canvas.height = Math.floor(rect.height * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const w = rect.width;
  const h = rect.height;
  const padX = 12;
  const padTop = 10;
  const padBottom = 14;
  const drawW = w - padX * 2;
  const drawH = h - padTop - padBottom;
  const top = Math.max(Math.max(...data, minMax) * 1.12, minMax);
  const step = drawW / Math.max(data.length - 1, 1);
  const yOf = (v) => padTop + drawH - (v / top) * drawH;

  ctx.clearRect(0, 0, w, h);
  ctx.strokeStyle = "rgba(125,150,205,0.2)";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i += 1) {
    const y = padTop + (drawH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padX, y);
    ctx.lineTo(w - padX, y);
    ctx.stroke();
  }

  if (!data.length) return;
  const points = data.map((value, idx) => ({ x: padX + idx * step, y: yOf(value) }));

  const area = new Path2D();
  area.moveTo(points[0].x, points[0].y);
  for (let i = 1; i < points.length; i += 1) area.lineTo(points[i].x, points[i].y);
  area.lineTo(points[points.length - 1].x, padTop + drawH);
  area.lineTo(points[0].x, padTop + drawH);
  area.closePath();
  ctx.fillStyle = fill;
  ctx.fill(area);

  ctx.beginPath();
  ctx.moveTo(points[0].x, points[0].y);
  for (let i = 1; i < points.length; i += 1) ctx.lineTo(points[i].x, points[i].y);
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.stroke();
}

function renderPlayers() {
  const body = $("playersBody");
  if (!body) return;
  body.innerHTML = "";

  if (!state.players.length) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="5" style="opacity:.72;">暂无在线玩家</td>';
    body.appendChild(tr);
    return;
  }

  const avgUpPerPlayer = state.players.length ? state.hostUpNow / state.players.length : 0;
  const avgDownPerPlayer = state.players.length ? state.hostDownNow / state.players.length : 0;

  state.players.forEach((player, idx) => {
    const tr = document.createElement("tr");
    const spread = 0.86 + (idx % 3) * 0.08;
    const up = avgUpPerPlayer * spread;
    const down = avgDownPerPlayer * spread;
    tr.innerHTML = `
      <td class="mono">${player.user_id || "peer"}</td>
      <td>${Math.round(player.latency || 0)} ms</td>
      <td>${Number(player.packet_loss || 0).toFixed(1)}%</td>
      <td class="up">${up.toFixed(2)} Mbps</td>
      <td class="down">${down.toFixed(2)} Mbps</td>
    `;
    body.appendChild(tr);
  });
}

function resetProgress() {
  joinFlow.progress = 0;
  const fill = $("progressFill");
  if (fill) fill.style.width = "0%";
  setText("progressCode", "------");
  [...($("progressSteps")?.children || [])].forEach((row, idx) => {
    row.classList.toggle("on", idx === 0);
    row.textContent = `${idx + 1}. ${FLOW_STEPS[idx]}${idx === 0 ? " 中..." : ""}`;
  });
}

function setProgress(progress) {
  joinFlow.progress = clamp(progress, 0, 100);
  const fill = $("progressFill");
  if (fill) fill.style.width = `${joinFlow.progress}%`;

  const idx = joinFlow.progress >= 100 ? 3 : joinFlow.progress >= 75 ? 2 : joinFlow.progress >= 45 ? 1 : 0;
  [...($("progressSteps")?.children || [])].forEach((row, i) => {
    const done = i < idx || joinFlow.progress >= 100;
    const current = i === idx && joinFlow.progress < 100;
    row.classList.toggle("on", i <= idx);
    if (done) row.textContent = `${i + 1}. ${FLOW_STEPS[i]} 完成`;
    else if (current) row.textContent = `${i + 1}. ${FLOW_STEPS[i]} 中...`;
    else row.textContent = `${i + 1}. ${FLOW_STEPS[i]}`;
  });
}

function setDiagProgress(progress, stage, etaSeconds = 0) {
  state.diagProgress.value = clamp(Number(progress) || 0, 0, 100);
  if (stage) state.diagProgress.stage = String(stage);
  state.diagProgress.eta = Math.max(0, Number(etaSeconds) || 0);

  const fill = $("diagProgressFill");
  if (fill) fill.style.width = `${state.diagProgress.value}%`;
  setText("diagProgressPct", `${Math.round(state.diagProgress.value)}%`);
  setText("diagStage", state.diagProgress.stage);
  setText("diagEta", `预计剩余 ${state.diagProgress.eta}s`);
}

function startDiagEstimateTicker() {
  clearInterval(diagFlow.timer);
  const start = Date.now();
  diagFlow.timer = setInterval(() => {
    if (!state.diagBusy) return;
    const elapsed = (Date.now() - start) / 1000;
    const target = clamp(Math.floor((elapsed / 16) * 100), 0, 93);
    if (target > state.diagProgress.value) {
      setDiagProgress(target, state.diagProgress.stage || "多轮 STUN 检测中...", Math.max(0, 16 - Math.round(elapsed)));
      refresh();
    }
  }, 280);
}

function stopDiagEstimateTicker() {
  clearInterval(diagFlow.timer);
  diagFlow.timer = null;
}

function renderHomeSummary() {
  const latest = state.logs.slice(-3).reverse();
  if (!latest.length) {
    setText("homeSessionSummary", "暂无会话记录");
    return;
  }
  const txt = latest.map((e) => `${fmtClock(e.time)} ${e.level} ${e.message}`).join(" | ");
  setText("homeSessionSummary", txt);
}

function renderDiagMappings() {
  const body = $("diagMappingsBody");
  if (!body) return;
  body.innerHTML = "";

  if (!state.diagMappings.length) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="3" style="opacity:.72;">尚未执行检测</td>';
    body.appendChild(tr);
    return;
  }

  state.diagMappings.forEach((item) => {
    const mappingText = state.isDevMode ? item.mapping : maskIpEndpoint(item.mapping);
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${item.server}</td>
      <td class="mono">${mappingText}</td>
      <td>${Number(item.rtt || 0).toFixed(0)} ms</td>
    `;
    body.appendChild(tr);
  });
}

function renderDiagSummary() {
  setText("diagNat", state.diag.nat);
  setText("diagPublic", state.isDevMode ? state.diag.public : maskIpEndpoint(state.diag.public));
  setText("diagMapping", state.diag.mapping);
  setText("diagFiltering", state.diag.filtering);
  setText("diagPortPattern", state.diag.portPattern);
  setText("diagConfidence", state.diag.confidence);
  setText("diagUpnp", state.diag.upnp);
  setText("diagIpv6", state.isDevMode ? state.diag.ipv6 : maskIpEndpoint(state.diag.ipv6));
  setText("diagPriority", state.diag.priority);
  setText("diagRounds", `采样轮次 ${state.diagRounds || "--"}`);
  setDiagProgress(state.diagProgress.value, state.diagProgress.stage, state.diagProgress.eta);

  const pingNow = state.diagSeries.ping.at(-1) || 0;
  const lossNow = state.diagSeries.loss.at(-1) || 0;
  setText("diagPingNow", `${Math.round(pingNow)} ms`);
  setText("diagLossNow", `${lossNow.toFixed(1)}%`);
  setText("chipNat", state.diag.nat);
}

function renderMetrics() {
  setText("hostAvgPing", `${Math.round(state.isHost ? state.players.reduce((s, p) => s + (p.latency || 0), 0) / Math.max(state.players.length, 1) : 0)} ms`);
  setText("hostAvgLoss", `${(state.isHost ? state.players.reduce((s, p) => s + (p.packet_loss || 0), 0) / Math.max(state.players.length, 1) : 0).toFixed(1)}%`);
  setText("hostUpTotal", fmtMB(state.hostUpMB));
  setText("hostDownTotal", fmtMB(state.hostDownMB));
  setText("hostUpNow", `${state.hostUpNow.toFixed(2)} Mbps`);
  setText("hostDownNow", `${state.hostDownNow.toFixed(2)} Mbps`);

  setText("guestPing", `${Math.round(state.guest.ping)} ms`);
  setText("guestLoss", `${state.guest.loss.toFixed(1)}%`);
  setText("guestUp", `${state.guest.up.toFixed(2)} Mbps`);
  setText("guestDown", `${state.guest.down.toFixed(2)} Mbps`);
  setText("guestUpNow", `${(state.guestSeries.up.at(-1) || 0).toFixed(2)} Mbps`);
  setText("guestDownNow", `${(state.guestSeries.down.at(-1) || 0).toFixed(2)} Mbps`);
  setText("connId", shortId(state.guest.id));
  setText("connMode", state.guest.mode);
  setText("connAddr", state.guest.addr);
  setText("connJitter", `${state.guest.jitter.toFixed(1)} ms`);

  const chipState = state.guestActive
    ? `已连接 (${state.guest.mode})`
    : state.isHost
      ? "房间已创建"
      : state.connected
        ? "信令已连接"
        : "未连接";
  setText("chipState", chipState);
  setText("chipTraffic", fmtMB(state.hostUpMB + state.hostDownMB));
  setText("chipConnId", shortId(state.sessionId || state.guest.id));

  const homePing = state.guestActive ? state.guest.ping : state.players[0]?.latency || 0;
  const homeLoss = state.guestActive ? state.guest.loss : state.players[0]?.packet_loss || 0;
  const homeUp = state.guestActive ? state.guest.up : state.hostUpNow;
  const homeDown = state.guestActive ? state.guest.down : state.hostDownNow;

  setText("kpiPing", `${Math.round(homePing)} ms`);
  setText("kpiLoss", `${homeLoss.toFixed(1)} %`);
  setText("kpiUp", `${homeUp.toFixed(1)} Mbps`);
  setText("kpiDown", `${homeDown.toFixed(1)} Mbps`);

  // 显示 subnet 虚拟 IP 信息
  if (state.subnet && state.guest.mode.includes("TUN") && !state.guest.addr.includes("----")) {
    setText("connAddr", state.guest.addr);
    setText("connMode", `${state.guest.mode} (${state.subnet}.0/24)`);
  }
}

function updateSidebar() {
  setText("sideCode", state.roomCode || "------");
  setText("sideUptime", fmtTime(state.uptime));
  setText("sideMode", state.guest.mode);
  setText("sidePlayers", String(state.players.length));
}

function renderLogs() {
  const body = $("sessionLogBody");
  if (!body) return;

  const query = $("logSearchInput")?.value.trim().toLowerCase() || "";
  const level = $("logLevelFilter")?.value || "ALL";
  const module = $("logModuleFilter")?.value || "ALL";

  const filtered = state.logs.filter((item) => {
    if (level !== "ALL" && item.level !== level) return false;
    if (module !== "ALL" && item.module !== module) return false;
    if (query && !`${item.level} ${item.module} ${item.message}`.toLowerCase().includes(query)) {
      return false;
    }
    return true;
  });

  setText("logStatTotal", String(state.logs.length));
  setText("logStatInfo", String(state.logs.filter((v) => v.level === "INFO").length));
  setText("logStatWarn", String(state.logs.filter((v) => v.level === "WARN").length));
  setText("logStatError", String(state.logs.filter((v) => v.level === "ERROR").length));
  setText("logStatus", state.running ? "运行中" : "已暂停");

  body.innerHTML = "";
  if (!filtered.length) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="4" style="opacity:.72;">没有匹配日志</td>';
    body.appendChild(tr);
    return;
  }

  filtered.slice().reverse().forEach((entry) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${fmtClock(entry.time)}</td>
      <td>${entry.level}</td>
      <td>${entry.module}</td>
      <td>${entry.message}</td>
    `;
    body.appendChild(tr);
  });
}

function refresh() {
  updateNetworkModeBanner();
  updateActionButtons();
  updateSidebar();
  renderPlayers();
  renderMetrics();
  renderDiagSummary();
  renderDiagMappings();
  renderLogs();

  drawSeriesChart("hostUpChart", state.hostSeries.up, "#4D89FF", "rgba(77,137,255,.22)", 1.2);
  drawSeriesChart("hostDownChart", state.hostSeries.down, "#18B499", "rgba(24,180,153,.2)", 1.2);
  drawSeriesChart("guestUpChart", state.guestSeries.up, "#4D89FF", "rgba(77,137,255,.22)", 0.9);
  drawSeriesChart("guestDownChart", state.guestSeries.down, "#18B499", "rgba(24,180,153,.2)", 0.9);
  drawSeriesChart("diagPingChart", state.diagSeries.ping, "#FF8A3D", "rgba(255,138,61,.2)", 15);
  drawSeriesChart("diagLossChart", state.diagSeries.loss, "#E35E7B", "rgba(227,94,123,.2)", 0.6);
}

function applyStats(stats) {
  if (!stats) return;

  const upNow = Number(stats.upload_mbps || 0);
  const downNow = Number(stats.download_mbps || 0);
  const ping = Number(stats.latency || 0);
  const loss = Number(stats.packet_loss || 0);
  let sessionPing = 0;
  let sessionLoss = 0;
  const selfId = state.sessionId || "";
  const selfIdShort = shortId(selfId);

  if (stats.is_host) {
    if (state.isHost && state.roomCode) {
      const sourcePlayers = Array.isArray(stats.players) ? stats.players : [];
      state.players = sourcePlayers.filter((p) => {
        const pid = String(p?.user_id || "");
        return !!pid && pid !== selfId && pid !== selfIdShort;
      });

      if (state.players.length > 0) {
        const totalUpMB = (Number(stats.total_upload_bytes || 0) / 1024 / 1024);
        const totalDownMB = (Number(stats.total_download_bytes || 0) / 1024 / 1024);
        state.hostUpMB = totalUpMB;
        state.hostDownMB = totalDownMB;
        state.hostUpNow = upNow;
        state.hostDownNow = downNow;
        state.hostSeries.up = normalizeHistory(stats.upload_history, state.hostSeries.up.length ? state.hostSeries.up : [upNow]);
        state.hostSeries.down = normalizeHistory(stats.download_history, state.hostSeries.down.length ? state.hostSeries.down : [downNow]);
        sessionPing = state.players.reduce((sum, p) => sum + Number(p.latency || 0), 0) / state.players.length;
        sessionLoss = state.players.reduce((sum, p) => sum + Number(p.packet_loss || 0), 0) / state.players.length;
      } else {
        state.hostUpMB = 0;
        state.hostDownMB = 0;
        state.hostUpNow = 0;
        state.hostDownNow = 0;
        state.hostSeries.up = zeroSeries();
        state.hostSeries.down = zeroSeries();
        sessionPing = 0;
        sessionLoss = 0;
      }
    } else if (!state.isHost) {
      clearRealtimeStats();
    }
  } else {
    state.guest.mode = modeToText(stats.connection_mode);
    const inGuestSession = !state.isHost && !!state.roomCode && state.guest.mode !== "待连接";
    state.guestActive = inGuestSession;

    if (inGuestSession) {
      const totalUpMB = (Number(stats.total_upload_bytes || 0) / 1024 / 1024);
      const totalDownMB = (Number(stats.total_download_bytes || 0) / 1024 / 1024);
      state.hostUpMB = totalUpMB;
      state.hostDownMB = totalDownMB;
      state.hostUpNow = upNow;
      state.hostDownNow = downNow;

      state.guest.ping = ping;
      state.guest.loss = loss;
      state.guest.up = upNow;
      state.guest.down = downNow;
      state.guestSeries.up = normalizeHistory(stats.upload_history, state.guestSeries.up.length ? state.guestSeries.up : [upNow]);
      state.guestSeries.down = normalizeHistory(stats.download_history, state.guestSeries.down.length ? state.guestSeries.down : [downNow]);
      state.guest.jitter = clamp(state.guest.jitter + rand(-0.4, 0.45), 0.2, 9.5);

      sessionPing = ping;
      sessionLoss = loss;
    } else {
      clearRealtimeStats();
      state.guest.mode = "待连接";
      state.guest.addr = "--";
    }
  }

  pushSeries(state.diagSeries.ping, sessionPing);
  pushSeries(state.diagSeries.loss, sessionLoss);
}

async function pollStats() {
  if (!state.running || state.monitoringBusy) return;
  state.monitoringBusy = true;
  try {
    const stats = await invoke("get_tunnel_stats");
    state.lastStatsErr = "";
    applyStats(stats);
  } catch (err) {
    const msg = String(err);
    if (msg !== state.lastStatsErr) {
      state.lastStatsErr = msg;
      addLog(`获取统计失败: ${msg}`, "WARN", "system");
    }
  } finally {
    state.monitoringBusy = false;
    refresh();
  }
}

async function ensureConnected() {
  if (state.connected) {
    if (!state.authenticated) {
      const ok = await waitForAuth(5000);
      if (!ok) {
        addLog("认证超时，请重试", "ERROR", "system");
        return false;
      }
    }
    return true;
  }
  try {
    await invoke("connect_signal", { signalUrl: state.settings.signal });
    const target = "ws://********";
    addLog(`连接信令服务器: ${target}`, "INFO", "system");
    const ok = await waitForAuth(5000);
    if (!ok) {
      addLog("认证超时，请重试", "ERROR", "system");
      return false;
    }
    return true;
  } catch (err) {
    addLog(`连接信令失败: ${err}`, "ERROR", "system");
    return false;
  }
}

/** 等待 state.authenticated 变为 true，超时返回 false */
function waitForAuth(timeoutMs) {
  return new Promise((resolve) => {
    if (state.authenticated) { resolve(true); return; }
    const interval = 50;
    let elapsed = 0;
    const timer = setInterval(() => {
      elapsed += interval;
      if (state.authenticated) {
        clearInterval(timer);
        resolve(true);
      } else if (elapsed >= timeoutMs) {
        clearInterval(timer);
        resolve(false);
      }
    }, interval);
  });
}

async function startPunch(peerSessionId = null) {
  try {
    await invoke("start_punch", { peerSessionId });
    addLog("开始打洞流程", "INFO", "system");
  } catch (err) {
    addLog(`启动打洞失败: ${err}`, "ERROR", "system");
  }
}

async function startRelayTunnel() {
  if (!state.relayInfo) return;
  try {
    setProgress(Math.max(joinFlow.progress, 85));
    await invoke("start_relay_tunnel", {
      relayAddr: state.relayInfo.relay_addr,
      relayQuicPort: state.relayInfo.relay_quic_port,
      token: state.relayInfo.token
    });
    state.guest.mode = "P2P 直连 (QUIC)";
    setProgress(Math.max(joinFlow.progress, 95));
    addLog("QUIC 连接建立中，等待配对完成...", "INFO", "guest");
  } catch (err) {
    addLog(`QUIC 连接失败: ${err}`, "ERROR", "guest");
    toast(`QUIC 连接失败: ${err}`, "error", 2200);
  }
}

function syncSettingsToggles() {
  settingsToggleRows.forEach((row) => {
    const key = row.dataset.flag;
    const switchNode = row.querySelector(".switch");
    if (!key || !switchNode) return;
    switchNode.classList.toggle("on", !!state.flags[key]);
  });
}

function bindSettingsToggles() {
  syncSettingsToggles();
  settingsToggleRows.forEach((row) => {
    const key = row.dataset.flag;
    if (!key) return;
    const switchNode = row.querySelector(".switch");
    if (!switchNode) return;

    row.addEventListener("click", () => {
      const enabled = !switchNode.classList.contains("on");
      switchNode.classList.toggle("on", enabled);
      state.flags[key] = enabled;
      syncSettingsToggles();

      const label = row.querySelector("span")?.textContent || key;
      addLog(`策略更新: ${label} -> ${enabled ? "开启" : "关闭"}`, "INFO", "system");
      refresh();
    });
  });
}

function applySettingsToForm() {
  setValue("setSignal", state.isDevMode ? state.settings.signal : maskSignalUrl(state.settings.signal));
  setValue("setTimeout", state.settings.timeout);
}

async function loadRuntimeMode() {
  try {
    state.isDevMode = !!(await invoke("is_dev_mode"));
  } catch {
    state.isDevMode = false;
  }
}

/// 在非开发模式下隐藏信令服务器地址等敏感配置项
function applyDevVisibility() {
  const hidden = !state.isDevMode;
  // Host 控制区信令地址
  const hostSignalField = $("hostSignalField");
  if (hostSignalField) hostSignalField.style.display = hidden ? "none" : "";
  // 设置页信令地址
  const setSignalField = $("setSignalField");
  if (setSignalField) setSignalField.style.display = hidden ? "none" : "";
}

async function loadConfig() {
  try {
    const cfg = await invoke("load_config");
    state.config = cfg;
    if (cfg.signal_server) state.settings.signal = cfg.signal_server;
    state.flags.upnp = !!cfg.enable_upnp;
    if (cfg.last_room_code) setValue("joinCode", cfg.last_room_code);
    addLog("配置已加载", "INFO", "system");
  } catch (err) {
    addLog(`加载配置失败，使用默认配置: ${err}`, "WARN", "system");
  }
  syncSettingsToggles();
  applySettingsToForm();
}

async function saveSettings() {
  const signalInput = $("setSignal")?.value.trim() || "";
  const signal = signalInput || DEFAULT_SETTINGS.signal;
  const timeout = Number($("setTimeout")?.value);

  if (!signal) {
    addLog("保存失败: 信令地址不能为空", "ERROR", "system");
    toast("保存失败：信令地址不能为空", "error");
    return;
  }
  if (!Number.isInteger(timeout) || timeout < 2 || timeout > 60) {
    addLog("保存失败: 超时阈值应在 2-60 秒", "ERROR", "system");
    toast("保存失败：超时阈值应在 2-60 秒", "error");
    return;
  }

  // 用户把信令地址改成了非官方地址：必须先完成强确认（勾选风险复选框）才能生效保存。
  // "改回官方地址"这个方向不涉及离开官方网络的风险，不需要走这个确认流程。
  const changingToCustom = signal !== state.settings.signal && !isOfficialSignal(signal);
  if (changingToCustom) {
    const confirmed = await confirmCustomServer();
    if (!confirmed) {
      addLog("已取消切换到自定义信令服务器", "WARN", "system");
      return;
    }
  }

  state.settings = { signal, timeout };

  const cfg = state.config || {
    signal_server: signal,
    username: `玩家${Math.floor(Math.random() * 9000 + 1000)}`,
    last_room_code: state.roomCode,
    enable_upnp: state.flags.upnp,
    enable_stun: true,
    dev_mode: false
  };

  cfg.signal_server = signal;
  cfg.last_room_code = state.roomCode;
  cfg.enable_upnp = !!state.flags.upnp;
  cfg.enable_stun = true;
  state.config = cfg;
  syncSettingsToggles();

  try {
    await invoke("save_config", { config: cfg });
    addLog("设置已保存", "INFO", "system");
    toast("设置已保存", "success");
  } catch (err) {
    addLog(`保存设置失败: ${err}`, "ERROR", "system");
    toast(`保存设置失败: ${err}`, "error", 2200);
  }

  applySettingsToForm();
  refresh();
}

function resetSettings() {
  state.settings = { ...DEFAULT_SETTINGS };
  state.flags.upnp = true;
  state.flags.preferIpv6 = false;
  state.flags.verbose = true;
  state.flags.autoConnect = true;
  state.flags.smoothCharts = false;

  syncSettingsToggles();
  applySettingsToForm();
  addLog("设置已恢复默认", "WARN", "system");
  toast("设置已恢复默认", "success");
  refresh();
}

async function runDiagnosis() {
  if (state.diagBusy) return;
  state.diagBusy = true;
  startDiagEstimateTicker();
  setDiagProgress(3, "初始化诊断...", 16);

  const runBtn = $("diagRunBtn");
  if (runBtn) {
    runBtn.disabled = true;
    runBtn.textContent = "检测中...";
  }

  state.diag.nat = "检测中...";
  state.diag.mapping = "检测中...";
  state.diag.filtering = "检测中...";
  state.diag.portPattern = "检测中...";
  state.diag.confidence = "检测中...";
  state.diag.public = "检测中...";
  state.diag.upnp = "检测中...";
  state.diag.ipv6 = "检测中...";
  state.diag.priority = "检测中...";
  state.diagRounds = 0;
  state.diagMappings = [
    { server: "检测中", mapping: "请稍候...", rtt: 0 }
  ];
  addLog("开始网络诊断...", "INFO", "system");
  toast("网络诊断启动", "success");
  refresh();

  try {
    const info = await invoke("get_network_info");
    state.diag.nat = info.nat_type || "未知";
    state.diag.mapping = info.mapping_behavior || "--";
    state.diag.filtering = info.filtering_behavior || "--";
    state.diag.portPattern = info.port_pattern || "--";
    state.diagRounds = Number(info.diagnostics_rounds || 0);
    state.diag.confidence = info.confidence || "--";
    state.diag.public = `${info.external_ip || "--"}:${info.external_port || "--"}`;
    state.diag.upnp = info.upnp ? `可用 (${info.upnp_port || "-"})` : "不可用";
    state.diag.ipv6 = info.ipv6 ? `可用 (${info.ipv6_addr || "--"})` : "不可用";
    state.diag.priority = info.network_priority || "--";

    const details = Array.isArray(info.stun_details) ? info.stun_details : [];
    if (details.length) {
      state.diagMappings = details.map((d) => ({
        server: `R${Number(d.round || 0)}-${String(d.socket || "?")} ${d.server || "STUN"}`,
        mapping: d.mapping || "--",
        rtt: Number(d.rtt_ms || 0)
      }));
    } else {
      const mappings = Array.isArray(info.stun_mappings) ? info.stun_mappings : [];
      state.diagMappings = mappings.map((m, idx) => {
        const [, addr = m] = String(m).split("→");
        return {
          server: `STUN-${idx + 1}`,
          mapping: addr,
          rtt: rand(18, 90)
        };
      });
    }

    setDiagProgress(100, "诊断完成", 0);
    addLog(`网络诊断完成: ${state.diag.nat} / ${state.diag.filtering}`, "INFO", "system");
    toast(`网络诊断完成：${state.diag.nat}`, "success");
  } catch (err) {
    state.diag.nat = "检测失败";
    state.diag.mapping = "--";
    state.diag.filtering = "--";
    state.diag.portPattern = "--";
    state.diag.confidence = "--";
    state.diag.public = "--";
    state.diag.upnp = "--";
    state.diag.ipv6 = "--";
    state.diag.priority = "--";
    state.diagMappings = [];
    setDiagProgress(0, "检测失败", 0);
    addLog(`网络诊断失败: ${err}`, "ERROR", "system");
    toast(`网络诊断失败: ${err}`, "error", 2200);
  } finally {
    stopDiagEstimateTicker();
    state.diagBusy = false;
    if (runBtn) {
      runBtn.disabled = false;
      runBtn.textContent = "开始检测";
    }
    refresh();
  }
}

async function copyDiagResult() {
  const publicInfo = state.isDevMode ? state.diag.public : maskIpEndpoint(state.diag.public);
  const text = [
    `NAT: ${state.diag.nat}`,
    `Mapping: ${state.diag.mapping}`,
    `Filtering: ${state.diag.filtering}`,
    `Port Pattern: ${state.diag.portPattern}`,
    `Confidence: ${state.diag.confidence}`,
    `Public: ${publicInfo}`,
    `UPnP: ${state.diag.upnp}`,
    `IPv6: ${state.diag.ipv6}`,
    `Priority: ${state.diag.priority}`
  ].join("\n");

  try {
    await navigator.clipboard.writeText(text);
    addLog("诊断结果已复制", "INFO", "system");
    toast("诊断结果已复制", "success");
  } catch {
    addLog("复制诊断结果失败", "WARN", "system");
    toast("复制失败，请检查系统剪贴板权限", "error");
  }
}

async function openHostRoom() {
  if (state.isHost && state.roomCode) {
    addLog("当前已是 Host 房间", "WARN", "host");
    toast("当前已是 Host 房间", "warn");
    return;
  }

  if (!(await ensureConnected())) {
    toast("创建失败：信令连接不可用", "error");
    return;
  }

  try {
    await invoke("reset_tunnel_stats");
    clearRealtimeStats();
    await invoke("create_room");
    state.isHost = true;
    state.guestActive = false;
    state.roomCode = null;
    state.guest.mode = "等待玩家加入";
    state.guest.addr = "--";
    setText("roomCode", "------");
    addLog("请求创建房间", "INFO", "host");
    toast("房间创建请求已发送", "success");
  } catch (err) {
    addLog(`创建房间失败: ${err}`, "ERROR", "host");
    toast(`创建房间失败: ${err}`, "error", 2200);
  }
}

async function closeHostRoom() {
  try {
    await invoke("close_room");
    await invoke("reset_tunnel_stats");
    if (state.peerUserId) {
      await invoke("remove_connection", { userId: state.peerUserId }).catch(() => {});
    }

    clearRealtimeStats();
    state.isHost = false;
    state.guestActive = false;
    state.roomCode = null;
    state.peerUserId = null;
    state.relayInfo = null;
    state.subnet = null;
    state.guest.mode = "待连接";
    state.guest.addr = "--";
    setText("roomCode", "------");
    resetProgress();
    addLog("房间已关闭，统计已清空", "WARN", "host");
    toast("房间已关闭，统计已清空", "success");
  } catch (err) {
    addLog(`关闭房间失败: ${err}`, "ERROR", "host");
    toast(`关闭房间失败: ${err}`, "error", 2200);
  }
}

async function joinGuestRoom() {
  if (state.isHost) {
    addLog("当前是 Host 房间，请先关闭房间再加入", "WARN", "guest");
    toast("请先关闭当前 Host 房间", "warn");
    return;
  }

  const code = $("joinCode")?.value.trim().toUpperCase() || "";
  if (!code || code.length < 4) {
    addLog("加入失败: 配对码无效", "WARN", "guest");
    toast("加入失败：配对码无效", "error");
    return;
  }
  if (!(await ensureConnected())) {
    toast("加入失败：信令连接不可用", "error");
    return;
  }

  try {
    await invoke("reset_tunnel_stats");
    clearRealtimeStats();
    await invoke("join_room", { roomCode: code });
    state.isHost = false;
    state.roomCode = code;
    state.guest.mode = "连接中";
    resetProgress();
    setText("progressCode", code);
    setProgress(20);
    addLog(`正在加入房间: ${code}`, "INFO", "guest");
    toast(`正在加入房间 ${code}`, "success");
  } catch (err) {
    addLog(`加入房间失败: ${err}`, "ERROR", "guest");
    toast(`加入房间失败: ${err}`, "error", 2200);
  }
}

async function leaveGuestRoom() {
  try {
    await invoke("leave_room");
    await invoke("reset_tunnel_stats");
    if (state.peerUserId) {
      await invoke("remove_connection", { userId: state.peerUserId }).catch(() => {});
    }

    clearRealtimeStats();
    state.isHost = false;
    state.guestActive = false;
    state.roomCode = null;
    state.peerUserId = null;
    state.relayInfo = null;
    state.subnet = null;
    state.guest.mode = "待连接";
    state.guest.addr = "--";
    setText("roomCode", "------");
    resetProgress();
    addLog("已离开房间，统计已清空", "WARN", "guest");
    toast("已离开房间，统计已清空", "success");
  } catch (err) {
    addLog(`离开房间失败: ${err}`, "ERROR", "guest");
    toast(`离开房间失败: ${err}`, "error", 2200);
  }
}

function bindActions() {
  $("confirmCancelBtn")?.addEventListener("click", () => closeConfirmDialog(false));
  $("confirmAcceptBtn")?.addEventListener("click", () => closeConfirmDialog(true));
  $("confirmModal")?.addEventListener("click", (event) => {
    if (event.target === event.currentTarget) closeConfirmDialog(false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeConfirmDialog(false);
  });

  // 自建/第三方信令服务器风险确认弹窗：必须勾选复选框后"确认切换"按钮才可点击
  $("customServerAckBox")?.addEventListener("change", (event) => {
    const acceptBtn = $("customServerAcceptBtn");
    if (acceptBtn) acceptBtn.disabled = !event.target.checked;
  });
  $("customServerCancelBtn")?.addEventListener("click", () => closeCustomServerDialog(false));
  $("customServerAcceptBtn")?.addEventListener("click", () => {
    if ($("customServerAcceptBtn")?.disabled) return;
    closeCustomServerDialog(true);
  });
  $("customServerModal")?.addEventListener("click", (event) => {
    if (event.target === event.currentTarget) closeCustomServerDialog(false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeCustomServerDialog(false);
  });

  $("requestFixedIpBtn")?.addEventListener("click", async () => {
    if (state.fixedHostIp) {
      const accepted = await confirmInApp({
        title: "放弃固定 IP",
        message: `放弃后，${state.fixedHostIp} 将被释放，后续创建房间会恢复使用动态 IP。`,
        confirmText: "确认放弃"
      });
      if (!accepted) return;
      state.fixedIpBusy = true;
      refresh();
      try {
        await invoke("release_fixed_host_ip");
      } catch (err) {
        state.fixedIpBusy = false;
        addLog(`放弃固定 IP 失败: ${err}`, "ERROR", "host");
        toast(`放弃固定 IP 失败: ${err}`, "error", 2200);
        refresh();
      }
      return;
    }

    if (!(await ensureConnected())) return;
    state.fixedIpBusy = true;
    refresh();
    try {
      await invoke("request_fixed_host_ip");
    } catch (err) {
      state.fixedIpBusy = false;
      addLog(`申请固定 IP 失败: ${err}`, "ERROR", "host");
      toast(`申请固定 IP 失败: ${err}`, "error", 2200);
      refresh();
    }
  });

  $("hostMainBtn")?.addEventListener("click", async () => {
    if (state.isHost) {
      await closeHostRoom();
    } else {
      await openHostRoom();
    }
    refresh();
  });

  $("copyCodeBtn")?.addEventListener("click", async () => {
    const code = $("roomCode")?.textContent?.trim() || "";
    if (!code || code === "------") {
      toast("当前没有可复制的配对码", "warn");
      return;
    }
    try {
      await navigator.clipboard.writeText(code);
      addLog(`已复制配对码: ${code}`, "INFO", "host");
      toast("配对码已复制", "success");
    } catch {
      addLog("复制配对码失败", "WARN", "host");
      toast("复制失败，请检查系统剪贴板权限", "error");
    }
  });

  $("joinMainBtn")?.addEventListener("click", async () => {
    const inGuestSession = !state.isHost && !!state.roomCode;
    if (inGuestSession) {
      await leaveGuestRoom();
    } else {
      await joinGuestRoom();
    }
    refresh();
  });

  $("copyAddrBtn")?.addEventListener("click", async () => {
    if (!state.guestActive) {
      toast("尚未建立连接，暂无可复制地址", "warn");
      return;
    }
    // 如果有虚拟子网，复制 Host 虚拟 IP；否则复制当前地址
    const addr = state.guest.addr;
    if (!addr || addr.includes("----")) {
      toast("TUN is not ready; no virtual address is available", "warn");
      return;
    }
    try {
      await navigator.clipboard.writeText(addr);
      addLog(`已复制连接地址: ${addr}`, "INFO", "guest");
      toast("连接地址已复制", "success");
    } catch {
      addLog("复制连接地址失败", "WARN", "guest");
      toast("复制失败，请检查系统剪贴板权限", "error");
    }
  });

  $("diagRunBtn")?.addEventListener("click", runDiagnosis);
  $("diagCopyBtn")?.addEventListener("click", copyDiagResult);

  $("saveSettingsBtn")?.addEventListener("click", saveSettings);
  $("resetSettingsBtn")?.addEventListener("click", resetSettings);

  ["logSearchInput", "logLevelFilter", "logModuleFilter"].forEach((id) => {
    const el = $(id);
    if (!el) return;
    el.addEventListener(id === "logSearchInput" ? "input" : "change", renderLogs);
  });

  $("logClearBtn")?.addEventListener("click", () => {
    state.logs = [];
    renderLogs();
    renderHomeSummary();
  });

  $("themeBtn")?.addEventListener("click", () => {
    const isLight = document.body.classList.toggle("theme-light");
    state.theme = isLight ? "light" : "dark";
    setText("themeBtn", isLight ? "切换深色" : "切换浅色");
    addLog(isLight ? "切换到浅色模式" : "切换到深色模式", "INFO", "system");
    refresh();
  });

  $("simBtn")?.addEventListener("click", () => {
    state.running = !state.running;
    setText("simBtn", state.running ? "暂停采样" : "恢复采样");
    addLog(state.running ? "恢复实时采样" : "暂停实时采样", "WARN", "system");
    refresh();
  });
}

async function setupEventListeners() {
  await listen("diag:progress", (event) => {
    const payload = event.payload || {};
    setDiagProgress(
      Number(payload.progress || 0),
      String(payload.stage || "检测中..."),
      Number(payload.eta_seconds || 0)
    );
    if (Number(payload.progress || 0) >= 100) {
      stopDiagEstimateTicker();
    }
    refresh();
  });

  await listen("signal:status", (event) => {
    const payload = event.payload || {};
    state.connected = payload.state === "已连接";
    state.sessionId = payload.session_id || state.sessionId;
    if (Object.prototype.hasOwnProperty.call(payload, "room_code")) {
      const serverCode = payload.room_code || null;
      if (serverCode) {
        state.roomCode = serverCode;
      } else if (!state.isHost && !state.guestActive) {
        state.roomCode = null;
        clearRealtimeStats();
        state.isHost = false;
        state.peerUserId = null;
        state.relayInfo = null;
        state.subnet = null;
        state.guest.mode = "待连接";
        state.guest.addr = "--";
        resetProgress();
        setText("roomCode", "------");
      }
    }
    state.guest.id = state.sessionId || state.guest.id;
    refresh();
  });

  await listen("signal:welcome", (event) => {
    const payload = event.payload || {};
    state.connected = true;
    state.authenticated = false;
    state.sessionId = payload.session_id || state.sessionId;
    state.guest.id = state.sessionId || state.guest.id;
    addLog(`信令已连接: ${shortId(state.sessionId)}`, "INFO", "system");
    refresh();
  });

  await listen("signal:auth_ok", (event) => {
    const payload = event.payload || {};
    state.authenticated = true;
    addLog(`认证成功: ${payload.user_id || "--"}`, "INFO", "system");
    refresh();
  });

  await listen("signal:auth_failed", (event) => {
    const payload = event.payload || {};
    state.authenticated = false;
    addLog(`认证失败: ${payload.reason || "未知原因"}`, "ERROR", "system");
    refresh();
  });

  await listen("signal:fixed_host_ip_status", (event) => {
    const payload = event.payload || {};
    state.fixedHostIp = payload.enabled ? (payload.virtual_ip || null) : null;
    state.fixedIpBusy = false;
    addLog(
      state.fixedHostIp ? `固定 IP 已启用: ${state.fixedHostIp}` : "当前使用动态 IP",
      "INFO",
      "host"
    );
    refresh();
  });

  await listen("signal:room_created", (event) => {
    const payload = event.payload || {};
    state.isHost = true;
    state.guestActive = false;
    state.roomCode = payload.room_code || state.roomCode;
    state.subnet = payload.subnet || state.subnet;
    state.virtualIp = payload.virtual_ip || state.virtualIp;
    state.hostVirtualIp = payload.virtual_ip || state.hostVirtualIp;
    setText("roomCode", state.roomCode || "------");
    if (state.roomCode) setValue("joinCode", state.roomCode);
    state.guest.mode = "等待玩家加入";
    addLog(`房间创建成功: ${state.roomCode}`, "INFO", "host");
    toast(`房间已创建: ${state.roomCode}`, "success");
    refresh();
  });

  await listen("signal:join_ok", async (event) => {
    const payload = event.payload || {};
    state.isHost = false;
    state.roomCode = payload.room_code || state.roomCode;
    state.subnet = payload.subnet || null;
    state.virtualIp = payload.virtual_ip || null;
    state.hostVirtualIp = payload.host_virtual_ip || (state.subnet ? `${state.subnet}.1` : null);

    const peerIdRaw = String(payload.host_session_id || "peer");
    const selfId = state.sessionId || "";
    if (peerIdRaw === selfId || shortId(peerIdRaw) === shortId(selfId)) {
      addLog(`忽略本机连接 ID: ${peerIdRaw}`, "WARN", "guest");
      toast("检测到本机 ID，已忽略无效连接", "warn");
      return;
    }
    state.peerUserId = peerIdRaw;

    state.guest.addr = "--";
    state.guest.mode = "连接中";

    setText("progressCode", state.roomCode || "------");
    setProgress(35);

    await invoke("add_connection", { userId: peerIdRaw, connectionMode: "p2p" }).catch(() => {});
    if (isTauriMode) await startPunch(peerIdRaw);

    addLog(`加入房间成功: ${state.roomCode}`, "INFO", "guest");
    toast(`已加入房间 ${state.roomCode}`, "success");
    refresh();
  });

  await listen("signal:join_failed", (event) => {
    const payload = event.payload || {};
    clearRealtimeStats();
    state.isHost = false;
    state.guestActive = false;
    state.roomCode = null;
    state.peerUserId = null;
    state.relayInfo = null;
    state.subnet = null;
    state.guest.mode = "待连接";
    state.guest.addr = "--";
    setText("roomCode", "------");
    resetProgress();
    addLog(`加入失败: ${payload.reason || "未知"}`, "ERROR", "guest");
    toast(`加入失败: ${payload.reason || "未知"}`, "error", 2200);
    refresh();
  });

  await listen("signal:peer_joined", async (event) => {
    const payload = event.payload || {};
    const peerIdRaw = String(payload.peer_session_id || "peer");
    const selfId = state.sessionId || "";
    if (peerIdRaw === selfId || shortId(peerIdRaw) === shortId(selfId)) {
      addLog(`忽略本机 PeerJoined: ${peerIdRaw}`, "WARN", "host");
      return;
    }
    state.peerUserId = peerIdRaw;
    await invoke("add_connection", { userId: peerIdRaw, connectionMode: "p2p" }).catch(() => {});
    addLog(`玩家加入: ${shortId(peerIdRaw)}`, "INFO", "host");
    toast(`玩家已加入: ${shortId(peerIdRaw)}`, "success");
    if (isTauriMode) await startPunch(peerIdRaw);
    refresh();
  });

  await listen("signal:peer_left", async (event) => {
    const payload = event.payload || {};
    const peerIdRaw = String(payload.peer_session_id || state.peerUserId || "peer");
    await invoke("remove_connection", { userId: peerIdRaw }).catch(() => {});
    if (state.peerUserId === peerIdRaw) state.peerUserId = null;
    addLog(`玩家离开: ${shortId(peerIdRaw)}`, "WARN", "host");
    toast(`玩家离开: ${shortId(peerIdRaw)}`, "warn");
    refresh();
  });

  await listen("signal:room_closed", (event) => {
    const payload = event.payload || {};
    clearRealtimeStats();
    state.isHost = false;
    state.roomCode = null;
    state.peerUserId = null;
    state.guestActive = false;
    state.relayInfo = null;
    state.subnet = null;
    state.guest.mode = "待连接";
    state.guest.addr = "--";
    setText("roomCode", "------");
    resetProgress();
    addLog(`房间已关闭并清空统计: ${payload.reason || "--"}`, "WARN", "system");
    toast("房间已关闭", "warn");
    refresh();
  });

  await listen("signal:error", (event) => {
    const payload = event.payload || {};
    addLog(`服务端错误: ${payload.message || "未知错误"}`, "ERROR", "system");
    refresh();
  });

  // QUIC 中继预分配就绪
  await listen("signal:relay_pre_allocated", async (event) => {
    const payload = event.payload || {};
    state.relayInfo = payload;
    addLog("QUIC 中继通道预分配就绪", "INFO", "system");
    refresh();
  });

  // ICE：对端候选已到达（Rust 侧自动触发打洞，前端仅记录）
  await listen("signal:peer_candidates", async (event) => {
    if (state.isDevMode) {
      const candidates = (event.payload && event.payload.candidates) || [];
      addLog(`ICE 候选收到: ${candidates.length} 个，Rust 侧自动触发连通性检测`, "INFO", "system");
    }
  });

  // QUIC 静默升级完成通知
  await listen("tunnel:upgraded", async (event) => {
    const mode = event.payload || "relay";
    addLog(`QUIC 通道静默升级完成，当前模式: ${mode}`, "INFO", "system");
  });

  await listen("signal:relay_ready", async (event) => {
    const payload = event.payload || {};
    const payloadRoomCode = String(payload.room_code || "").trim().toUpperCase();
    const currentRoomCode = String(state.roomCode || "").trim().toUpperCase();

    if (!currentRoomCode) {
      return;
    }
    if (payloadRoomCode && payloadRoomCode !== currentRoomCode) {
      return;
    }

    state.relayInfo = payload;
    addLog("QUIC 通道信息已就绪", "INFO", "system");
    setProgress(Math.max(joinFlow.progress, 88));
    if (isTauriMode && state.roomCode && !state.guest.mode.includes("P2P")) {
      await startRelayTunnel();
    }
    refresh();
  });

  await listen("punch:phase", async (event) => {
    const phase = event.payload;

    if (typeof phase === "string") {
      if (phase === "Probing") setProgress(Math.max(joinFlow.progress, 25));
      else if (phase === "WaitingPeer") setProgress(Math.max(joinFlow.progress, 50));
      else if (phase === "Punching") setProgress(Math.max(joinFlow.progress, 75));
      return;
    }

    if (phase?.Success) {
      state.guestActive = true;
      state.guest.mode = "P2P 直连";
      state.guest.ping = Number(phase.Success.latency_ms || state.guest.ping || 0);
      setProgress(100);
      addLog(`P2P 直连成功: ${phase.Success.latency_ms}ms`, "INFO", "guest");
      refresh();
      return;
    }

    if (phase?.Failed) {
      addLog(`打洞失败: ${phase.Failed.reason}`, "WARN", "guest");
      if (isTauriMode && state.relayInfo) {
        await startRelayTunnel();
        setProgress(100);
      }
      refresh();
    }
  });

  await listen("tunnel:started", async (event) => {
    const mode = String(event.payload || "");
    state.guest.mode = modeToText(mode);
    if (!state.isHost) state.guestActive = true;
    setProgress(100);
    addLog(`连接已建立: ${state.guest.mode}`, "INFO", state.isHost ? "host" : "guest");

    // 非房主侧自动启动 TUN 虚拟网卡
    if (isTauriMode && !state.isHost && state.subnet) {
      try {
        await invoke("start_tun_bridge");
        addLog(`虚拟网卡启动请求已发送 (${state.subnet}.0/24)`, "INFO", "system");
      } catch (err) {
        addLog(`虚拟网卡启动失败: ${err}（不影响隧道使用）`, "WARN", "system");
      }
    } else if (isTauriMode && !state.isHost) {
      addLog("子网信息未就绪，跳过虚拟网卡自动启动", "WARN", "system");
    }
    refresh();
  });

  await listen("tunnel:failed", async (event) => {
    const payload = event.payload || {};
    const mode = String(payload.mode || "relay");
    const reason = String(payload.reason || "未知原因");
    addLog(`QUIC 连接失败 (${mode}): ${reason}`, "ERROR", "system");
    toast(`QUIC 连接失败: ${reason}`, "error", 2200);
    refresh();
  });

  // TUN 虚拟网卡就绪
  await listen("tun:failed", (event) => {
    const reason = String(event.payload || "TUN startup failed");
    state.guest.addr = "--";
    state.guest.mode = "TUN startup failed";
    addLog(`TUN startup failed: ${reason}`, "ERROR", "system");
    toast(`TUN startup failed: ${reason}`, "error", 3000);
    refresh();
  });

  await listen("tun:ready", (event) => {
    const payload = event.payload || {};
    const myIp = String(payload.my_ip || "");
    const hostIp = String(payload.host_ip || "");
    if (myIp) {
      state.guest.addr = `${hostIp}`;
      state.guest.mode = `P2P 直连 (TUN)`;
      addLog(`虚拟网卡已就绪: my=${myIp}, host=${hostIp}`, "INFO", "system");
      toast(`虚拟 IP: ${myIp}，Host: ${hostIp}`, "success");
      refresh();
    }
  });
}

async function bootstrap() {
  document.addEventListener("contextmenu", (event) => event.preventDefault());

  if (window.__TAURI__) {
    document.body.classList.add("tauri-native-frame");
  }

  await loadRuntimeMode();
  applyDevVisibility();
  bindActions();
  bindSettingsToggles();
  resetProgress();
  setText("simBtn", "暂停采样");
  await loadConfig();
  await setupEventListeners();

  // 动态读取版本号
  if (isTauriMode) {
    try {
      const ver = await window.__TAURI__.app.getVersion();
      const el = document.getElementById("appVersion");
      if (el) el.textContent = `v${ver} (${el.dataset.build})`;
    } catch (_) {}
  }

  if (state.flags.autoConnect) {
    await ensureConnected();
  }

  window.addEventListener("resize", refresh);

  setInterval(() => {
    state.uptime += 1;
    if (!state.running) {
      refresh();
      return;
    }
    pollStats();
  }, 1000);

  addLog("UI 已启动（新界面已接入主程序）", "INFO", "system");
  refresh();

  // WebView2 完成渲染后再显示窗口，避免部分 Win11 机器启动黑屏
  if (isTauriMode) {
    try {
      await invoke("show_main_window");
    } catch (_) {}
  }
}

document.addEventListener("DOMContentLoaded", bootstrap);
