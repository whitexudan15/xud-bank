// ============================================================
// XUD-BANK — secureDataMonitor/static/js/ws_alerts.js
// Client WebSocket — Alertes temps réel
// ============================================================

let ws = null;
let reconnectDelay = 3000;

function initWS(url) {
  const dot    = document.getElementById('ws-dot');
  const status = document.getElementById('ws-status');
  const feed   = document.getElementById('alert-feed');

  function connect() {
    ws = new WebSocket(url);

    ws.onopen = () => {
      if (dot)    { dot.classList.add('connected'); }
      if (status) { status.textContent = 'Connecté — alertes en temps réel'; }
      reconnectDelay = 3000;
    };

    ws.onmessage = (evt) => {
      const msg = JSON.parse(evt.data);

      if (msg.type === 'init') {
        // Mise à jour stats initiales
        updateStat('stat-unresolved', msg.stats.unresolved_alerts);
        updateStat('stat-total-events', msg.stats.total_events);

      } else if (msg.type === 'new_alert') {
        prependAlert(msg.alert, feed);
        // Incrémente compteur alertes
        const cnt = document.getElementById('alert-count');
        if (cnt) cnt.textContent = parseInt(cnt.textContent || 0) + 1;
        // Notification visuelle
        showToast(msg.alert);

      } else if (msg.type === 'new_event') {
        prependEvent(msg.event);

      } else if (msg.type === 'heartbeat') {
        if (status) {
          status.textContent = `Connecté — ${msg.connected_clients} client(s)`;
        }
      }
    };

    ws.onclose = () => {
      if (dot)    { dot.classList.remove('connected'); }
      if (status) { status.textContent = `Reconnexion dans ${reconnectDelay/1000}s...`; }
      setTimeout(connect, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 2, 30000);
    };

    ws.onerror = () => { ws.close(); };
  }

  // Ping heartbeat côté client
  setInterval(() => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'ping' }));
    }
  }, 25000);

  connect();
}

function updateStat(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

const LEVEL_COLORS = {
  LOW: '#16A34A', MEDIUM: '#D97706', HIGH: '#DC2626', CRITICAL: '#7C3AED'
};

function prependAlert(alert, feed) {
  if (!feed) return;
  const color = LEVEL_COLORS[alert.alert_level] || '#6B7280';
  const time  = new Date(alert.timestamp).toLocaleTimeString('fr-FR');
  const div   = document.createElement('div');
  div.className = 'd-flex align-items-start gap-2 mb-2 p-2 rounded';
  div.style.background = '#F8FAFC';
  div.innerHTML = `
    <span class="badge text-white mt-1" style="background:${color};min-width:72px;">${alert.alert_level}</span>
    <div>
      <p class="small mb-0">${alert.message.substring(0,80)}</p>
      <small class="text-muted">${time}</small>
    </div>`;
  feed.prepend(div);
  // Limite à 20 entrées
  while (feed.children.length > 20) feed.removeChild(feed.lastChild);
}

function prependEvent(event) {
  const tbody = document.getElementById('events-feed');
  if (!tbody) return;
  const color = LEVEL_COLORS[event.severity] || '#6B7280';
  const time  = new Date(event.timestamp).toLocaleTimeString('fr-FR');
  const tr    = document.createElement('tr');
  tr.innerHTML = `
    <td><span class="badge text-white" style="background:${color};font-size:.65rem;">${event.event_type.substring(0,14)}</span></td>
    <td class="small text-muted">${event.ip_address}</td>
    <td class="small text-muted">${time}</td>`;
  tbody.prepend(tr);
  while (tbody.children.length > 15) tbody.removeChild(tbody.lastChild);
}

function showToast(alert) {
  const color = LEVEL_COLORS[alert.alert_level] || '#6B7280';
  const toast = document.createElement('div');
  toast.style.cssText = `
    position:fixed;top:20px;right:20px;z-index:9999;
    background:#fff;border-left:4px solid ${color};
    border-radius:8px;padding:12px 16px;min-width:280px;
    box-shadow:0 4px 12px rgba(0,0,0,.15);
    animation:slideIn .3s ease;`;
  toast.innerHTML = `
    <div class="d-flex align-items-center gap-2">
      <span class="badge text-white" style="background:${color};">${alert.alert_level}</span>
      <span class="small fw-semibold">Nouvelle alerte</span>
    </div>
    <p class="small text-muted mb-0 mt-1">${alert.message.substring(0,80)}</p>`;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 5000);
}