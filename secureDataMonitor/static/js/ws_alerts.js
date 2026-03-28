// ============================================================
// XUD-BANK — secureDataMonitor/static/js/ws_alerts.js
// Client WebSocket — Alertes temps réel
// ============================================================

let ws = null;
let reconnectDelay = 3000;

function initWS(url) {
  const dot = document.getElementById('ws-dot');
  const status = document.getElementById('ws-status');
  const feed = document.getElementById('alert-feed');

  function connect() {
    ws = new WebSocket(url);

    ws.onopen = () => {
      if (dot) { dot.classList.add('connected'); }
      if (status) { status.textContent = 'Connecté — temps réel'; }
      reconnectDelay = 3000;
    };

    ws.onmessage = (evt) => {
      console.log("WS reçu:", evt.data);
      const msg = JSON.parse(evt.data);

      if (msg.type === 'init') {
        // Mise à jour stats initiales
        updateStat('stat-unresolved', msg.stats.unresolved_alerts);
        updateStat('stat-total-events', msg.stats.total_events);

      } else if (msg.type === 'new_alert') {
        prependAlert(msg.alert, feed);
        // Incrémente compteur alertes actives
        const cnt = document.getElementById('alert-count');
        if (cnt) cnt.textContent = parseInt(cnt.textContent || 0) + 1;
        const statUnresolved = document.getElementById('stat-unresolved');
        if (statUnresolved) statUnresolved.textContent = parseInt(statUnresolved.textContent || 0) + 1;
        showToast(msg.alert);

      } else if (msg.type === 'new_event') {
        prependEvent(msg.event);
        // Incrémente compteur total événements
        const statTotal = document.getElementById('stat-total-events');
        if (statTotal) statTotal.textContent = parseInt(statTotal.textContent || 0) + 1;
        // Incrémente HIGH+ si applicable
        if (msg.event.severity === 'HIGH' || msg.event.severity === 'CRITICAL') {
          const statHigh = document.getElementById('stat-high');
          if (statHigh) statHigh.textContent = parseInt(statHigh.textContent || 0) + 1;
        }
        if (msg.event.severity === 'CRITICAL') {
          const statCrit = document.getElementById('stat-critical');
          if (statCrit) statCrit.textContent = parseInt(statCrit.textContent || 0) + 1;
        }

      } else if (msg.type === 'heartbeat') {
        if (status) {
          status.textContent = `Connecté — ${msg.connected_clients} client(s)`;
        }
      }
    };

    ws.onclose = () => {
      if (dot) { dot.classList.remove('connected'); }
      if (status) { status.textContent = `Reconnexion dans ${reconnectDelay / 1000}s...`; }
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
  const colors = {
    LOW: 'var(--s-low)', MEDIUM: 'var(--s-med)',
    HIGH: 'var(--s-hi)', CRITICAL: 'var(--s-crit)'
  };
  const time = new Date(alert.timestamp).toLocaleTimeString('fr-FR');
  const div = document.createElement('div');
  div.style.cssText = `display:flex;align-items:flex-start;gap:.6rem;margin-bottom:.55rem;
    padding:.65rem .8rem;background:rgba(255,255,255,.025);
    border-radius:9px;border:1px solid var(--bdr2);`;
  div.innerHTML = `
    <span class="bdg bdg-${alert.alert_level}" style="min-width:68px;justify-content:center;flex-shrink:0;">
      ${alert.alert_level}
    </span>
    <div>
      <p style="font-size:.8rem;color:var(--t1);margin:0 0 .1rem;">${alert.message.substring(0, 80)}</p>
      <small style="color:var(--t3);font-size:.7rem;">${time}</small>
    </div>`;
  feed.prepend(div);
  while (feed.children.length > 20) feed.removeChild(feed.lastChild);
}

function prependEvent(event) {
  const tbody = document.getElementById('events-feed');
  if (!tbody) return;
  const time = new Date(event.timestamp).toLocaleTimeString('fr-FR');
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td style="padding-left:1rem;">
      <span class="bdg bdg-${event.severity}">${event.event_type.substring(0, 14)}</span>
    </td>
    <td style="font-size:.78rem;color:var(--t2);font-family:monospace;">${event.ip_address}</td>
    <td style="font-size:.78rem;color:var(--t3);">${time}</td>`;
  tbody.prepend(tr);
  while (tbody.children.length > 15) tbody.removeChild(tbody.lastChild);
}

function showToast(alert) {
  const colors = {
    LOW: 'var(--s-low)', MEDIUM: 'var(--s-med)',
    HIGH: 'var(--s-hi)', CRITICAL: 'var(--s-crit)'
  };
  const color = colors[alert.alert_level] || 'var(--t2)';
  const toast = document.createElement('div');
  toast.style.cssText = `
    position:fixed;top:72px;right:20px;z-index:9999;
    background:var(--bg-card);
    border:1px solid var(--bdr2);
    border-left:4px solid ${color};
    border-radius:12px;padding:14px 18px;min-width:300px;
    box-shadow:0 8px 32px rgba(0,0,0,.4);
    backdrop-filter:blur(20px);
    animation:fadeSlideUp .3s var(--ease);`;
  toast.innerHTML = `
    <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.3rem;">
      <span class="bdg bdg-${alert.alert_level}">${alert.alert_level}</span>
      <span style="font-size:.82rem;font-weight:700;color:var(--t1);font-family:'Syne',sans-serif;">Nouvelle alerte</span>
    </div>
    <p style="font-size:.78rem;color:var(--t2);margin:0;">${alert.message.substring(0, 90)}</p>`;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 5000);
}