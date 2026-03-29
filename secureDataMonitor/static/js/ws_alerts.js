// ============================================================
// XUD-BANK — secureDataMonitor/static/js/ws_alerts.js
// Client WebSocket — Alertes temps réel (Optimisé)
// ============================================================

let ws = null;
let reconnectDelay = 3000;
let msgQueue = [];
let uiUpdateRequested = false;

function initWS(url) {
  const dot = document.getElementById('ws-dot');
  const status = document.getElementById('ws-status');

  function connect() {
    ws = new WebSocket(url);

    ws.onopen = () => {
      if (dot) { dot.classList.add('connected'); }
      if (status) { status.textContent = 'Connecté — temps réel'; }
      reconnectDelay = 3000;
    };

    ws.onmessage = (evt) => {
      const msg = JSON.parse(evt.data);

      if (msg.type === 'init') {
        updateStat('stat-unresolved', msg.stats.unresolved_alerts);
        updateStat('stat-total-events', msg.stats.total_events);
      } else if (msg.type === 'heartbeat') {
        if (status && status.textContent.includes('Connecté')) {
          status.textContent = `Connecté — ${msg.connected_clients} client(s)`;
        }
      } else if (msg.type === 'new_alert' || msg.type === 'new_event') {
        msgQueue.push(msg);
        if (!uiUpdateRequested) {
          uiUpdateRequested = true;
          requestAnimationFrame(flushQueue);
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

function flushQueue() {
  if (msgQueue.length === 0) {
    uiUpdateRequested = false;
    return;
  }

  const batch = msgQueue.splice(0, msgQueue.length); // clear and grab all
  uiUpdateRequested = false;

  let newAlerts = [];
  let newEvents = [];
  
  batch.forEach(msg => {
    if (msg.type === 'new_alert') newAlerts.push(msg.alert);
    else if (msg.type === 'new_event') newEvents.push(msg.event);
  });

  if (newAlerts.length > 0) {
    processAlertsQueue(newAlerts);
  }
  if (newEvents.length > 0) {
    processEventsQueue(newEvents);
  }
}

function processAlertsQueue(alerts) {
  const feed = document.getElementById('alert-feed');
  
  // Dashboard UI Updates
  if (feed) {
    const frag = document.createDocumentFragment();
    alerts.forEach(alert => {
      const time = new Date(alert.timestamp).toLocaleTimeString('fr-FR');
      const div = document.createElement('div');
      div.style.cssText = `display:flex;align-items:flex-start;gap:.6rem;margin-bottom:.55rem;
        padding:.65rem .8rem;background:rgba(255,255,255,.025);
        border-radius:9px;border:1px solid var(--bdr2);`;
      const level = typeof alert.alert_level === 'object' ? alert.alert_level.value : alert.alert_level;
      const msg = alert.message ? alert.message.substring(0, 80) : '';
      div.innerHTML = `
        <span class="bdg bdg-${level}" style="min-width:68px;justify-content:center;flex-shrink:0;">
          ${level}
        </span>
        <div>
          <p style="font-size:.8rem;color:var(--t1);margin:0 0 .1rem;">${msg}</p>
          <small style="color:var(--t3);font-size:.7rem;">${time}</small>
        </div>`;
      frag.appendChild(div);
    });
    
    feed.prepend(frag);
    
    // Remove empty state message
    const emptyP = feed.querySelector('p');
    if (emptyP && emptyP.textContent.includes('Aucune alerte')) emptyP.remove();
    
    // Maintain max items
    while (feed.children.length > 20) feed.removeChild(feed.lastChild);
  }

  // Update Stats Counters
  ['alert-count', 'stat-unresolved'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = parseInt(el.textContent || 0) + alerts.length;
  });

  // Limit toast spam to max 1 per batch
  showToast(alerts[0]);
}

function processEventsQueue(events) {
  const tbody = document.getElementById('events-feed');
  
  // Dashboard UI Updates
  if (tbody) {
    const frag = document.createDocumentFragment();
    events.forEach(event => {
      const time = new Date(event.timestamp).toLocaleTimeString('fr-FR');
      const tr = document.createElement('tr');
      const eventType = typeof event.event_type === 'object' ? event.event_type.value : event.event_type;
      const severity = typeof event.severity === 'object' ? event.severity.value : event.severity;
      
      tr.innerHTML = `
        <td style="padding-left:1rem;">
          <span class="bdg bdg-${severity}">${eventType.substring(0, 14)}</span>
        </td>
        <td style="font-size:.78rem;color:var(--t2);font-family:monospace;">${event.ip_address || ''}</td>
        <td style="font-size:.78rem;color:var(--t3);">${time}</td>`;
      frag.appendChild(tr);
    });
    
    tbody.prepend(frag);
    while (tbody.children.length > 15) tbody.removeChild(tbody.lastChild);
  }

  // Update Stats Counters
  const statTotal = document.getElementById('stat-total-events');
  if (statTotal) statTotal.textContent = parseInt(statTotal.textContent || 0) + events.length;
  
  let highCount = 0;
  let critCount = 0;
  events.forEach(e => {
    const sev = typeof e.severity === 'object' ? e.severity.value : e.severity;
    if (sev === 'HIGH' || sev === 'CRITICAL') highCount++;
    if (sev === 'CRITICAL') critCount++;
  });
  
  if (highCount > 0) {
    const el = document.getElementById('stat-high');
    if (el) el.textContent = parseInt(el.textContent || 0) + highCount;
  }
  if (critCount > 0) {
    const el = document.getElementById('stat-critical');
    if (el) el.textContent = parseInt(el.textContent || 0) + critCount;
  }
}

// Ensure we don't have too many toasts on screen
let activeToasts = 0;

function showToast(alert) {
  if (activeToasts >= 3) return; // limit to 3 toasts max
  
  const level = typeof alert.alert_level === 'object' ? alert.alert_level.value : alert.alert_level;
  const msg = alert.message ? alert.message.substring(0, 90) : '';
  
  const colors = { LOW: 'var(--s-low)', MEDIUM: 'var(--s-med)', HIGH: 'var(--s-hi)', CRITICAL: 'var(--s-crit)' };
  const color = colors[level] || 'var(--t2)';
  
  const toast = document.createElement('div');
  const topOffset = 72 + (activeToasts * 90);
  activeToasts++;
  
  toast.style.cssText = `
    position:fixed;top:${topOffset}px;right:20px;z-index:9999;
    background:var(--bg-card);
    border:1px solid var(--bdr2);
    border-left:4px solid ${color};
    border-radius:12px;padding:14px 18px;min-width:300px;
    box-shadow:0 8px 32px rgba(0,0,0,.4);
    backdrop-filter:blur(20px);
    transition: top 0.3s ease;
    animation:fadeSlideUp .3s var(--ease);`;
    
  toast.innerHTML = `
    <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.3rem;">
      <span class="bdg bdg-${level}">${level}</span>
      <span style="font-size:.82rem;font-weight:700;color:var(--t1);font-family:'Syne',sans-serif;">Nouvelle alerte</span>
    </div>
    <p style="font-size:.78rem;color:var(--t2);margin:0;">${msg}</p>`;
    
  document.body.appendChild(toast);
  
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-10px)';
    setTimeout(() => {
      toast.remove();
      activeToasts = Math.max(0, activeToasts - 1);
    }, 300);
  }, 4000);
}