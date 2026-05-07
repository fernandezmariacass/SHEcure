/* SHEcure — Main JS */

// ── Alert count polling ──────────────────────
let alertCountEl = document.getElementById('alert-count-badge');
let alertBellDot = document.getElementById('alert-bell-dot');

function pollAlertCount() {
  fetch('/api/alerts/count')
    .then(r => r.json())
    .then(data => {
      if (alertCountEl) {
        alertCountEl.textContent = data.count;
        alertCountEl.style.display = data.count > 0 ? '' : 'none';
      }
      if (alertBellDot) {
        alertBellDot.style.display = data.count > 0 ? '' : 'none';
      }
    })
    .catch(() => {});
}

if (alertCountEl || alertBellDot) {
  pollAlertCount();
  setInterval(pollAlertCount, 15000);
}

// ── Toast notification system ────────────────
function showToast(message, type = 'info', duration = 4000) {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const icons = { success: '✅', danger: '🚨', warning: '⚠️', info: 'ℹ️' };

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'polite');
  toast.innerHTML = `
    <span style="font-size:1.1rem">${icons[type] || icons.info}</span>
    <span style="flex:1">${message}</span>
    <button onclick="this.parentElement.remove()" aria-label="Dismiss"
      style="background:none;border:none;cursor:pointer;color:#9ca3af;font-size:1rem">✕</button>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = 'all .3s';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ── Expose for inline use ────────────────────
window.showToast = showToast;

// ── Flash message auto-dismiss ───────────────
document.querySelectorAll('.alert[data-auto-dismiss]').forEach(el => {
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity .4s';
    setTimeout(() => el.remove(), 400);
  }, 5000);
});

// ── Mobile sidebar toggle ────────────────────
const menuBtn = document.getElementById('menu-toggle');
const sidebar = document.querySelector('.sidebar');
const overlay = document.getElementById('sidebar-overlay');

function openSidebar() {
  sidebar?.classList.add('open');
  overlay?.classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeSidebar() {
  sidebar?.classList.remove('open');
  overlay?.classList.remove('active');
  document.body.style.overflow = '';
}

menuBtn?.addEventListener('click', openSidebar);
overlay?.addEventListener('click', closeSidebar);

// ── Resolve alert button ─────────────────────
document.querySelectorAll('.resolve-alert-btn').forEach(btn => {
  btn.addEventListener('click', async function () {
    const alertId = this.dataset.alertId;
    const res = await fetch(`/admin/alerts/${alertId}/resolve`, { method: 'POST' });
    const data = await res.json();
    if (data.ok) {
      const row = document.getElementById(`alert-row-${alertId}`);
      if (row) {
        row.classList.add('resolved');
        row.querySelector('.resolve-alert-btn').remove();
      }
      showToast('Alert resolved.', 'success');
      pollAlertCount();
    }
  });
});

// ── Confirm delete ───────────────────────────
document.querySelectorAll('[data-confirm]').forEach(btn => {
  btn.addEventListener('click', function (e) {
    if (!confirm(this.dataset.confirm)) {
      e.preventDefault();
    }
  });
});

// ── Camera status ────────────────────────────
const cameraStatusEl = document.getElementById('camera-status-text');
if (cameraStatusEl) {
  fetch('/camera/status')
    .then(r => r.json())
    .then(data => {
      cameraStatusEl.textContent = data.online ? 'LIVE' : 'OFFLINE';
      cameraStatusEl.style.color = data.online ? '#10b981' : '#ef4444';
    })
    .catch(() => {
      if (cameraStatusEl) cameraStatusEl.textContent = 'UNKNOWN';
    });
}

// ── Table row highlight for suspicious ───────
document.querySelectorAll('tr[data-suspicious="true"]').forEach(row => {
  row.style.background = '#fff5f7';
});

// ── Real-time activity feed (dashboard) ──────
const activityFeed = document.getElementById('live-activity-feed');
if (activityFeed) {
  function refreshActivity() {
    fetch('/api/access/recent')
      .then(r => r.json())
      .then(logs => {
        activityFeed.innerHTML = logs.slice(0, 8).map(log => {
          const statusClass = log.status === 'success' ? 'badge-success'
            : log.status === 'blocked' ? 'badge-danger' : 'badge-warning';
          return `
            <tr>
              <td><span class="text-mono">${log.ip}</span></td>
              <td>${log.username || '—'}</td>
              <td><span class="badge ${statusClass} badge-dot">${log.status}</span></td>
              <td class="text-muted">${new Date(log.timestamp).toLocaleTimeString()}</td>
            </tr>`;
        }).join('');
      })
      .catch(() => {});
  }

  refreshActivity();
  setInterval(refreshActivity, 10000);
}

// ── Sidebar active state ─────────────────────
const currentPath = window.location.pathname;
document.querySelectorAll('.sidebar-nav-item').forEach(item => {
  const href = item.getAttribute('href');
  if (href && currentPath.startsWith(href) && href !== '/') {
    item.classList.add('active');
  } else if (href === '/' && currentPath === '/') {
    item.classList.add('active');
  }
});
