// Everything around the map: the header controls, the sidebar cards
// (patient records, isolation tests, alerts), captions under the map, the
// result banner and alert toasts.

import { icon } from './icons.js';
import { RESULT_ICON, clock, outcome, plural, service, timeAgo } from './words.js';

const $ = (sel) => document.querySelector(sel);

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

// ------------------------------------------------------------------ header

export class Header {
  constructor({ onRun }) {
    this.variantEl = $('#variant');
    this.connEl = $('#conn');
    this.buttons = {
      tests: $('#btn-tests'),
      attack: $('#btn-attack'),
    };
    this.labels = {
      tests: { idle: 'Run isolation tests', busy: 'Testing…', icon: 'list' },
      attack: { idle: 'Simulate ransomware', busy: 'Attack running…', icon: 'bug' },
    };
    for (const [name, btn] of Object.entries(this.buttons)) {
      btn.addEventListener('click', () => onRun(name));
    }
    this.setBusy(null);
  }

  setVariant(variant) {
    const flat = variant === 'flat';
    this.variantEl.dataset.variant = flat ? 'flat' : 'clinic';
    this.variantEl.innerHTML = flat
      ? `${icon('alert')}<span><b>Before:</b> one flat network</span>`
      : `${icon('shieldCheck')}<span><b>After:</b> segmented, firewall between zones</span>`;
    document.title = flat ? 'Clinic network · before' : 'Clinic network';
  }

  setConnection(state) {
    this.connEl.dataset.state = state;
    this.connEl.querySelector('.conn-text').textContent = {
      live: 'Live', connecting: 'Connecting…', lost: 'Reconnecting…',
    }[state];
  }

  // busy: null, or which job is running ("tests" / "attack").
  setBusy(busy) {
    // Redrawing restarts the spinner, so only redraw on a change.
    if (busy === this.busy) return;
    this.busy = busy;
    for (const [name, btn] of Object.entries(this.buttons)) {
      const l = this.labels[name];
      const mine = busy === name;
      btn.disabled = Boolean(busy);
      btn.classList.toggle('is-running', mine);
      btn.setAttribute('aria-busy', mine ? 'true' : 'false');
      btn.innerHTML = mine
        ? `<span class="spinner" aria-hidden="true"></span><span>${l.busy}</span>`
        : `${icon(l.icon)}<span>${l.idle}</span>`;
    }
  }
}

// ------------------------------------------------------------------ records

export class RecordsCard {
  constructor() {
    this.el = $('#records-card');
    this.total = 12;
  }

  render(rec, topology) {
    const hasEmr = topology?.nodes.some((n) => n.id === 'emr');
    this.el.hidden = !hasEmr;
    const emrLabel = topology?.nodes.find((n) => n.id === 'emr')?.label || 'EMR server';
    if (!rec || !rec.total) {
      this.el.dataset.state = 'unknown';
      this.el.innerHTML = `
        <header class="card-head"><h2>Patient records</h2><span class="card-meta">${esc(emrLabel)}</span></header>
        <div class="metric"><span class="metric-num metric-num--muted">–</span><span class="metric-of">Checking records…</span></div>
        <div class="files">${this.files(this.total, 0, true)}</div>
        <p class="card-foot">Each record is fingerprinted when the server starts.</p>`;
      return;
    }
    this.total = rec.total;
    const encrypted = rec.encrypted || 0;
    const damaged = rec.total - rec.intact;
    const hit = damaged > 0 || encrypted > 0;
    this.el.dataset.state = hit ? 'hit' : 'ok';
    const lost = Math.max(damaged, encrypted);
    let foot;
    if (rec.phase === 'encrypting') {
      foot = `${icon('lock', 'ic ic--inline')} Ransomware is encrypting records`;
    } else if (hit) {
      foot = `${plural(lost, 'record')} ${encrypted ? 'encrypted' : 'damaged'} · checked ${clock(rec.ts)}`;
    } else {
      foot = `${icon('shieldCheck', 'ic ic--inline')} All fingerprints match · checked ${clock(rec.ts)}`;
    }
    this.el.innerHTML = `
      <header class="card-head"><h2>Patient records</h2><span class="card-meta">${esc(emrLabel)}</span></header>
      <div class="metric">
        <span class="metric-num">${rec.intact}</span>
        <span class="metric-of">of ${rec.total} intact</span>
      </div>
      <div class="files" role="img" aria-label="${rec.intact} of ${rec.total} records intact">${this.files(rec.total, lost)}</div>
      <p class="card-foot">${foot}</p>`;
  }

  files(total, lost, pending = false) {
    let html = '';
    for (let i = 0; i < total; i += 1) {
      const gone = i >= total - lost;
      html += `<span class="file${gone ? ' file--lost' : ''}${pending ? ' file--pending' : ''}">${icon(gone ? 'lock' : 'file')}</span>`;
    }
    return html;
  }
}

// ------------------------------------------------------------------ tests

export class TestsCard {
  constructor() {
    this.el = $('#tests-card');
    this.flows = [];
    this.tests = null;
    this.variant = 'clinic';
  }

  setFlows(flows, variant) {
    this.flows = flows || [];
    this.variant = variant;
  }

  render(tests) {
    this.tests = tests;
    const results = tests?.results || {};
    const running = Boolean(tests?.running);
    const summary = tests?.summary;
    const total = this.flows.length;
    const done = this.flows.filter((f) => results[f.id]).length;
    const passed = this.flows.filter((f) => results[f.id]?.pass).length;
    const violations = this.flows.filter((f) => results[f.id] && !results[f.id].pass && f.expect === 'deny').length;
    const broken = this.flows.filter((f) => results[f.id] && !results[f.id].pass && f.expect === 'allow').length;
    const any = done > 0;

    let meta = 'Not run yet';
    if (running) meta = `Testing · ${done} of ${tests.total || total}`;
    else if (summary?.ts) meta = `Last run ${timeAgo(summary.ts)}`;
    let state = 'idle';
    if (running) state = 'running';
    else if (any) state = passed === done && done > 0 ? 'ok' : 'bad';
    this.el.dataset.state = state;

    const cell = (f) => {
      const r = results[f.id];
      let cls = 'pending';
      let glyph = '';
      if (r) {
        if (r.pass) { cls = 'pass'; glyph = icon('check'); } else if (f.expect === 'deny') { cls = 'violation'; glyph = icon('alert'); } else { cls = 'broken'; glyph = icon('x'); }
      }
      const verdict = !r ? 'not run' : r.pass ? 'as policy says' : f.expect === 'deny' ? 'got through' : 'blocked';
      return `<li class="cell cell--${cls}" title="${esc(f.id)} · ${esc(f.what)} (${verdict})" aria-label="${esc(f.id)} ${esc(f.what)}: ${verdict}">${glyph}</li>`;
    };
    const allow = this.flows.filter((f) => f.expect === 'allow');
    const deny = this.flows.filter((f) => f.expect !== 'allow');
    const num = any ? passed : '–';
    let foot;
    if (!any) foot = 'Sends real traffic between every pair that matters.';
    else if (running) foot = `${plural(violations, 'violation')} so far`;
    else if (violations || broken) foot = `<b>${plural(violations, 'forbidden connection')}</b> got through${broken ? ` · ${broken} needed blocked` : ''}`;
    else foot = `${icon('shieldCheck', 'ic ic--inline')} No violations · ${allow.length} allowed, ${deny.length} blocked`;

    this.el.innerHTML = `
      <header class="card-head"><h2>Isolation tests</h2><span class="card-meta">${meta}</span></header>
      <div class="metric">
        <span class="metric-num${any ? '' : ' metric-num--muted'}">${num}</span><span class="metric-of">/${total}</span>
        <span class="metric-label">connections<br>match policy</span>
      </div>
      <div class="cells-group">
        <div class="cells-head"><span>Should work</span><span>${allow.length}</span></div>
        <ul class="cells">${allow.map(cell).join('')}</ul>
      </div>
      <div class="cells-group">
        <div class="cells-head"><span>Should be blocked</span><span>${deny.length}</span></div>
        <ul class="cells">${deny.map(cell).join('')}</ul>
      </div>
      <p class="card-foot">${foot}</p>`;
  }

  // One probe result arrived: light up its cell without redrawing the card.
  result(msg) {
    if (!this.tests) return;
    this.tests.results[msg.id] = { pass: msg.pass, observed: msg.observed };
    this.render(this.tests);
    const idx = this.flows.findIndex((f) => f.id === msg.id);
    if (idx >= 0) {
      const cells = this.el.querySelectorAll('.cell');
      cells[idx]?.classList.add('is-new');
    }
  }
}

// ------------------------------------------------------------------ alerts

function severity(level) {
  if (level >= 12) return 'critical';
  if (level >= 8) return 'high';
  if (level >= 5) return 'medium';
  return 'low';
}

export class AlertsCard {
  constructor() {
    this.el = $('#alerts-card');
    this.alerts = [];
  }

  render(alerts, nodeLabel) {
    this.alerts = alerts.slice(-30);
    this.nodeLabel = nodeLabel;
    this.draw();
  }

  add(alert) {
    this.alerts.push(alert);
    this.alerts = this.alerts.slice(-30);
    this.draw(alert);
  }

  draw(fresh = null) {
    const items = [...this.alerts].reverse();
    const list = items.length
      ? items.map((a) => {
        const where = a.node || a.src || a.dst;
        const who = where ? this.nodeLabel(where) : null;
        return `<li class="alert alert--${severity(a.level || 0)}${a === fresh ? ' is-new' : ''}">
          <span class="alert-sev" aria-hidden="true"></span>
          <div class="alert-body">
            <p class="alert-title">${esc(a.title)}</p>
            <p class="alert-meta">${who ? `${esc(who)} · ` : ''}${timeAgo(a.ts)}</p>
          </div>
        </li>`;
      }).join('')
      : `<li class="alerts-empty">${icon('bell')}<span>No alerts. Suspicious activity seen by the security monitor shows up here.</span></li>`;
    this.el.innerHTML = `
      <header class="card-head"><h2>Alerts</h2><span class="card-meta">${items.length ? items.length : ''}</span></header>
      <ol class="alerts">${list}</ol>`;
  }

  tick() {
    if (this.alerts.length) this.draw();
  }
}

// ------------------------------------------------------------------ captions

export class Captions {
  constructor() {
    this.el = $('#captions');
    this.items = [];
  }

  clear() {
    this.items = [];
    this.el.replaceChildren();
  }

  push(flow, nodeLabel, variant, count = 1) {
    const li = document.createElement('li');
    li.className = `caption caption--${flow.result}`;
    const svc = service(flow.port, flow.proto);
    const times = count > 1 ? ` <span class="caption-count">×${count}</span>` : '';
    li.innerHTML = `
      <span class="caption-icon">${icon(RESULT_ICON[flow.result] || 'arrow')}</span>
      <span class="caption-main"><b>${esc(nodeLabel(flow.from))}</b><span class="caption-arrow">→</span><b>${esc(nodeLabel(flow.to))}</b>${times}</span>
      <span class="caption-svc">${esc(svc)}</span>
      <span class="caption-result">${esc(outcome(flow, variant))}</span>
      ${flow.what ? `<span class="caption-what">${esc(flow.what)}</span>` : ''}`;
    this.el.appendChild(li);
    this.items.push(li);
    while (this.items.length > 3) this.items.shift().remove();
  }
}

// ------------------------------------------------------------------ banner

export class Banner {
  constructor() {
    this.el = $('#banner');
    this.el.addEventListener('click', () => this.hide());
  }

  show(kind, title, text, seconds = 10) {
    this.el.className = `banner banner--${kind}`;
    const ic = { ok: 'shieldCheck', bad: 'alert', info: 'zap' }[kind] || 'zap';
    this.el.innerHTML = `
      <span class="banner-icon">${icon(ic)}</span>
      <div class="banner-body"><p class="banner-title">${esc(title)}</p><p class="banner-text">${esc(text)}</p></div>`;
    this.el.hidden = false;
    requestAnimationFrame(() => this.el.classList.add('is-shown'));
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.hide(), seconds * 1000);
  }

  hide() {
    clearTimeout(this.timer);
    this.el.classList.remove('is-shown');
    this.timer = setTimeout(() => { this.el.hidden = true; }, 350);
  }
}

// ------------------------------------------------------------------ status

export class Status {
  constructor() {
    this.el = $('#status');
  }

  set(kind, html) {
    if (!kind) {
      this.el.classList.remove('is-shown');
      this.el.dataset.kind = '';
      return;
    }
    this.el.dataset.kind = kind;
    this.el.innerHTML = `<span class="status-dot" aria-hidden="true"></span><span>${html}</span>`;
    this.el.classList.add('is-shown');
  }
}

// ------------------------------------------------------------------ toasts

export class Toasts {
  constructor() {
    this.el = $('#toasts');
  }

  show({ kind = 'alert', title, text, seconds = 6 }) {
    const t = document.createElement('div');
    t.className = `toast toast--${kind}`;
    t.setAttribute('role', 'status');
    t.innerHTML = `
      <span class="toast-icon">${icon(kind === 'error' ? 'x' : 'bell')}</span>
      <div class="toast-body"><p class="toast-title">${esc(title)}</p>${text ? `<p class="toast-text">${esc(text)}</p>` : ''}</div>`;
    this.el.append(t);
    while (this.el.children.length > 2) this.el.firstElementChild.remove();
    requestAnimationFrame(() => t.classList.add('is-shown'));
    const close = () => {
      t.classList.remove('is-shown');
      setTimeout(() => t.remove(), 400);
    };
    t.addEventListener('click', close);
    setTimeout(close, seconds * 1000);
  }
}
