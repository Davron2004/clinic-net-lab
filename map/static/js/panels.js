// Everything around the map: the header controls, the sidebar cards
// (patient records, isolation tests, alerts), captions under the map, the
// result banner and alert toasts.

import { icon } from './icons.js';
import { RESULT_ICON, clock, outcome, plural, service, timeAgo } from './words.js';
import { reducedMotion } from './scene.js';

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

// Were the damaged records encrypted? Ransomware replaces each record with an
// encrypted copy under a new name, so the originals are missing and new files
// appeared. That is still true when a repeat attack finds nothing left to
// encrypt (it reports 0 encrypted this time).
export function recordsEncrypted(rec) {
  return Boolean(rec?.encrypted) || (rec?.missing > 0 && rec?.added > 0);
}

export class RecordsCard {
  constructor() {
    this.el = $('#records-card');
    this.total = 12;
    this.lost = 0;
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
      foot = `${plural(lost, 'record')} ${recordsEncrypted(rec) ? 'encrypted' : 'changed or missing'} · checked ${clock(rec.ts)}`;
    } else {
      foot = `${icon('shieldCheck', 'ic ic--inline')} All fingerprints match · checked ${clock(rec.ts)}`;
    }
    this.el.innerHTML = `
      <header class="card-head"><h2>Patient records</h2><span class="card-meta">${esc(emrLabel)}</span></header>
      <div class="metric">
        <span class="metric-num">${rec.intact}</span>
        <span class="metric-of">of ${rec.total} intact</span>
      </div>
      <div class="files" role="img" aria-label="${rec.intact} of ${rec.total} records intact">${this.files(rec.total, lost, false, this.lost)}</div>
      <p class="card-foot">${foot}</p>`;
    this.lost = lost;
  }

  // Records locked since the last redraw get the lock-in animation; the
  // ones already locked stay still.
  files(total, lost, pending = false, before = lost) {
    let html = '';
    for (let i = 0; i < total; i += 1) {
      const gone = i >= total - lost;
      const fresh = gone && i < total - before;
      html += `<span class="file${gone ? ' file--lost' : ''}${fresh ? ' is-new' : ''}${pending ? ' file--pending' : ''}">${icon(gone ? 'lock' : 'file')}</span>`;
    }
    return html;
  }
}

// ------------------------------------------------------------------ tests

// A test that could not be run (the probe itself failed): "could not test".
export function isError(r) {
  return Boolean(r) && String(r.observed || '').toLowerCase() === 'error';
}

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
    // A probe that could not run (observed "error") says nothing about the
    // network: it is neither a pass nor a failure.
    const failed = (f) => results[f.id] && !results[f.id].pass && !isError(results[f.id]);
    const done = this.flows.filter((f) => results[f.id]).length;
    const passed = this.flows.filter((f) => results[f.id]?.pass).length;
    const errors = this.flows.filter((f) => isError(results[f.id])).length;
    const violations = this.flows.filter((f) => failed(f) && f.expect === 'deny').length;
    const broken = this.flows.filter((f) => failed(f) && f.expect === 'allow').length;
    const any = done > 0;

    let meta = 'Not run yet';
    if (running) meta = `Testing · ${done} of ${tests.total || total}`;
    else if (summary?.ts) meta = `Last run ${timeAgo(summary.ts)}`;
    let state = 'idle';
    if (running) state = 'running';
    else if (violations || broken) state = 'bad';
    else if (any) state = errors ? 'unsure' : 'ok';
    this.el.dataset.state = state;

    const cell = (f) => {
      const r = results[f.id];
      let cls = 'pending';
      let glyph = '';
      let verdict = 'not run';
      if (isError(r)) {
        cls = 'error'; glyph = icon('help'); verdict = 'could not test';
      } else if (r?.pass) {
        cls = 'pass'; glyph = icon('check'); verdict = 'as policy says';
      } else if (r && f.expect === 'deny') {
        cls = 'violation'; glyph = icon('alert'); verdict = 'got through';
      } else if (r) {
        cls = 'broken'; glyph = icon('x'); verdict = 'blocked';
      }
      return `<li class="cell cell--${cls}" title="${esc(f.id)} · ${esc(f.what)} (${verdict})" aria-label="${esc(f.id)} ${esc(f.what)}: ${verdict}">${glyph}</li>`;
    };
    const allow = this.flows.filter((f) => f.expect === 'allow');
    const deny = this.flows.filter((f) => f.expect !== 'allow');
    const num = any ? passed : '–';
    // One finding per line, so a line never breaks in the middle of one.
    const line = (html) => `<span class="foot-line">${html}</span>`;
    const unsure = errors ? line(`${plural(errors, 'connection')} could not be tested`) : '';
    let foot;
    if (!any) foot = 'Sends real traffic between every pair that matters.';
    else if (running) foot = `${plural(violations, 'violation')} so far`;
    else if (violations || broken) {
      const got = violations ? line(`<b>${plural(violations, 'forbidden connection')}</b> got through`) : '';
      const lost = broken ? line(`${plural(broken, 'needed connection')} blocked`) : '';
      foot = got + lost + unsure;
    } else if (errors) foot = unsure;
    else foot = `${icon('shieldCheck', 'ic ic--inline')} No violations: all as the policy says`;

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

// Alerts arrive in bursts (ransomware sets off one per encrypted record), so
// repeats of the same rule on the same machine within a minute become one
// line with a count. Alerts the test suite set off on purpose are marked as
// such and kept quiet.
const GROUP_SECONDS = 60;

// "Patient record deleted: patient-0003.json" and "...: patient-0007.json"
// are the same thing happening twice.
function mergeTitles(a, b) {
  if (a === b) return a;
  const pa = a.split(':')[0];
  return pa === b.split(':')[0] ? pa : b;
}

export function alertKey(a) {
  return `${a.rule_id}|${a.node || a.src || ''}`;
}

export class AlertsCard {
  constructor() {
    this.el = $('#alerts-card');
    this.groups = [];
    this.monitoring = null;
    // The isolation tests set off alerts on purpose (that is the monitor
    // working). They would only alarm someone watching, so they stay out of
    // the list unless asked for.
    this.showTests = false;
    this.el.addEventListener('click', (e) => {
      if (!e.target.closest('.alerts-toggle')) return;
      this.showTests = !this.showTests;
      this.draw();
    });
    new ResizeObserver(() => this.fit()).observe(this.el);
  }

  render(alerts, nodeLabel, monitoring) {
    this.nodeLabel = nodeLabel;
    this.monitoring = monitoring;
    this.groups = [];
    for (const a of alerts) this.merge(a);
    this.draw();
  }

  // Returns the group the alert landed in.
  add(alert) {
    const g = this.merge(alert);
    // Only a new line makes an entrance; a repeat just counts up.
    this.draw(g.count === 1 ? g : null);
    return g;
  }

  merge(a) {
    const key = alertKey(a);
    const g = this.groups.find((x) => x.key === key && a.ts - x.ts < GROUP_SECONDS);
    if (g) {
      g.count += 1;
      g.ts = Math.max(g.ts, a.ts);
      g.level = Math.max(g.level, a.level || 0);
      g.title = mergeTitles(g.title, a.title);
      g.during = g.during && a.during === g.during ? g.during : null;
      return g;
    }
    const fresh = { key, title: a.title, count: 1, ts: a.ts, level: a.level || 0, during: a.during, where: a.node || a.src || a.dst };
    this.groups.push(fresh);
    this.groups = this.groups.slice(-40);
    return fresh;
  }

  draw(fresh = null) {
    const all = [...this.groups].sort((a, b) => b.ts - a.ts);
    const fromTests = all.filter((g) => g.during === 'test').length;
    const items = this.showTests ? all : all.filter((g) => g.during !== 'test');
    let list;
    if (items.length) {
      list = items.map((g) => {
        const who = g.where ? this.nodeLabel(g.where) : null;
        const tag = g.during === 'test' ? '<span class="alert-tag">During test</span>' : '';
        const count = g.count > 1 ? `<span class="alert-count">×${g.count}</span>` : '';
        return `<li class="alert alert--${severity(g.level)}${g.during === 'test' ? ' alert--expected' : ''}${g === fresh ? ' is-new' : ''}">
          <span class="alert-sev" aria-hidden="true"></span>
          <div class="alert-body">
            <p class="alert-title">${esc(g.title)}${count}</p>
            <p class="alert-meta">${tag}${who ? `${esc(who)} · ` : ''}${timeAgo(g.ts)}</p>
          </div>
        </li>`;
      }).join('') + '<li class="alerts-more" hidden></li>';
    } else if (this.monitoring === 'off') {
      list = `<li class="alerts-empty">${icon('bell')}<span>Security monitoring is off for this lab, so nothing raises alerts.</span></li>`;
    } else if (fromTests) {
      list = `<li class="alerts-empty">${icon('shieldCheck')}<span>No alerts outside the isolation tests.</span></li>`;
    } else {
      list = `<li class="alerts-empty">${icon('bell')}<span>No alerts. Suspicious activity seen by the security monitor shows up here.</span></li>`;
    }
    let meta = '';
    if (fromTests) {
      const what = this.showTests ? `Hide ${fromTests} from tests` : `${fromTests} from tests hidden`;
      meta = `<button class="alerts-toggle" type="button" aria-pressed="${this.showTests}" title="Alerts the isolation tests set off on purpose">${what}</button>`;
    }
    this.el.innerHTML = `
      <header class="card-head"><h2>Alerts</h2><span class="card-meta">${meta}</span></header>
      <ol class="alerts">${list}</ol>`;
    this.fit();
    const li = fresh && this.el.querySelector('.alert.is-new');
    if (li && !li.hidden && !reducedMotion()) {
      // Open a gap of the new line's height, so the lines below slide down
      // while it fades in, instead of jumping.
      const h = li.offsetHeight;
      li.animate(
        [{ height: '0px', opacity: 0 }, { height: `${h}px`, opacity: 0, offset: 0.45 }, { height: `${h}px`, opacity: 1 }],
        { duration: 650, easing: 'cubic-bezier(.2,.8,.3,1)' },
      );
    }
  }

  // Show only whole lines: the ones that do not fit are summed up in one
  // line at the bottom instead of being cut off at the card's edge.
  fit() {
    const list = this.el.querySelector('.alerts');
    const more = list?.querySelector('.alerts-more');
    if (!more) return;
    const items = [...list.querySelectorAll('.alert')];
    for (const li of items) li.hidden = false;
    more.hidden = true;
    const limit = list.clientHeight;
    const bottom = (el) => el.offsetTop + el.offsetHeight;
    if (!items.length || bottom(items[items.length - 1]) <= limit) return;
    more.hidden = false;
    more.textContent = plural(1, 'earlier alert');
    let hidden = 0;
    for (let i = items.length - 1; i > 0 && bottom(more) > limit; i -= 1) {
      items[i].hidden = true;
      hidden += 1;
      more.textContent = `${plural(hidden, 'earlier alert')}`;
    }
    if (!hidden) more.hidden = true;
  }

  tick() {
    if (this.groups.length) this.draw();
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

  push(flow, nodeLabel, variant, count = 1, ports = 1) {
    const li = document.createElement('li');
    li.className = `caption caption--${flow.result}`;
    // A scan touches many ports at once: say how many, not the first one.
    const svc = ports > 1 ? `${ports} ports` : service(flow.port, flow.proto);
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
    this.el.parentElement.classList.add('has-banner');
    requestAnimationFrame(() => this.el.classList.add('is-shown'));
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.hide(), seconds * 1000);
  }

  hide() {
    clearTimeout(this.timer);
    this.el.classList.remove('is-shown');
    this.el.parentElement.classList.remove('has-banner');
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
    this.open = new Map();
    this.maxHeight = Infinity;
  }

  // The column the toasts live in, in pixels of the map's box: under the
  // outside world, left of the clinic's wall (see main.js).
  place({ left, width, bottom, maxHeight }) {
    Object.assign(this.el.style, { left: `${left}px`, width: `${width}px`, bottom: `${bottom}px` });
    this.maxHeight = maxHeight;
    this.fit();
  }

  // Never let the stack climb into the map above it: drop the least severe
  // toast (of equal ones, the oldest, but not the one just shown) until it
  // fits. A burst of minor alerts never pushes out the one that matters.
  fit(keep = null) {
    let shown = [...this.el.children].filter((x) => !x.classList.contains('is-leaving'));
    while (shown.length > 1 && this.el.offsetHeight > this.maxHeight) {
      const level = (x) => Number(x.dataset.level);
      const weakest = shown.reduce((w, x) => {
        if (level(x) !== level(w)) return level(x) < level(w) ? x : w;
        return w === keep ? x : w;
      });
      this.close(weakest, true);
      shown = shown.filter((x) => x !== weakest);
    }
  }

  // key: toasts with the same key update one another (a burst of the same
  // alert counts up on one toast instead of stacking).
  // level: when there is no room, the least severe toast goes first, so a
  // burst of minor alerts never pushes out the one that matters.
  show({ kind = 'alert', title, text, seconds = 6, key = null, count = 1, level = 0 }) {
    let t = key ? this.open.get(key) : null;
    if (!t || !t.isConnected) {
      const shown = [...this.el.children].filter((x) => !x.classList.contains('is-leaving'));
      if (shown.length >= 2) {
        const weakest = shown.reduce((w, x) => (Number(x.dataset.level) < Number(w.dataset.level) ? x : w));
        if (Number(weakest.dataset.level) > level) return;
        this.close(weakest, true);
      }
      t = document.createElement('div');
      t.setAttribute('role', 'status');
      t.addEventListener('click', () => this.close(t));
      this.el.append(t);
      requestAnimationFrame(() => t.classList.add('is-shown'));
      if (key) {
        t.dataset.key = key;
        this.open.set(key, t);
      }
    }
    t.dataset.level = String(level);
    t.className = `toast toast--${kind}${t.classList.contains('is-shown') ? ' is-shown' : ''}`;
    const glyph = { error: 'x', critical: 'alert' }[kind] || 'bell';
    const times = count > 1 ? `<span class="toast-count">×${count}</span>` : '';
    t.innerHTML = `
      <span class="toast-icon">${icon(glyph)}</span>
      <div class="toast-body"><p class="toast-title">${esc(title)}${times}</p>${text ? `<p class="toast-text">${esc(text)}</p>` : ''}</div>`;
    this.fit(t);
    clearTimeout(t.timer);
    t.timer = setTimeout(() => this.close(t), seconds * 1000);
  }

  close(t, now = false) {
    if (!t) return;
    clearTimeout(t.timer);
    if (t.dataset.key && this.open.get(t.dataset.key) === t) this.open.delete(t.dataset.key);
    if (now) {
      t.remove();
      return;
    }
    t.classList.remove('is-shown');
    t.classList.add('is-leaving');
    setTimeout(() => t.remove(), 400);
  }
}
