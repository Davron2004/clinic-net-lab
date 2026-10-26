// Draws the clinic: building, zones, machines, router. Also owns the small
// effects that happen on those things (a machine flashing, a badge count).

import { CARD, LABEL_FONT, computeLayout, wires, wrapLabel, textWidth, FONT_STACK } from './layout.js';
import { iconFor } from './icons.js';

const NS = 'http://www.w3.org/2000/svg';

export function svgEl(name, attrs = {}, parent = null) {
  const node = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== undefined && v !== null) node.setAttribute(k, v);
  }
  if (parent) parent.appendChild(node);
  return node;
}

function useIcon(name, x, y, size, parent, cls = '') {
  return svgEl('use', { href: `#i-${name}`, x, y, width: size, height: size, class: cls }, parent);
}

const MARK_FONT = `700 11px ${FONT_STACK}`;
const BADGE_FONT = `700 10.5px ${FONT_STACK}`;
const NODE_ICON_Y = 30;
// A status pill takes the address line's place, at the same height on every
// card, clear of a two-line name and of the card's bottom edge.
const BADGE_Y = CARD.h - 18;
const BADGE_H = 18;
const MARK_ICON = { allowed: 'check', blocked: 'x', broken: 'x', violation: 'alert' };
const MARK_LIFE = { allowed: 2200, blocked: 2600, broken: 4000, violation: 6000 };

export class Scene {
  constructor(svg) {
    this.svg = svg;
    this.L = null;
    this.variant = 'clinic';
    this.marks = new Map();
    this.badges = new Map();
  }

  get layout() {
    return this.L;
  }

  build(topology, aspect) {
    this.topology = topology;
    this.variant = topology.variant;
    this.L = computeLayout(topology, aspect);
    const { viewBox: vb } = this.L;
    const svg = this.svg;
    svg.replaceChildren();
    svg.setAttribute('viewBox', `${vb.x} ${vb.y} ${vb.w} ${vb.h}`);
    svg.classList.toggle('is-flat', this.variant === 'flat');
    this.marks.clear();

    const layer = (name) => svgEl('g', { class: `layer layer-${name}` }, svg);
    this.layers = {
      building: layer('building'),
      zones: layer('zones'),
      wires: layer('wires'),
      flows: layer('flows'),
      // Labels on wires (the VPN tag) sit above the connections crossing them.
      tags: layer('tags'),
      router: layer('router'),
      nodes: layer('nodes'),
      fx: layer('fx'),
    };
    // Invisible path used to measure lengths of connection paths.
    this.measurePath = svgEl('path', { class: 'measure', d: 'M0 0' }, this.layers.fx);

    this._building();
    this._zones();
    this._wires();
    this._router();
    this._nodes();
    // Re-apply states that outlive a redraw (infected machine, locked records, alerts).
    for (const [id, b] of this.badges) this.setBadge(id, b.kind, b.text, true);
    return this.L;
  }

  _building() {
    const b = this.L.building;
    const g = this.layers.building;
    svgEl('rect', { class: 'building', x: b.x, y: b.y, width: b.w, height: b.h, rx: 30 }, g);
    const label = svgEl('text', { class: 'building-label', x: b.labelPos.x, y: b.labelPos.y }, g);
    label.textContent = this.variant === 'flat'
      ? 'Clinic · one flat network: every machine can reach every other'
      : 'Clinic';
  }

  _zones() {
    const flat = this.variant === 'flat';
    for (const z of Object.values(this.L.zones)) {
      const outside = z.face === 'right';
      const g = svgEl('g', { class: `zone zone--${outside ? 'outside' : 'inside'}`, 'data-zone': z.id }, this.layers.zones);
      svgEl('rect', { class: 'zone-box', x: z.x, y: z.y, width: z.w, height: z.h, rx: 20 }, g);
      if (flat && !outside) {
        // No walls in the flat network: keep a faint name so machines can be found.
        const t = svgEl('text', { class: 'zone-label zone-label--ghost', x: z.labelPos.x, y: z.labelPos.y }, g);
        t.textContent = z.label;
        continue;
      }
      const t = svgEl('text', { class: 'zone-label', x: z.labelPos.x, y: z.labelPos.y }, g);
      t.textContent = z.label;
      if (z.vlanText) {
        const v = svgEl('text', { class: 'zone-vlan', x: z.vlanPos.x, y: z.vlanPos.y, 'text-anchor': 'end' }, g);
        v.textContent = z.vlanText;
      }
      const vertical = z.face !== 'right';
      svgEl('rect', {
        class: 'zone-gate',
        x: z.gate.x - (vertical ? 11 : 3),
        y: z.gate.y - (vertical ? 3 : 11),
        width: vertical ? 22 : 6,
        height: vertical ? 6 : 22,
        rx: 3,
      }, g);
    }
  }

  _wires() {
    for (const w of wires(this.L, this.variant)) {
      const path = svgEl('path', { class: `wire wire--${w.kind}${w.vpn ? ' wire--vpn' : ''}`, d: w.d, 'data-zone': w.zone }, this.layers.wires);
      if (w.vpn) this._vpnTag(path);
    }
  }

  // A small "VPN" tag with a lock on the tunnel.
  _vpnTag(path) {
    // Placed outside the building: the tunnel runs over the internet.
    const p = path.getPointAtLength(path.getTotalLength() * 0.2);
    const g = svgEl('g', { class: 'vpn-tag', transform: `translate(${p.x} ${p.y})` }, this.layers.tags);
    svgEl('rect', { class: 'vpn-tag-pill', x: -24, y: -10, width: 48, height: 20, rx: 10 }, g);
    useIcon('lock', -17, -6, 12, g, 'vpn-tag-icon');
    const t = svgEl('text', { class: 'vpn-tag-text', x: -2, y: 4 }, g);
    t.textContent = 'VPN';
  }

  _router() {
    const g = this.layers.router;
    if (this.variant === 'flat') {
      const r = this.L.flatRouter;
      const rg = svgEl('g', { class: 'router router--flat', transform: `translate(${r.x} ${r.y})` }, g);
      svgEl('rect', { class: 'router-card', width: r.w, height: r.h, rx: 16 }, rg);
      svgEl('circle', { class: 'router-icon-bg', cx: r.w / 2, cy: 28, r: 18 }, rg);
      useIcon('router', r.w / 2 - 11, 17, 22, rg, 'router-icon');
      const t = svgEl('text', { class: 'router-title', x: r.w / 2, y: 64, 'text-anchor': 'middle' }, rg);
      t.textContent = 'Internet router';
      const s = svgEl('text', { class: 'router-sub', x: r.w / 2, y: 80, 'text-anchor': 'middle' }, rg);
      s.textContent = 'No firewall inside';
      this._ports(rg, r, [r.wan, r.lan]);
      this.routerCounts = null;
      this._switch();
      return;
    }
    const r = this.L.router;
    const rg = svgEl('g', { class: 'router', transform: `translate(${r.x} ${r.y})` }, g);
    svgEl('rect', { class: 'router-glow', x: -1, y: -1, width: r.w + 2, height: r.h + 2, rx: 21 }, rg);
    svgEl('rect', { class: 'router-card', width: r.w, height: r.h, rx: 20 }, rg);
    svgEl('circle', { class: 'router-icon-bg', cx: 42, cy: r.h / 2, r: 24 }, rg);
    useIcon('shield', 29, r.h / 2 - 13, 26, rg, 'router-icon');
    const t = svgEl('text', { class: 'router-title', x: 78, y: r.h / 2 - 4 }, rg);
    t.textContent = 'Firewall';
    const s = svgEl('text', { class: 'router-sub', x: 78, y: r.h / 2 + 15 }, rg);
    s.textContent = 'Checks every connection';
    // Live counters: how many new connections it let through and stopped
    // since the lab started (routine traffic, tests and attacks alike). The
    // heading keeps them from reading as test results.
    const cg = svgEl('g', { class: 'router-counts', transform: `translate(${r.w - 18} ${r.h / 2})` }, rg);
    const head = svgEl('text', { class: 'router-count-head', x: 0, y: -16, 'text-anchor': 'end' }, cg);
    head.textContent = 'Since lab start';
    const allowed = svgEl('text', { class: 'router-count router-count--allowed', x: 0, y: 2, 'text-anchor': 'end' }, cg);
    const blocked = svgEl('text', { class: 'router-count router-count--blocked', x: 0, y: 19, 'text-anchor': 'end' }, cg);
    this.routerCounts = { allowed, blocked };
    this.setCounters(this._counters || { allowed: 0, blocked: 0 });
    this._ports(rg, r, Object.values(r.ports).filter((p, i, all) => all.indexOf(p) === i));
  }

  // The flat network's one switch: every machine inside plugs into it, so
  // every machine can reach every other.
  _switch() {
    const S = this.L.flatSwitch;
    const sg = svgEl('g', { class: 'switch', transform: `translate(${S.x} ${S.y})` }, this.layers.router);
    svgEl('rect', { class: 'switch-card', width: S.w, height: S.h, rx: 16 }, sg);
    svgEl('circle', { class: 'switch-icon-bg', cx: 38, cy: S.h / 2, r: 19 }, sg);
    useIcon('switch', 27, S.h / 2 - 11, 22, sg, 'switch-icon');
    const t = svgEl('text', { class: 'switch-title', x: 68, y: S.h / 2 - 3 }, sg);
    t.textContent = 'One network switch';
    const sub = svgEl('text', { class: 'switch-sub', x: 68, y: S.h / 2 + 15 }, sg);
    sub.textContent = 'No firewall between machines';
    this._ports(sg, S, [S.west, ...Object.values(S.ports)]);
  }

  _ports(group, r, ports) {
    for (const p of ports) {
      const vertical = p.n[0] === 0;
      svgEl('rect', {
        class: 'router-port',
        x: p.x - r.x - (vertical ? 9 : 3),
        y: p.y - r.y - (vertical ? 3 : 9),
        width: vertical ? 18 : 6,
        height: vertical ? 6 : 18,
        rx: 3,
      }, group);
    }
  }

  _nodes() {
    this.nodeEls = {};
    for (const n of Object.values(this.L.nodes)) {
      const g = svgEl('g', { class: 'node', 'data-node': n.id, transform: `translate(${n.x} ${n.y})` }, this.layers.nodes);
      svgEl('rect', { class: 'node-card', width: CARD.w, height: CARD.h, rx: 16 }, g);
      svgEl('circle', { class: 'node-icon-bg', cx: CARD.w / 2, cy: NODE_ICON_Y, r: 18 }, g);
      useIcon(iconFor(n), CARD.w / 2 - 11, NODE_ICON_Y - 11, 22, g, 'node-icon');
      const lines = wrapLabel(n.label, CARD.w - 14, LABEL_FONT);
      const blockTop = lines.length === 1 ? 68 : 61;
      const label = svgEl('text', { class: 'node-label', x: CARD.w / 2, y: blockTop, 'text-anchor': 'middle' }, g);
      lines.forEach((line, i) => {
        const ts = svgEl('tspan', { x: CARD.w / 2, dy: i === 0 ? 0 : 15 }, label);
        ts.textContent = line;
      });
      const ip = svgEl('text', {
        class: 'node-ip', x: CARD.w / 2, y: blockTop + (lines.length - 1) * 15 + 17, 'text-anchor': 'middle',
      }, g);
      ip.textContent = n.ip || (n.dhcp ? 'DHCP' : '');
      const title = svgEl('title', {}, g);
      title.textContent = `${n.label}${n.ip ? ` · ${n.ip}` : ''}`;
      this.nodeEls[n.id] = g;
    }
  }

  // ------------------------------------------------------------ effects

  setCounters(c) {
    this._counters = c;
    if (!this.routerCounts) return;
    this.routerCounts.allowed.textContent = `${c.allowed ?? 0} allowed`;
    this.routerCounts.blocked.textContent = `${c.blocked ?? 0} blocked`;
  }

  // A ring that grows out of a machine's card and fades.
  pulse(id, kind) {
    const n = this.L?.nodes[id];
    if (!n || reducedMotion()) {
      if (n) this._flash(id, kind);
      return;
    }
    const ring = svgEl('rect', {
      class: `pulse pulse--${kind}`, x: n.x, y: n.y, width: CARD.w, height: CARD.h, rx: 16,
    }, this.layers.fx);
    const anim = ring.animate(
      [{ transform: 'scale(1)', opacity: 0.9 }, { transform: 'scale(1.16)', opacity: 0 }],
      { duration: kind === 'violation' ? 900 : 700, easing: 'cubic-bezier(.2,.7,.3,1)', iterations: kind === 'violation' ? 2 : 1 },
    );
    anim.onfinish = () => ring.remove();
    this._flash(id, kind);
  }

  _flash(id, kind) {
    const g = this.nodeEls?.[id];
    if (!g) return;
    const cls = `is-hit-${kind}`;
    g.classList.remove(cls);
    // Restart the transition so back-to-back hits each show.
    void g.getBoundingClientRect();
    g.classList.add(cls);
    clearTimeout(g[`_t_${kind}`]);
    g[`_t_${kind}`] = setTimeout(() => g.classList.remove(cls), kind === 'violation' ? 2600 : 1100);
  }

  // A ring around a router port, when the firewall stops something there.
  flashPoint(p, kind) {
    if (!p || reducedMotion()) return;
    const ring = svgEl('circle', { class: `port-flash port-flash--${kind}`, cx: p.x, cy: p.y, r: 9 }, this.layers.fx);
    const anim = ring.animate(
      [{ transform: 'scale(0.6)', opacity: 1 }, { transform: 'scale(2.4)', opacity: 0 }],
      { duration: 600, easing: 'cubic-bezier(.2,.7,.3,1)' },
    );
    anim.onfinish = () => ring.remove();
  }

  // A result marker (check, cross, warning) where a connection ended. Repeats
  // at the same place count up instead of piling up.
  mark(key, p, kind, by = 1) {
    if (!p) return;
    let m = this.marks.get(key);
    if (!m || !m.g.isConnected) {
      const g = svgEl('g', { class: `mark mark--${kind}`, transform: `translate(${p.x} ${p.y})` }, this.layers.fx);
      const inner = svgEl('g', { class: 'mark-inner' }, g);
      const pill = svgEl('rect', { class: 'mark-pill', x: -10, y: -10, width: 20, height: 20, rx: 10 }, inner);
      useIcon(MARK_ICON[kind], -6.5, -6.5, 13, inner, 'mark-icon');
      const count = svgEl('text', { class: 'mark-count', x: 13, y: 4 }, inner);
      m = { g, pill, count, n: 0, kind };
      this.marks.set(key, m);
      if (!reducedMotion()) {
        inner.animate(
          [{ transform: 'scale(0.2)', opacity: 0 }, { transform: 'scale(1.12)', opacity: 1, offset: 0.6 }, { transform: 'scale(1)', opacity: 1 }],
          { duration: 380, easing: 'cubic-bezier(.3,.7,.4,1)' },
        );
      }
    }
    m.n += by;
    if (m.n > 1) {
      m.count.textContent = String(m.n);
      const w = 20 + textWidth(String(m.n), MARK_FONT) + 8;
      m.pill.setAttribute('width', w);
    }
    m.g.classList.remove('is-leaving');
    clearTimeout(m.timer);
    m.timer = setTimeout(() => {
      m.g.classList.add('is-leaving');
      m.timer = setTimeout(() => {
        m.g.remove();
        if (this.marks.get(key) === m) this.marks.delete(key);
      }, 500);
    }, MARK_LIFE[kind] || 2500);
  }

  // A status pill on a machine (infected, records locked, alert). It takes
  // the place of the address line while it lasts, so it never covers
  // anything around the card.
  setBadge(id, kind, text = '', redraw = false) {
    if (!redraw) {
      if (kind) this.badges.set(id, { kind, text });
      else this.badges.delete(id);
    }
    const g = this.nodeEls?.[id];
    if (!g) return;
    const icons = { infected: 'bug', locked: 'lock', alerted: 'bell' };
    const label = text || { infected: 'Infected', locked: 'Locked', alerted: 'Alert' }[kind];
    const w = Math.min(CARD.w - 12, 28 + textWidth(label || '', BADGE_FONT));
    const old = g.querySelector('.badge');
    if (old && kind && old.dataset.kind === kind) {
      // Same badge, new count ("3 locked" -> "4 locked"): no new entrance.
      old.querySelector('.badge-pill').setAttribute('x', -w / 2);
      old.querySelector('.badge-pill').setAttribute('width', w);
      old.querySelector('.badge-icon').setAttribute('x', -w / 2 + 7);
      const t = old.querySelector('.badge-text');
      t.setAttribute('x', -w / 2 + 22);
      t.textContent = label;
      return;
    }
    old?.remove();
    for (const k of ['infected', 'locked', 'alerted']) g.classList.toggle(`is-${k}`, k === kind);
    if (!kind) return;
    const b = svgEl('g', { class: `badge badge--${kind}`, 'data-kind': kind, transform: `translate(${CARD.w / 2} ${BADGE_Y})` }, g);
    const inner = svgEl('g', { class: 'badge-inner' }, b);
    svgEl('rect', { class: 'badge-pill', x: -w / 2, y: -BADGE_H / 2, width: w, height: BADGE_H, rx: BADGE_H / 2 }, inner);
    useIcon(icons[kind], -w / 2 + 7, -5.5, 11, inner, 'badge-icon');
    const t = svgEl('text', { class: 'badge-text', x: -w / 2 + 22, y: 3.7 }, inner);
    t.textContent = label;
    if (!redraw && !reducedMotion()) {
      inner.animate(
        [{ transform: 'scale(0.4)', opacity: 0 }, { transform: 'scale(1.08)', opacity: 1, offset: 0.6 }, { transform: 'scale(1)', opacity: 1 }],
        { duration: 420, easing: 'cubic-bezier(.3,.7,.4,1)' },
      );
    }
  }

  clearBadges(kind) {
    for (const [id, b] of [...this.badges]) if (!kind || b.kind === kind) this.setBadge(id, null);
  }

  // Length of an SVG path string, using one hidden element.
  measure(d) {
    this.measurePath.setAttribute('d', d);
    return this.measurePath.getTotalLength();
  }
}

const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
export function reducedMotion() {
  return motionQuery.matches;
}
