// Animates connections along their paths.
//
// Allowed: a green pulse travels all the way to the target.
// Blocked: a red pulse runs into the firewall (or the zone's switch) and stops.
// Violation: a forbidden connection that got through; it reaches the target
// in hot pink, leaves a marching hazard trace and makes the target flash.
//
// The test suite fires a dozen probes at once and a scan can fire hundreds,
// so starts are paced (one every GAP_MS) and repeats of the same connection
// that arrive while one is still in flight are counted onto it instead of
// drawn again.

import { connectionPath } from './layout.js';
import { reducedMotion, svgEl } from './scene.js';

const SPEED = 540; // user units per second
const MIN_SECONDS = 0.65;
const MAX_SECONDS = 1.7;
const TRAIL = 64;
const GAP_MS = 95;
const BURST_GAP_MS = 45;
const MAX_ACTIVE = 18;
const MERGE_MS = 1100;
const STALE_MS = 6000;
const LINGER = { allowed: 650, blocked: 450, broken: 1600, violation: 3600 };
const FADE = { allowed: 900, blocked: 800, broken: 1000, violation: 1400 };

const easeInOut = (p) => -(Math.cos(Math.PI * p) - 1) / 2;
const easeIntoWall = (p) => 0.3 * p + 0.7 * p * p;

export class Flows {
  constructor(scene, { onStart, onArrive }) {
    this.scene = scene;
    this.onStart = onStart;
    this.onArrive = onArrive;
    this.queue = [];
    this.active = [];
    this.geo = new Map();
    this.lastStart = 0;
    this.raf = 0;
    this.frame = this.frame.bind(this);
  }

  reset() {
    for (const a of this.active) a.g.remove();
    this.active = [];
    this.queue = [];
    this.geo.clear();
  }

  add(flow) {
    const key = `${flow.from}>${flow.to}>${flow.result}`;
    const now = performance.now();
    if (!flow.stream) {
      const same = this.active.find((a) => a.key === key && now - a.t0 < MERGE_MS && a.phase === 'travel')
        || this.queue.find((q) => q.key === key);
      if (same) {
        same.count = (same.count || 1) + 1;
        same.ports?.add(flow.port);
        if (same.tag) same.tag.textContent = `×${same.count}`;
        return;
      }
    }
    this.queue.push({ key, flow, count: 1, ports: new Set([flow.port]), queuedAt: now });
    this.kick();
  }

  kick() {
    if (!this.raf) this.raf = requestAnimationFrame(this.frame);
  }

  geometry(flow) {
    const variant = this.scene.variant;
    const id = `${variant}|${flow.from}|${flow.to}|${flow.route}`;
    if (this.geo.has(id)) return this.geo.get(id);
    const p = connectionPath(this.scene.layout, variant, flow.from, flow.to, flow.route);
    let g = null;
    if (p && p.segments.length) {
      const head = `M ${p.start.x} ${p.start.y}`;
      const d = `${head} ${p.segments.join(' ')}`;
      const len = this.scene.measure(d);
      const stopLen = p.stopAfter > 0 ? this.scene.measure(`${head} ${p.segments.slice(0, p.stopAfter).join(' ')}`) : 0;
      g = { d, len, stopLen, end: p.end, endKind: p.endKind, endNormal: p.endNormal };
    }
    this.geo.set(id, g);
    return g;
  }

  start(item, now) {
    const { flow } = item;
    const geo = this.geometry(flow);
    this.onStart?.(flow, item);
    if (!geo) return;
    const stops = flow.result === 'blocked' || flow.result === 'broken';
    const travel = stops ? geo.stopLen || geo.len : geo.len;
    const stale = now - item.queuedAt > STALE_MS;
    const instant = reducedMotion() || stale;
    const seconds = Math.min(MAX_SECONDS, Math.max(MIN_SECONDS, travel / SPEED)) * (flow.stream ? 0.8 : 1);

    const g = svgEl('g', { class: `flow flow--${flow.result}${flow.stream ? ' flow--stream' : ''}` }, this.scene.layers.flows);
    const wake = svgEl('path', { class: 'flow-wake', d: geo.d }, g);
    const trail = svgEl('path', { class: 'flow-trail', d: geo.d }, g);
    const head = svgEl('circle', { class: 'flow-head', r: flow.stream ? 3.2 : 4.6, cx: -99, cy: -99 }, g);
    wake.style.strokeDasharray = `0 ${geo.len + 1}`;
    trail.style.strokeDasharray = `0 ${geo.len + TRAIL}`;
    const a = {
      ...item, g, wake, trail, head, geo, travel, stops,
      t0: now, dur: seconds * 1000, phase: 'travel', instant,
    };
    if (item.count > 1) this.addTag(a);
    this.active.push(a);
    if (instant) this.arrive(a, now);
  }

  addTag(a) {
    a.tag = svgEl('text', { class: 'flow-tag', x: -99, y: -99 }, a.g);
    a.tag.textContent = `×${a.count}`;
  }

  frame(now) {
    this.raf = 0;
    const gap = this.queue.length > 12 ? BURST_GAP_MS : GAP_MS;
    if (this.queue.length && this.active.length < MAX_ACTIVE && now - this.lastStart >= gap) {
      this.start(this.queue.shift(), now);
      this.lastStart = now;
    }
    for (const a of [...this.active]) this.step(a, now);
    if (this.active.length || this.queue.length) this.kick();
  }

  step(a, now) {
    if (a.phase === 'travel') {
      const p = Math.min(1, (now - a.t0) / a.dur);
      const s = (a.stops ? easeIntoWall(p) : easeInOut(p)) * a.travel;
      this.place(a, s);
      if (p >= 1) this.arrive(a, now);
      return;
    }
    const t = now - a.tArrive;
    if (a.phase === 'impact') {
      // Bounce back off the wall a little, then fade.
      const k = Math.min(1, t / 380);
      const back = Math.sin(k * Math.PI) * 9 * (1 - k * 0.5);
      const pt = a.geo.len ? this.pointAt(a, Math.max(0, a.travel - back)) : null;
      if (pt) {
        a.head.setAttribute('cx', pt.x);
        a.head.setAttribute('cy', pt.y);
      }
      a.head.setAttribute('opacity', String(1 - k));
      if (k >= 1) a.phase = 'linger';
    }
    const linger = LINGER[a.flow.result] ?? 600;
    const fade = FADE[a.flow.result] ?? 800;
    if (t > linger) {
      const k = Math.min(1, (t - linger) / fade);
      a.g.setAttribute('opacity', String(1 - k));
      if (k >= 1) {
        a.g.remove();
        this.active.splice(this.active.indexOf(a), 1);
      }
    }
  }

  pointAt(a, s) {
    return a.wake.getPointAtLength(Math.max(0, Math.min(a.geo.len, s)));
  }

  place(a, s) {
    const pt = this.pointAt(a, s);
    a.head.setAttribute('cx', pt.x);
    a.head.setAttribute('cy', pt.y);
    a.wake.style.strokeDasharray = `${s} ${a.geo.len + 1}`;
    const t = Math.min(TRAIL, s);
    a.trail.style.strokeDasharray = `${t} ${a.geo.len + TRAIL}`;
    a.trail.style.strokeDashoffset = `${-(s - t)}`;
    if (a.tag) {
      a.tag.setAttribute('x', pt.x + 9);
      a.tag.setAttribute('y', pt.y - 8);
    }
  }

  arrive(a, now) {
    a.tArrive = now;
    this.place(a, a.travel);
    a.trail.style.opacity = '0';
    if (a.stops) {
      a.phase = a.instant ? 'linger' : 'impact';
      if (a.instant) a.head.setAttribute('opacity', '0');
    } else {
      a.phase = 'linger';
      a.head.setAttribute('opacity', '0');
      if (a.flow.result === 'violation' && !a.flow.stream) {
        // Swap the revealed trace for a marching hazard line.
        a.wake.style.strokeDasharray = '';
        a.wake.classList.add('flow-wake--hazard');
      }
    }
    if (a.tag) a.tag.setAttribute('opacity', '0.9');
    const endPoint = this.pointAt(a, a.travel);
    // Where the result marker goes. Every path arrives at a machine along the
    // card's outward direction, so one spot just outside the card serves all
    // connections to it. Anything that stops at (or ends in) the router or a
    // switch is marked just before the wall.
    let markPoint;
    if (!a.stops && a.geo.endKind === 'node') {
      const [nx, ny] = a.geo.endNormal;
      markPoint = { x: a.geo.end.x + nx * 16, y: a.geo.end.y + ny * 16 };
    } else {
      const p = this.pointAt(a, a.travel - 15);
      markPoint = { x: p.x, y: p.y };
    }
    this.onArrive?.(a.flow, { point: endPoint, markPoint, count: a.count, stopped: a.stops, endKind: a.geo.endKind });
  }
}
