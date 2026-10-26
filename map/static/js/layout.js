// Where everything goes, computed from policy/clinic.yml.
//
// The picture: a clinic building with the router/firewall in the middle,
// zones (VLANs) above and below it, and the outside world (internet, home
// office) to the left. Every zone connects to the router through its own
// port, which is the whole point of segmentation: traffic between zones has
// to pass the firewall. The flat "before" network keeps every machine in the
// same place but removes the zones: every machine is wired to one switch in
// the middle, and the router moves to the outside wall, where it only links
// the clinic to the internet. Nothing stands between two machines inside.
//
// All numbers are SVG user units; the SVG scales to fit its box.

export const CARD = { w: 104, h: 110 };

const G = {
  cardGap: 10,
  zonePad: 14,
  zoneHead: 36, // band holding the zone's name
  zoneWire: 34, // band between the machines and the zone's switch port
  zoneGap: 26,
  maxCols: 3,
  buildingPad: 30,
  buildingHead: 40,
  router: { w: 320, h: 84 },
  flatRouter: { w: 110, h: 96 },
  flatSwitch: { minW: 330, h: 70, portStep: 40, portInset: 46 },
  outsideGap: 124, // room for the flat network's router, which sits on the wall
  outsideStackGap: 40,
  margin: 22,
  bandMin: 74, // vertical gap between a zone row and the router
  bandMax: 150,
};

const NORMAL = { down: [0, 1], up: [0, -1], right: [1, 0], left: [-1, 0] };

// Text measurement for wrapping labels inside cards.
const ctx = document.createElement('canvas').getContext('2d');
export const FONT_STACK = getComputedStyle(document.documentElement).getPropertyValue('--font').trim()
  || '-apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
export function textWidth(text, font) {
  ctx.font = font;
  return ctx.measureText(text).width;
}

export const LABEL_FONT = `600 13px ${FONT_STACK}`;
const ZONE_FONT = `600 13.5px ${FONT_STACK}`;
const VLAN_FONT = '500 10.5px ui-monospace, "SF Mono", Menlo, Consolas, monospace';

export function wrapLabel(text, maxWidth, font = LABEL_FONT, maxLines = 2) {
  const lines = wrapWords(String(text), maxWidth, font);
  if (lines.length <= maxLines) return lines;
  // "Security monitor (SIEM)": the bracketed part is a nice-to-have.
  const plain = String(text).replace(/\s*\([^)]*\)\s*$/, '');
  if (plain !== text) return wrapLabel(plain, maxWidth, font, maxLines);
  const kept = lines.slice(0, maxLines);
  kept[maxLines - 1] = `${kept[maxLines - 1]}…`;
  return kept;
}

function wrapWords(text, maxWidth, font) {
  const words = text.split(/\s+/);
  const lines = [];
  let line = '';
  for (const word of words) {
    const next = line ? `${line} ${word}` : word;
    if (!line || textWidth(next, font) <= maxWidth) {
      line = next;
    } else {
      lines.push(line);
      line = word;
    }
  }
  if (line) lines.push(line);
  return lines;
}

function groupZones(topology) {
  const zones = new Map();
  for (const z of topology.zones) zones.set(z.id, { ...z, nodes: [] });
  for (const n of topology.nodes) {
    if (n.id === 'router' || n.zone === 'core') continue;
    let zone = zones.get(n.zone);
    if (!zone) {
      // A machine in a zone policy does not describe: give it a room anyway.
      zone = { id: n.zone || 'other', label: n.zone ? n.zone.replace(/-/g, ' ') : 'Other', vlan: null, inside: true, nodes: [] };
      zones.set(zone.id, zone);
    }
    zone.nodes.push(n);
  }
  const inside = [...zones.values()].filter((z) => z.inside)
    .sort((a, b) => (a.vlan ?? 999) - (b.vlan ?? 999));
  const outside = [...zones.values()].filter((z) => !z.inside);
  return { inside, outside };
}

function sizeZone(zone, face) {
  const n = Math.max(1, zone.nodes.length);
  const cols = face === 'right' ? 1 : Math.min(n, G.maxCols);
  const rows = Math.ceil(n / cols);
  const cardsW = cols * CARD.w + (cols - 1) * G.cardGap;
  const cardsH = rows * CARD.h + (rows - 1) * G.cardGap;
  const vlan = zone.vlan != null ? `VLAN ${zone.vlan}` : '';
  const headW = textWidth(zone.label, ZONE_FONT) + (vlan ? 12 + textWidth(vlan, VLAN_FONT) : 0);
  let w;
  let h;
  if (face === 'right') {
    // Outside zones wire sideways; the extra room keeps a result marker
    // between the card and the zone's port.
    w = Math.max(G.zonePad + cardsW + G.zoneWire + 14, headW + 2 * G.zonePad);
    h = G.zoneHead + cardsH + G.zonePad;
  } else {
    w = Math.max(cardsW + 2 * G.zonePad, headW + 2 * G.zonePad);
    h = G.zoneHead + cardsH + G.zoneWire;
  }
  return { ...zone, face, cols, rows, cardsW, cardsH, vlanText: vlan, w: Math.ceil(w), h };
}

function placeZone(z, x, y, nodes) {
  z.x = x;
  z.y = y;
  z.cx = x + z.w / 2;
  let cardsTop;
  let cardsLeft;
  if (z.face === 'down') {
    cardsTop = y + G.zoneHead;
    cardsLeft = z.cx - z.cardsW / 2;
    z.gate = { x: z.cx, y: y + z.h };
    z.labelPos = { x: x + G.zonePad, y: y + 23 };
  } else if (z.face === 'up') {
    cardsTop = y + G.zoneWire;
    cardsLeft = z.cx - z.cardsW / 2;
    z.gate = { x: z.cx, y };
    z.labelPos = { x: x + G.zonePad, y: y + z.h - 14 };
  } else {
    cardsTop = y + G.zoneHead;
    cardsLeft = x + G.zonePad;
    z.gate = { x: x + z.w, y: cardsTop + z.cardsH / 2 };
    z.labelPos = { x: x + G.zonePad, y: y + 23 };
  }
  z.vlanPos = { x: x + z.w - G.zonePad, y: z.labelPos.y };
  z.nodes.forEach((n, i) => {
    const col = i % z.cols;
    const row = Math.floor(i / z.cols);
    // A partly filled last row is centred.
    const inRow = Math.min(z.cols, z.nodes.length - row * z.cols);
    const rowW = inRow * CARD.w + (inRow - 1) * G.cardGap;
    const left = z.face === 'right' ? cardsLeft : z.cx - rowW / 2;
    const cx = left + col * (CARD.w + G.cardGap);
    const cy = cardsTop + row * (CARD.h + G.cardGap);
    const attach = z.face === 'down' ? { x: cx + CARD.w / 2, y: cy + CARD.h }
      : z.face === 'up' ? { x: cx + CARD.w / 2, y: cy }
        : { x: cx + CARD.w, y: cy + CARD.h / 2 };
    nodes[n.id] = {
      ...n, x: cx, y: cy, w: CARD.w, h: CARD.h, cx: cx + CARD.w / 2, cy: cy + CARD.h / 2,
      zone: z.id, face: z.face, attach,
    };
  });
}

function rowWidth(zones) {
  return zones.reduce((s, z) => s + z.w, 0) + Math.max(0, zones.length - 1) * G.zoneGap;
}

function spreadPorts(n, center, span, maxStep = 64) {
  if (n <= 1) return [center];
  const step = Math.min(maxStep, span / (n - 1));
  return Array.from({ length: n }, (_, i) => center + (i - (n - 1) / 2) * step);
}

export function computeLayout(topology, aspect) {
  const { inside, outside } = groupZones(topology);
  const half = Math.ceil(inside.length / 2);
  const top = inside.slice(0, half).map((z) => sizeZone(z, 'down'));
  const bottom = inside.slice(half).map((z) => sizeZone(z, 'up'));
  const outs = outside.map((z) => sizeZone(z, 'right'));

  const topH = Math.max(0, ...top.map((z) => z.h));
  const botH = Math.max(0, ...bottom.map((z) => z.h));
  const R = G.router;
  const innerW = Math.max(rowWidth(top), rowWidth(bottom), R.w + 260);
  const bw = innerW + 2 * G.buildingPad;
  const outW = outs.length ? Math.max(...outs.map((z) => z.w)) : 0;
  const outStackH = outs.reduce((s, z) => s + z.h, 0) + Math.max(0, outs.length - 1) * G.outsideStackGap;
  const W0 = G.margin * 2 + (outs.length ? outW + G.outsideGap : 0) + bw;

  const heightFor = (band) => G.buildingHead + topH + band + R.h + (bottom.length ? band + botH : 0) + G.buildingPad;
  const twoBands = bottom.length ? 2 : 1;
  const want = W0 / aspect - 2 * G.margin;
  const band = Math.max(G.bandMin, Math.min(G.bandMax, (want - heightFor(0)) / twoBands));
  const bh = Math.max(heightFor(band), outStackH + 2 * G.buildingPad);
  const H0 = bh + 2 * G.margin;

  const bx = G.margin + (outs.length ? outW + G.outsideGap : 0);
  const by = G.margin;
  const bcx = bx + bw / 2;
  const building = { x: bx, y: by, w: bw, h: bh, labelPos: { x: bx + 22, y: by + 26 } };

  const nodes = {};
  const zones = {};
  // Top row: zones hang above the router, aligned on their bottom edge.
  const rowTopBottom = by + G.buildingHead + topH;
  let x = bcx - rowWidth(top) / 2;
  for (const z of top) {
    placeZone(z, x, rowTopBottom - z.h, nodes);
    zones[z.id] = z;
    x += z.w + G.zoneGap;
  }
  const routerY = rowTopBottom + band;
  const routerCy = routerY + R.h / 2;
  const rowBotTop = routerY + R.h + band;
  x = bcx - rowWidth(bottom) / 2;
  for (const z of bottom) {
    placeZone(z, x, rowBotTop, nodes);
    zones[z.id] = z;
    x += z.w + G.zoneGap;
  }
  // Outside: stacked to the left, centred on the router.
  let y = routerCy - outStackH / 2;
  for (const z of outs) {
    placeZone(z, G.margin + (outW - z.w), y, nodes);
    zones[z.id] = z;
    y += z.h + G.outsideStackGap;
  }

  // The segmented router: one port per zone, on the side facing that zone.
  const router = { x: bcx - R.w / 2, y: routerY, w: R.w, h: R.h, cx: bcx, cy: routerCy, ports: {} };
  spreadPorts(top.length, bcx, R.w - 120).forEach((px, i) => {
    router.ports[top[i].id] = { x: px, y: routerY, n: NORMAL.up };
  });
  spreadPorts(bottom.length, bcx, R.w - 120).forEach((px, i) => {
    router.ports[bottom[i].id] = { x: px, y: routerY + R.h, n: NORMAL.down };
  });
  router.wan = { x: router.x, y: routerCy, n: NORMAL.left };
  for (const z of outs) router.ports[z.id] = router.wan;

  // The flat network's router sits on the outside wall: it only links the
  // office to the internet, through one cable to the switch.
  const F = G.flatRouter;
  const fx = bx - F.w / 2;
  const flatRouter = { x: fx, y: routerCy - F.h / 2, w: F.w, h: F.h, cx: fx + F.w / 2, cy: routerCy };
  flatRouter.wan = { x: fx, y: routerCy, n: NORMAL.left };
  flatRouter.lan = { x: fx + F.w, y: routerCy, n: NORMAL.right };

  // The flat network's one switch, where the segmented firewall would be.
  // Each machine above it plugs into its top edge, each machine below into
  // its bottom edge, in the same left-to-right order, so no cables cross.
  const S = G.flatSwitch;
  const above = top.flatMap((z) => z.nodes.map((n) => nodes[n.id])).sort((a, b) => a.cx - b.cx);
  const below = bottom.flatMap((z) => z.nodes.map((n) => nodes[n.id])).sort((a, b) => a.cx - b.cx);
  const most = Math.max(above.length, below.length, 1);
  const sw = Math.max(S.minW, (most - 1) * S.portStep + 2 * S.portInset);
  const flatSwitch = { x: bcx - sw / 2, y: routerCy - S.h / 2, w: sw, h: S.h, cx: bcx, cy: routerCy, ports: {}, zonePorts: {} };
  flatSwitch.west = { x: flatSwitch.x, y: routerCy, n: NORMAL.left };
  const plug = (list, edgeY, n) => spreadPorts(list.length, bcx, sw - 2 * S.portInset).forEach((px, i) => {
    flatSwitch.ports[list[i].id] = { x: px, y: edgeY, n };
  });
  plug(above, flatSwitch.y, NORMAL.up);
  plug(below, flatSwitch.y + S.h, NORMAL.down);
  // An unknown machine in a zone (a new DHCP guest) uses the middle of its
  // zone's ports.
  for (const z of [...top, ...bottom]) {
    const ps = z.nodes.map((n) => flatSwitch.ports[n.id]);
    flatSwitch.zonePorts[z.id] = {
      x: ps.length ? ps.reduce((sum, p) => sum + p.x, 0) / ps.length : bcx,
      y: z.face === 'down' ? flatSwitch.y : flatSwitch.y + S.h,
      n: NORMAL[z.face === 'down' ? 'up' : 'down'],
    };
  }

  // Fit the drawing to the box it is shown in, centred.
  const vbW = Math.max(W0, H0 * aspect);
  const vbH = Math.max(H0, W0 / aspect);
  const viewBox = { x: -(vbW - W0) / 2, y: -(vbH - H0) / 2, w: vbW, h: vbH };

  return { viewBox, building, zones, nodes, router, flatRouter, flatSwitch, band, rows: { top, bottom, outside: outs } };
}

// ------------------------------------------------------------------ paths

const fmt = (v) => Math.round(v * 10) / 10;
const pt = (p) => `${fmt(p.x)} ${fmt(p.y)}`;

// A cubic from a to b, leaving a along normal na and arriving at b from
// the direction of nb (both pointing away from the curve's ends).
function curve(a, na, b, nb, k) {
  const c1 = { x: a.x + na[0] * k, y: a.y + na[1] * k };
  const c2 = { x: b.x + nb[0] * k, y: b.y + nb[1] * k };
  return `C ${pt(c1)} ${pt(c2)} ${pt(b)}`;
}

function along(a, b, n) {
  return Math.abs((b.x - a.x) * n[0] + (b.y - a.y) * n[1]);
}

function neg(n) {
  return [-n[0], -n[1]];
}

// Endpoint description: a machine, an unknown machine in a zone ("@zone"),
// or the router itself.
function endpoint(L, id) {
  if (id === 'router') return { kind: 'router' };
  if (id && id.startsWith('@')) {
    const zone = L.zones[id.slice(1)];
    return zone ? { kind: 'zone', zone, at: zone.gate, n: NORMAL[zone.face] } : null;
  }
  const node = L.nodes[id];
  if (!node) return null;
  return { kind: 'node', node, zone: L.zones[node.zone], at: node.attach, n: NORMAL[node.face] };
}

// Machine -> its zone's switch port.
function wireUp(e) {
  if (e.kind !== 'node') return null;
  const g = e.zone.gate;
  const n = NORMAL[e.zone.face];
  return curve(e.at, n, g, neg(n), Math.max(10, along(e.at, g, n) * 0.55));
}

function wireDown(e) {
  if (e.kind !== 'node') return null;
  const g = e.zone.gate;
  const n = NORMAL[e.zone.face];
  return curve(g, neg(n), e.at, n, Math.max(10, along(e.at, g, n) * 0.55));
}

// Zone switch port <-> router port.
function trunk(gate, gn, port) {
  return curve(gate, gn, port, port.n, Math.max(24, along(gate, port, gn) * 0.5));
}

function trunkBack(port, gate, gn) {
  return curve(port, port.n, gate, gn, Math.max(24, along(gate, port, gn) * 0.5));
}

// Static wiring drawn under everything: machine to zone, zone to router.
export function wires(L, variant) {
  const out = [];
  const flat = variant === 'flat';
  if (flat) {
    // Every machine inside on its own cable to the one switch.
    for (const [id, port] of Object.entries(L.flatSwitch.ports)) {
      const node = L.nodes[id];
      out.push({ kind: 'wire', zone: node.zone, d: `M ${pt(node.attach)} ${flatCable(node.attach, NORMAL[node.face], port)}` });
    }
    out.push({ kind: 'trunk', zone: null, d: `M ${pt(L.flatSwitch.west)} ${straight(L.flatRouter.lan)}` });
  }
  for (const z of Object.values(L.zones)) {
    const n = NORMAL[z.face];
    // In the flat network, machines inside are wired to the switch (above).
    if (flat && z.face !== 'right') continue;
    // Remote machines that come in over the VPN get a tunnel, not a plain link.
    const vpn = !flat && z.face === 'right' && z.nodes.some((node) => node.vpn);
    const port = flat ? L.flatRouter.wan : L.router.ports[z.id];
    out.push({ kind: 'trunk', vpn, zone: z.id, d: `M ${pt(z.gate)} ${trunk(z.gate, n, port)}` });
    for (const node of z.nodes) {
      const e = endpoint(L, node.id);
      out.push({ kind: 'wire', zone: z.id, d: `M ${pt(e.at)} ${wireUp(e)}` });
    }
  }
  return out;
}

// The path a connection takes, as segments, plus where a block stops it.
//   route: router | switch | direct | outside (decided by the server)
// Returns { segments: [d...], start, stopAfter, end } where stopAfter is the
// number of segments travelled before the point that blocks it.
export function connectionPath(L, variant, from, to, route) {
  const a = endpoint(L, from);
  const b = endpoint(L, to);
  if (!a || !b) return null;
  if (variant === 'flat' && route !== 'outside') return flatPath(L, a, b, route);
  const R = L.router;
  const segs = [];
  let start;
  let stopAfter;

  if (route === 'router') {
    const portA = a.kind === 'router' ? null : R.ports[a.zone.id];
    const portB = b.kind === 'router' ? null : R.ports[b.zone.id];
    if (a.kind === 'router') {
      // Rare: the router starts a connection. Leave from the right port.
      start = portB;
    } else {
      start = a.at;
      if (a.kind === 'node') segs.push(wireUp(a));
      segs.push(trunk(a.zone.gate, NORMAL[a.zone.face], portA));
    }
    stopAfter = segs.length;
    if (b.kind === 'router') {
      return { segments: segs, start, stopAfter, end: portA, endKind: 'router', endNormal: portA.n };
    }
    if (portA && portA !== portB) {
      // Through the router (hidden under it on screen).
      const k = Math.max(R.h * 0.55, Math.abs(portA.x - portB.x) * 0.25);
      segs.push(curve(portA, neg(portA.n), portB, neg(portB.n), k));
    }
    segs.push(trunkBack(portB, b.zone.gate, NORMAL[b.zone.face]));
    if (b.kind === 'node') segs.push(wireDown(b));
    return { segments: segs, start, stopAfter, end: b.at, endKind: b.kind, endNormal: b.n };
  }

  if (route === 'switch' && a.zone && a.zone === b.zone) {
    // Same zone: down to the zone's switch and back up. The router never sees it.
    start = a.at;
    if (a.kind === 'node') segs.push(wireUp(a));
    stopAfter = segs.length;
    if (b.kind === 'node') segs.push(wireDown(b));
    return { segments: segs, start, stopAfter, end: b.at, endKind: b.kind, endNormal: b.n };
  }

  // Between two places outside the clinic: straight from one to the other.
  start = a.at;
  const dist = Math.hypot(b.at.x - a.at.x, b.at.y - a.at.y);
  const k = Math.max(40, Math.min(L.band * 1.25, 30 + dist * 0.32));
  segs.push(curve(a.at, a.n, b.at, b.n, k));
  return { segments: segs, start, stopAfter: segs.length, end: b.at, endKind: b.kind, endNormal: b.n };
}

// ------------------------------------------------------------------ flat paths

function straight(p) {
  return `L ${pt(p)}`;
}

// A machine's cable to its switch port.
function flatCable(at, n, port) {
  return curve(at, n, port, port.n, Math.max(14, along(at, port, n) * 0.55));
}

function flatCableBack(port, at, n) {
  return curve(port, port.n, at, n, Math.max(14, along(at, port, n) * 0.55));
}

// From an endpoint to its port on the flat switch. `wall` is how many of the
// segments reach the router's outside port (where the router stops what
// comes in from the internet).
function flatOut(L, e) {
  const S = L.flatSwitch;
  const R = L.flatRouter;
  if (e.kind === 'router') return { start: R.lan, segs: [straight(S.west)], port: S.west };
  if (e.zone.inside) {
    const port = e.kind === 'node' ? S.ports[e.node.id] : S.zonePorts[e.zone.id];
    if (!port) return null;
    return { start: e.kind === 'node' ? e.at : port, segs: e.kind === 'node' ? [flatCable(e.at, e.n, port)] : [], port };
  }
  const segs = [];
  if (e.kind === 'node') segs.push(wireUp(e));
  segs.push(trunk(e.zone.gate, NORMAL[e.zone.face], R.wan));
  const wall = segs.length;
  segs.push(straight(R.lan), straight(S.west));
  return { start: e.at, segs, port: S.west, wall };
}

// From the flat switch to an endpoint. `wall` is how many segments reach the
// router's inside port (where the router stops what goes out).
function flatIn(L, e) {
  const S = L.flatSwitch;
  const R = L.flatRouter;
  if (e.kind === 'router') return { port: S.west, segs: [straight(R.lan)], end: R.lan, endNormal: R.lan.n };
  if (e.zone.inside) {
    const port = e.kind === 'node' ? S.ports[e.node.id] : S.zonePorts[e.zone.id];
    if (!port) return null;
    return {
      port, segs: e.kind === 'node' ? [flatCableBack(port, e.at, e.n)] : [], end: e.kind === 'node' ? e.at : port, endNormal: e.kind === 'node' ? e.n : port.n,
    };
  }
  const segs = [straight(R.lan)];
  const wall = segs.length;
  segs.push(straight(R.wan), trunkBack(R.wan, e.zone.gate, NORMAL[e.zone.face]));
  if (e.kind === 'node') segs.push(wireDown(e));
  return { port: S.west, segs, end: e.at, endNormal: e.n, wall };
}

// The flat network: every connection goes through the one switch. Only
// traffic to or from outside meets the router, and the router is the only
// thing that can stop it; inside, a refused connection runs all the way to
// the machine that refused it.
function flatPath(L, a, b, route) {
  const R = L.flatRouter;
  const outside = (e) => e.kind !== 'router' && !e.zone.inside;
  if (outside(a) && b.kind === 'router') {
    // From the internet to the clinic's own address: ends at the router.
    const segs = [];
    if (a.kind === 'node') segs.push(wireUp(a));
    segs.push(trunk(a.zone.gate, NORMAL[a.zone.face], R.wan));
    return { segments: segs, start: a.at, stopAfter: segs.length, end: R.wan, endKind: 'router', endNormal: R.wan.n };
  }
  if (a.kind === 'router' && outside(b)) {
    const segs = [trunkBack(R.wan, b.zone.gate, NORMAL[b.zone.face])];
    if (b.kind === 'node') segs.push(wireDown(b));
    return { segments: segs, start: R.wan, stopAfter: segs.length, end: b.at, endKind: b.kind, endNormal: b.n };
  }
  const out = flatOut(L, a);
  const into = flatIn(L, b);
  if (!out || !into) return null;
  const segs = [...out.segs];
  if (out.port !== into.port) {
    // Across the switch, hidden under it on screen.
    const P = out.port;
    const Q = into.port;
    const k = L.flatSwitch.h * (P.n === Q.n ? 0.7 : 0.5);
    segs.push(curve(P, neg(P.n), Q, neg(Q.n), k));
  }
  const toSwitch = segs.length;
  segs.push(...into.segs);
  let stopAfter = segs.length;
  if (route === 'router') {
    if (out.wall !== undefined) stopAfter = out.wall;
    else if (into.wall !== undefined) stopAfter = toSwitch + into.wall;
  }
  const endKind = b.kind === 'router' ? 'router' : b.kind;
  return { segments: segs, start: out.start, stopAfter, end: into.end, endKind, endNormal: into.endNormal };
}
