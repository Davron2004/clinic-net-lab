// The clinic map page: connects to the map server's event stream and keeps
// the drawing, the sidebar and the controls in step with the lab.

import { installSprite } from './icons.js';
import { Scene } from './scene.js';
import { Flows } from './flows.js';
import {
  AlertsCard, Banner, Captions, Header, RecordsCard, Status, TestsCard, Toasts, isError, recordsEncrypted,
} from './panels.js';
import { plural } from './words.js';

installSprite();

const canvas = document.getElementById('canvas');
const scene = new Scene(document.getElementById('map'));
const app = { state: null, topoKey: '', aspect: 0, infectedUntil: 0, alerted: new Map() };

const header = new Header({ onRun: run });
const records = new RecordsCard();
const tests = new TestsCard();
const alerts = new AlertsCard();
const captions = new Captions();
const banner = new Banner();
const status = new Status();
const toasts = new Toasts();

const variant = () => app.state?.topology?.variant || 'clinic';

function nodeLabel(id) {
  if (id === 'router') return variant() === 'flat' ? 'Internet router' : 'Firewall';
  if (id?.startsWith('@')) {
    const zone = app.state?.topology?.zones.find((z) => z.id === id.slice(1));
    return `Unknown device (${zone?.label || id.slice(1)})`;
  }
  return app.state?.topology?.nodes.find((n) => n.id === id)?.label || id || 'Unknown';
}

const flows = new Flows(scene, {
  onStart(flow, item) {
    captions.push(flow, nodeLabel, variant(), item.count, item.ports?.size || 1);
  },
  onArrive(flow, info) {
    const kind = flow.result;
    const p = info.markPoint;
    if (info.stopped) {
      scene.mark(`${Math.round(p.x)},${Math.round(p.y)}:${kind}`, p, kind, info.count);
      scene.flashPoint(info.point, kind);
    } else if (info.endKind === 'router') {
      // Answered by the router itself (a name lookup): a flash at the port is
      // enough, and leaves room for the block markers that gather there.
      scene.flashPoint(info.point, kind);
    } else {
      scene.mark(`${Math.round(p.x)},${Math.round(p.y)}:${kind}`, p, kind, info.count);
      if (scene.layout?.nodes[flow.to]) scene.pulse(flow.to, kind === 'violation' ? 'violation' : 'allowed');
    }
    if (flow.counters) scene.setCounters(flow.counters);
  },
});

// ------------------------------------------------------------------ drawing

function rebuild(force = false) {
  const topo = app.state?.topology;
  if (!topo) return;
  const box = canvas.getBoundingClientRect();
  if (box.width < 10 || box.height < 10) return;
  const aspect = box.width / box.height;
  const key = JSON.stringify(topo);
  if (!force && key === app.topoKey && Math.abs(aspect - app.aspect) < 0.015) return;
  const variantChanged = app.state && app.lastVariant && app.lastVariant !== topo.variant;
  app.topoKey = key;
  app.aspect = aspect;
  app.lastVariant = topo.variant;
  flows.reset();
  scene.build(topo, aspect);
  placeToasts();
  scene.setCounters(app.state.counters || {});
  refreshBadges();
  if (variantChanged) {
    canvas.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 500, easing: 'ease-out' });
  }
}

// Toasts live under the outside world, left of the clinic's wall: line the
// column up with the outside zones, and stop it short of the zone above.
function placeToasts() {
  const L = scene.layout;
  const outs = L?.rows.outside || [];
  const box = canvas.getBoundingClientRect();
  if (!outs.length) {
    toasts.place({ left: 16, width: 268, bottom: 6, maxHeight: box.height / 3 });
    return;
  }
  const k = box.width / L.viewBox.w;
  const px = (x) => (x - L.viewBox.x) * k;
  const py = (y) => (y - L.viewBox.y) * k;
  const left = px(Math.min(...outs.map((z) => z.x)));
  const right = px(L.building.x) - 14;
  const bottom = box.height - py(L.building.y + L.building.h);
  const top = py(Math.max(...outs.map((z) => z.y + z.h))) + 14;
  toasts.place({ left, width: right - left, bottom, maxHeight: box.height - bottom - top });
}

// A toast has room for a short headline. Alert titles from the monitor put
// the evidence first and the meaning after a colon ("Imaging workstation
// was blocked 10 times in 30 seconds: scanning the network or malware
// spreading"), or the meaning in brackets at the end. The meaning is the
// headline; the full title stays in the alerts list.
function toastCopy(group) {
  const where = group.where ? nodeLabel(group.where) : '';
  const title = group.title;
  const cap = (t) => t.charAt(0).toUpperCase() + t.slice(1);
  const colon = title.indexOf(': ');
  if (colon > 0) {
    const meaning = title.slice(colon + 2).trim();
    // "Patient record deleted: patient-0003.json": a file name is not a meaning.
    if (/\s/.test(meaning)) return { title: cap(meaning), text: where || title.slice(0, colon) };
  }
  const bracket = title.match(/^(.*\S)\s*\(([^)]+)\)$/);
  if (bracket) return { title: bracket[1], text: cap(bracket[2]) };
  return { title, text: where };
}

let resizeTimer = 0;
new ResizeObserver(() => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    rebuild();
    placeToasts();
  }, 120);
}).observe(canvas);

// Badges pinned on machines: records locked > infected > recent alert.
function refreshBadges() {
  const s = app.state;
  if (!s || !scene.layout) return;
  const wanted = new Map();
  const now = Date.now();
  for (const [id, until] of app.alerted) {
    if (until > now) wanted.set(id, ['alerted', '']);
    else app.alerted.delete(id);
  }
  const sc = s.scenario;
  if (sc?.node && (sc.running || app.infectedUntil > now)) wanted.set(sc.node, ['infected', 'Infected']);
  const rec = s.records;
  if (rec?.total && (rec.intact < rec.total || rec.encrypted)) {
    const lost = Math.max(rec.total - rec.intact, rec.encrypted || 0);
    wanted.set(rec.node || 'emr', ['locked', `${lost} locked`]);
  }
  for (const id of Object.keys(scene.layout.nodes)) {
    const [kind, text] = wanted.get(id) || [null, ''];
    const current = scene.badges.get(id);
    if ((current?.kind || null) !== kind || (current?.text || '') !== text) scene.setBadge(id, kind, text);
  }
}

// ------------------------------------------------------------------ status

function busy() {
  const s = app.state;
  if (!s) return null;
  if (s.job?.name) return s.job.name;
  if (s.tests?.running) return 'tests';
  if (s.scenario?.running) return 'attack';
  return null;
}

function runState(s, job) {
  return job === 'attack' ? s.scenario : s.tests;
}

function updateStatus() {
  const s = app.state;
  header.setBusy(busy());
  if (s?.tests?.running) {
    const done = Object.keys(s.tests.results || {}).length;
    status.set('tests', `Testing connections · <b>${done}</b> of ${s.tests.total}`);
  } else if (s?.scenario?.running) {
    const sc = s.scenario;
    const open = sc.breaches ? `, <b>${sc.breaches} got through</b>` : '';
    // Short enough to fit beside the legend at 1440px even on the flat map.
    const of = sc.planned ? ` of ${sc.planned}` : '';
    status.set('attack', `Ransomware on the ${nodeLabel(sc.node)} · <b>${sc.attempts}</b>${of} attack paths tried${open}`);
  } else if (s?.job?.name && !(runState(s, s.job.name)?.ts >= s.job.started)) {
    // Started from the page, not reporting yet. (Once the run has ended,
    // the program may take a moment to exit: no "Starting" then.)
    status.set(s.job.name === 'attack' ? 'attack' : 'tests', 'Starting…');
  } else {
    status.set(null);
  }
}

function testsBanner(summary) {
  if (!summary) return;
  const v = summary.violations?.length || 0;
  const b = summary.broken?.length || 0;
  const flowsDef = app.state.topology.flows;
  const results = app.state.tests?.results || {};
  const errors = flowsDef.filter((f) => isError(results[f.id])).length;
  if (!v && !b && errors) {
    banner.show('info', `${plural(errors, 'connection')} could not be tested`,
      `No violations among the other ${summary.total - errors}. Run the tests again to check the rest.`);
  } else if (!v && !b) {
    const allowed = flowsDef.filter((f) => f.expect === 'allow').length;
    banner.show('ok', `All ${summary.total} connections behave as the policy says`,
      `${allowed} needed connections work. ${summary.total - allowed} forbidden ones are blocked.`);
  } else if (v) {
    banner.show('bad', `${plural(v, 'forbidden connection')} got through`,
      variant() === 'flat'
        ? 'In a flat network nothing stands between machines: a guest phone can reach patient records.'
        : `${summary.passed} of ${summary.total} match policy. The firewall rules need fixing.`);
  } else {
    banner.show('bad', `${plural(b, 'needed connection')} blocked`,
      `${summary.passed} of ${summary.total} match policy. Staff would be unable to work.`);
  }
}

function scenarioBanner(result) {
  if (!result) return;
  const rec = result.records || {};
  const open = result.attempts - result.blocked;
  if (!result.breaches && !result.encrypted) {
    const intact = rec.total && rec.intact === rec.total ? `All ${rec.total} records intact.` : `Patient records: ${rec.intact ?? '?'} of ${rec.total ?? '?'} intact.`;
    banner.show('ok', 'Attack contained',
      `Blocked ${result.blocked} of ${result.attempts} paths${open ? (open === 1 ? '; the open one is its everyday job' : '') : ''}. ${intact}`, 12);
  } else if (result.encrypted) {
    banner.show('bad', 'Ransomware reached the patient records',
      `${open} of ${result.attempts} paths were open. ${plural(result.encrypted, 'record')} encrypted.`, 12);
  } else if (rec.total && rec.intact < rec.total && recordsEncrypted(rec)) {
    // A repeat run: the records were encrypted by an earlier attack, so
    // there was nothing left to encrypt this time.
    const lost = rec.total - rec.intact;
    banner.show('bad', 'Ransomware reached the patient records',
      `${open} of ${result.attempts} paths were open. ${lost === rec.total ? `All ${lost}` : lost} ${lost === 1 ? 'record was' : 'records were'} already encrypted.`, 12);
  } else {
    banner.show('bad', 'Ransomware got through',
      `${open} of ${result.attempts} paths were open. Patient records: ${rec.intact ?? '?'} of ${rec.total ?? '?'} intact.`, 12);
  }
}

// ------------------------------------------------------------------ events

function applyState(s) {
  app.state = s;
  const topo = s.topology;
  if (!topo) return;
  header.setVariant(topo.variant);
  tests.setFlows(topo.flows, topo.variant);
  tests.render(s.tests);
  records.render(s.records, topo);
  alerts.render(s.alerts || [], nodeLabel, s.monitoring);
  rebuild();
  scene.setCounters(s.counters || {});
  captions.clear();
  for (const f of (s.activity || []).slice(-3)) captions.push(f, nodeLabel, topo.variant);
  refreshBadges();
  updateStatus();
}

function handle(msg) {
  const s = app.state;
  if (msg.kind === 'state') {
    applyState(msg);
    return;
  }
  if (!s) return;
  switch (msg.kind) {
    case 'flow':
      s.counters = msg.counters;
      flows.add(msg);
      break;
    case 'result':
      if (s.tests) s.tests.results[msg.id] = { pass: msg.pass, observed: msg.observed };
      tests.result(msg);
      updateStatus();
      break;
    case 'tests':
      s.tests = msg.tests;
      tests.render(msg.tests);
      updateStatus();
      if (msg.finished) testsBanner(msg.tests.summary);
      else if (msg.tests.running) banner.hide();
      break;
    case 'scenario': {
      const was = s.scenario?.running;
      s.scenario = msg.scenario;
      if (msg.scenario.running && !was) banner.hide();
      if (msg.finished) {
        app.infectedUntil = Date.now() + 15000;
        setTimeout(refreshBadges, 15100);
        scenarioBanner(msg.scenario.result);
      }
      refreshBadges();
      updateStatus();
      break;
    }
    case 'records':
      s.records = msg.records;
      records.render(msg.records, s.topology);
      refreshBadges();
      break;
    case 'alert': {
      const a = msg.alert;
      s.alerts = [...(s.alerts || []), a].slice(-200);
      const group = alerts.add(a);
      // The test suite sets off alerts on purpose (that is the monitor
      // working). They go in the list, without pop-ups or flashing machines.
      if (a.during === 'test') break;
      const copy = toastCopy(group);
      toasts.show({
        kind: group.level >= 12 ? 'critical' : 'alert',
        key: group.key,
        count: group.count,
        title: copy.title,
        text: copy.text,
        seconds: group.level >= 15 ? 12 : 7,
        level: group.level,
      });
      for (const id of new Set([a.node, a.src].filter(Boolean))) {
        if (!scene.layout?.nodes[id]) continue;
        app.alerted.set(id, Date.now() + 12000);
        if (group.count === 1) scene.pulse(id, 'alert');
      }
      refreshBadges();
      setTimeout(refreshBadges, 12100);
      break;
    }
    case 'job':
      s.job = msg.job;
      if (msg.last_job) {
        s.last_job = msg.last_job;
        if (!msg.last_job.ok) {
          const what = msg.last_job.name === 'attack' ? 'The ransomware simulation' : 'The isolation tests';
          toasts.show({
            kind: 'error', title: `${what} stopped with an error`,
            text: msg.last_job.tail?.slice(-1)[0] || `Exit code ${msg.last_job.code}`, seconds: 10, level: 99,
          });
        }
      }
      updateStatus();
      break;
    default:
      break;
  }
}

function connect() {
  header.setConnection('connecting');
  const es = new EventSource('/api/events');
  es.onopen = () => header.setConnection('live');
  es.onerror = () => header.setConnection('lost');
  es.onmessage = (e) => {
    let msg;
    try {
      msg = JSON.parse(e.data);
    } catch {
      return;
    }
    handle(msg);
  };
}

async function run(name) {
  if (busy()) return;
  header.setBusy(name);
  try {
    // The server only accepts a run with this header (see RUN_HEADER in server.py).
    const r = await fetch(`/api/run/${name}`, { method: 'POST', headers: { 'X-Clinic-Map': 'run' } });
    if (r.status === 403) {
      toasts.show({ kind: 'error', title: 'The map refused to start it', text: `Open the map at http://localhost:${location.port || 80}.`, level: 99 });
      header.setBusy(busy());
    } else if (r.status === 409) {
      toasts.show({ kind: 'error', title: 'Something is already running', text: 'Wait for it to finish, then try again.', level: 99 });
    } else if (!r.ok) {
      throw new Error(`HTTP ${r.status}`);
    }
  } catch {
    toasts.show({ kind: 'error', title: 'Could not start it', text: 'The map server did not answer.', level: 99 });
    header.setBusy(busy());
  }
}

// Relative times ("2 min ago") stay current.
setInterval(() => {
  alerts.tick();
  if (app.state?.tests && !app.state.tests.running) tests.render(app.state.tests);
}, 20000);

connect();
