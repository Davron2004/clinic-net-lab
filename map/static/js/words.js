// Plain-English vocabulary. The audience is a clinic manager, not an
// engineer, so ports become what they are used for.

const SERVICES = {
  22: 'admin shell',
  53: 'name lookup (DNS)',
  80: 'web',
  443: 'secure web',
  445: 'file sharing',
  631: 'printing',
  1514: 'security monitor',
  1515: 'security monitor',
  2575: 'lab results (HL7)',
  3389: 'remote desktop',
  4242: 'image transfer (DICOM)',
  8042: 'image viewer',
  8080: 'web app',
  9100: 'printing',
  51820: 'VPN',
};

export function service(port, proto) {
  if (proto === 'icmp') return 'ping';
  if (SERVICES[port]) return SERVICES[port];
  return port ? `port ${port}` : 'connection';
}

export function outcome(flow, variant) {
  switch (flow.result) {
    case 'allowed':
      return 'Allowed';
    case 'violation':
      return flow.stream ? 'Encrypting' : 'Got through: should be blocked';
    case 'broken':
      return 'Blocked, but it is needed';
    default:
      if (flow.by === 'switch') return 'Blocked: devices kept apart';
      if (flow.by === 'firewall') return 'Blocked by firewall';
      if (flow.by === 'router') return variant === 'flat' ? 'Blocked by router' : 'Blocked by firewall';
      return 'No answer';
  }
}

export const RESULT_ICON = {
  allowed: 'check',
  blocked: 'x',
  broken: 'x',
  violation: 'alert',
};

export function timeAgo(ts, now = Date.now() / 1000) {
  const s = Math.max(0, Math.round(now - ts));
  if (s < 10) return 'just now';
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  return `${h} h ago`;
}

export function clock(ts) {
  return new Date(ts * 1000).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}

export function plural(n, one, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`;
}
