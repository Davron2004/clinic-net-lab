// Line icons (24x24, drawn with currentColor strokes), shared by the map
// and the HTML panels. Installed once as an SVG sprite of <symbol>s.

const PATHS = {
  pc: '<rect x="2.5" y="3.5" width="19" height="13" rx="2"/><path d="M8 20.5h8M12 16.5v4"/>',
  laptop: '<rect x="4" y="4.5" width="16" height="11" rx="1.5"/><path d="M2 19.5h20"/>',
  phone: '<rect x="6.5" y="2.5" width="11" height="19" rx="2.5"/><path d="M11 18.5h2"/>',
  records: '<rect x="8" y="2.5" width="8" height="4" rx="1"/><path d="M16 4.5h2a2 2 0 0 1 2 2v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-13a2 2 0 0 1 2-2h2"/><path d="M12 10.5v6M9 13.5h6"/>',
  archive: '<rect x="2.5" y="3.5" width="19" height="5" rx="1"/><path d="M4.5 8.5v10a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-10M10 12.5h4"/>',
  server: '<rect x="3" y="3" width="18" height="7.5" rx="2"/><rect x="3" y="13.5" width="18" height="7.5" rx="2"/><path d="M7 6.75h.01M7 17.25h.01"/>',
  imaging: '<path d="M3 8V5.5A2.5 2.5 0 0 1 5.5 3H8M16 3h2.5A2.5 2.5 0 0 1 21 5.5V8M21 16v2.5a2.5 2.5 0 0 1-2.5 2.5H16M8 21H5.5A2.5 2.5 0 0 1 3 18.5V16"/><path d="M12 7v10M9 9.5c1 .6 2 .9 3 .9s2-.3 3-.9M9 14.5c1-.6 2-.9 3-.9s2 .3 3 .9"/>',
  flask: '<path d="M9 2.5h6M10 2.5v6.2L4.6 18.2A2 2 0 0 0 6.3 21.5h11.4a2 2 0 0 0 1.7-3.3L14 8.7V2.5"/><path d="M7.2 15h9.6"/>',
  printer: '<path d="M6.5 9V3h11v6"/><path d="M6.5 17.5h-2a2 2 0 0 1-2-2v-4.5a2 2 0 0 1 2-2h15a2 2 0 0 1 2 2v4.5a2 2 0 0 1-2 2h-2"/><rect x="6.5" y="14" width="11" height="7.5" rx="1"/>',
  globe: '<circle cx="12" cy="12" r="9.5"/><path d="M2.5 12h19M12 2.5c2.6 2.6 3.9 5.8 3.9 9.5s-1.3 6.9-3.9 9.5c-2.6-2.6-3.9-5.8-3.9-9.5S9.4 5.1 12 2.5z"/>',
  home: '<path d="M3 10.5 12 3l9 7.5"/><path d="M5.5 9v11a1 1 0 0 0 1 1H10v-6h4v6h3.5a1 1 0 0 0 1-1V9"/>',
  shield: '<path d="M12 21.5s8-3.6 8-9.8V5.2L12 2.5 4 5.2v6.5c0 6.2 8 9.8 8 9.8z"/>',
  shieldCheck: '<path d="M12 21.5s8-3.6 8-9.8V5.2L12 2.5 4 5.2v6.5c0 6.2 8 9.8 8 9.8z"/><path d="m8.8 12 2.2 2.2 4.4-4.4"/>',
  router: '<rect x="2.5" y="13" width="19" height="7.5" rx="2"/><path d="M6.5 16.75h.01M10 16.75h.01M15.5 13V9.5"/><path d="M12.6 7.2a4.2 4.2 0 0 1 5.8 0M10.5 5a7.2 7.2 0 0 1 10 0"/>',
  radar: '<circle cx="12" cy="12" r="2"/><path d="M16.2 7.8a6 6 0 0 1 0 8.4M7.8 16.2a6 6 0 0 1 0-8.4M19.1 4.9a10 10 0 0 1 0 14.2M4.9 19.1a10 10 0 0 1 0-14.2"/>',
  switch: '<rect x="2.5" y="7" width="19" height="10" rx="2"/><path d="M6 12h.01M9.33 12h.01M12.67 12h.01M16 12h.01M6 4v3M12 4v3M18 4v3M6 17v3M12 17v3M18 17v3"/>',
  help: '<circle cx="12" cy="12" r="9.5"/><path d="M9.4 9.2a2.7 2.7 0 0 1 5.2 1c0 1.8-2.6 2.4-2.6 4M12 17.3h.01"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.8-9.8M17 6l3 3M14.5 8.5l2 2"/>',
  device: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 9h6v6H9z"/>',
  check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
  x: '<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>',
  alert: '<path d="M10.3 3.9 2.4 17.6A2 2 0 0 0 4.1 20.5h15.8a2 2 0 0 0 1.7-2.9L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4.5M12 17.2h.01"/>',
  bug: '<path d="M9 7.5V6a3 3 0 0 1 6 0v1.5"/><path d="M12 20.5c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6zM12 20.5v-9"/><path d="M6 13H2.5M21.5 13H18M6.5 9.2 3.5 7.5M17.5 9.2l3-1.7M6.5 17l-3 2M17.5 17l3 2"/>',
  lock: '<rect x="4" y="10.5" width="16" height="11" rx="2"/><path d="M7.5 10.5V7a4.5 4.5 0 0 1 9 0v3.5"/>',
  file: '<path d="M14 2.5H6.5a2 2 0 0 0-2 2v15a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V8z"/><path d="M14 2.5V8h5.5"/>',
  bell: '<path d="M6 8.5a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.9 1.9 0 0 0 3.4 0"/>',
  play: '<path d="M7 4.5v15l12.5-7.5z"/>',
  list: '<path d="M9 6h11.5M9 12h11.5M9 18h11.5"/><path d="m3.5 6 1 1 2-2M3.5 12l1 1 2-2M3.5 18l1 1 2-2"/>',
  zap: '<path d="M13 2.5 4 13.5h7l-1 8 9-11h-7z"/>',
  arrow: '<path d="M4.5 12h14M13.5 6.5 19 12l-5.5 5.5"/>',
};

export function installSprite() {
  const ns = 'http://www.w3.org/2000/svg';
  const sprite = document.createElementNS(ns, 'svg');
  sprite.setAttribute('aria-hidden', 'true');
  sprite.style.position = 'absolute';
  sprite.style.width = '0';
  sprite.style.height = '0';
  sprite.innerHTML = Object.entries(PATHS)
    .map(([name, d]) => `<symbol id="i-${name}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">${d}</symbol>`)
    .join('');
  document.body.prepend(sprite);
}

// Inline icon markup for HTML panels.
export function icon(name, cls = 'ic') {
  return `<svg class="${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
}

// Pick an icon for a machine from its name and label, unless policy names one.
export function iconFor(node) {
  if (node.icon && PATHS[node.icon]) return node.icon;
  const s = `${node.id} ${node.label}`.toLowerCase();
  const rules = [
    [/emr|record|chart/, 'records'],
    [/pacs|archive|orthanc/, 'archive'],
    [/imaging|x-?ray|scan|ultrasound|mri|ct\b/, 'imaging'],
    [/lab|analy[sz]er/, 'flask'],
    [/print|fax/, 'printer'],
    [/phone|mobile|tablet/, 'phone'],
    [/laptop|notebook/, 'laptop'],
    [/home|remote/, 'home'],
    [/internet|website|web\b|cloud/, 'globe'],
    [/siem|monitor|wazuh|security|log/, 'radar'],
    [/vpn|wireguard/, 'key'],
    [/server|nas|backup/, 'server'],
    [/pc|desktop|workstation|reception|doctor|nurse/, 'pc'],
  ];
  for (const [re, name] of rules) if (re.test(s)) return name;
  return 'device';
}
