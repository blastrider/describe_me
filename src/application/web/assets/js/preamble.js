const WEB_DEBUG = __WEB_DEBUG__;
const TOKEN_COOKIE_NAME = "describe_me_token";
const SESSION_COOKIE_NAME = "describe_me_session";
const dot = document.getElementById('statusDot');
const raw = document.getElementById('raw');
const err = document.getElementById('error');
const last = document.getElementById('lastUpdate');
const rawCard = document.getElementById('rawCard');
const rawBody = document.getElementById('rawBody');
const rawToggle = document.getElementById('rawToggle');
const updatesCard = document.getElementById('updatesCard');
const updatesDetails = document.getElementById('updatesDetails');
const updatesList = document.getElementById('updatesList');
const updatesToggle = document.getElementById('updatesDetailsToggle');
const networkCard = document.getElementById('networkCard');
const networkList = document.getElementById('networkList');
const tokenOverlay = document.getElementById('tokenOverlay');
const tokenForm = document.getElementById('tokenForm');
const tokenInput = document.getElementById('tokenInput');
const tokenErrorEl = document.getElementById('tokenError');
const tokenForget = document.getElementById('tokenForget');
const tokenOpen = document.getElementById('tokenOpen');

const createEl = (tag, className, text) => {
  const element = document.createElement(tag);
  if (className) {
    element.className = className;
  }
  if (typeof text === "string") {
    element.textContent = text;
  }
  return element;
};

const clearChildren = (node) => {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
};

const createServiceEmpty = (message = "—") => createEl('div', 'service-empty', message);

const pct = (used, total) => total > 0 ? Math.max(0, Math.min(100, (used/total)*100)) : 0;
const num = (value) => {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
};

if (WEB_DEBUG && rawCard) {
  rawCard.style.display = "block";
}
if (rawToggle && rawBody) {
  rawToggle.setAttribute('aria-controls', 'rawBody');
  rawToggle.setAttribute('aria-expanded', 'true');
  rawToggle.addEventListener('click', () => {
    const collapsed = rawBody.classList.toggle('collapsed');
    rawToggle.textContent = collapsed ? "Afficher" : "Masquer";
    rawToggle.setAttribute('aria-expanded', (!collapsed).toString());
  });
}
if (updatesToggle && updatesDetails) {
  updatesToggle.setAttribute('aria-controls', 'updatesDetails');
  updatesToggle.setAttribute('aria-expanded', 'false');
  updatesToggle.addEventListener('click', () => {
    const collapsed = updatesDetails.classList.toggle('collapsed');
    updatesToggle.textContent = collapsed ? "Détails" : "Masquer";
    updatesToggle.setAttribute('aria-expanded', (!collapsed).toString());
  });
}
const el = (id) => document.getElementById(id);
const fmtBytes = (n) => {
  const units = ["o","Ko","Mo","Go","To","Po"]; let i = 0, x = Number(n)||0;
  while (x >= 1024 && i < units.length-1) { x /= 1024; i++; }
  return x.toFixed(1) + " " + units[i];
};
const fmtSecs = (s) => {
  s = Number(s)||0;
  const d = Math.floor(s/86400); s%=86400;
  const h = Math.floor(s/3600); s%=3600;
  const m = Math.floor(s/60); s%=60;
  const parts = [];
  if (d) parts.push(d+"j"); if (h) parts.push(h+"h"); if (m) parts.push(m+"m"); if (s) parts.push(s+"s");
  return parts.join(" ") || "0s";
};
const serviceStateClass = (state) => {
  const val = (state || "").toLowerCase();
  if (!val) return "err";
  const okTokens = ["running", "listening", "online", "active"];
  return okTokens.some((token) => val.includes(token)) ? "ok" : "err";
};

const formatUpdatePackage = (pkg) => {
  const row = createEl('div', 'service-row');
  row.appendChild(createEl('span', 'dot service-dot'));

  const details = document.createElement('div');
  const name = pkg?.name ? String(pkg.name) : "Paquet";
  details.appendChild(createEl('div', 'service-name', name));

  const available = pkg?.available_version ? String(pkg.available_version) : "";
  const current = pkg?.current_version ? String(pkg.current_version) : "";
  const repo = pkg?.repository ? String(pkg.repository) : "";

  let versions = "";
  if (available && current) {
    versions = `${current} → ${available}`;
  } else if (available) {
    versions = `Version: ${available}`;
  } else if (current) {
    versions = `Installée: ${current}`;
  }

  const metaParts = [];
  if (versions) {
    metaParts.push(versions);
  }
  if (repo) {
    metaParts.push(repo);
  }
  if (metaParts.length) {
    details.appendChild(createEl('div', 'service-meta', metaParts.join(" • ")));
  }

  row.appendChild(details);
  return row;
};
