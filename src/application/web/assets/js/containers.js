function fmtAge(ms) {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${ms} ms`;
  const secs = Math.round(ms / 1000);
  if (secs < 90) return `${secs}s`;
  const mins = Math.round(secs / 60);
  if (mins < 90) return `${mins} min`;
  const hours = Math.round(mins / 60);
  return `${hours} h`;
}

function el(id) {
  return document.getElementById(id) || document.querySelector(`[data-role=\"${id}\"]`);
}

function createRow(container) {
  const row = document.createElement('div');
  row.className = 'service-row';
  const name = container?.name || "—";
  const runtime = container?.runtime || "—";
  const state = container?.state || "—";
  const ip = container?.ip || "—";
  const image = container?.image || "—";

  [
    name,
    runtime,
    state,
    ip,
    image,
  ].forEach((value) => {
    const cell = document.createElement('div');
    cell.textContent = String(value);
    row.appendChild(cell);
  });

  return row;
}

function createEmpty(message) {
  const empty = document.createElement('div');
  empty.className = 'service-empty';
  empty.textContent = message || "Aucun conteneur détecté.";
  return empty;
}

async function loadContainers() {
  const errorEl = document.querySelector('[data-role=\"containers-error\"]');
  const list = document.querySelector('[data-role=\"containers-list\"]');
  const summaryHint = document.querySelector('[data-role=\"containers-summary-hint\"]');
  const totalEl = document.querySelector('[data-role=\"containers-total\"]');
  const runningEl = document.querySelector('[data-role=\"containers-running\"]');
  const ageEl = document.querySelector('[data-role=\"containers-age\"]');
  const hintEl = document.querySelector('[data-role=\"containers-hint\"]');

  if (!list) return;

  if (errorEl) {
    errorEl.hidden = true;
    errorEl.textContent = "";
  }
  list.innerHTML = '<div class=\"service-empty\">Chargement…</div>';
  if (summaryHint) summaryHint.textContent = "";

  try {
    const resp = await fetch('/api/containers', { credentials: 'same-origin' });
    if (resp.status === 401) {
      list.innerHTML = '';
      list.appendChild(createEmpty("Jeton requis pour accéder aux conteneurs."));
      if (errorEl) {
        errorEl.hidden = false;
        errorEl.textContent = "Authentifiez-vous pour consulter les conteneurs.";
      }
      if (typeof showTokenPrompt === "function") {
        showTokenPrompt("Jeton requis pour accéder aux conteneurs.");
      }
      return;
    }
    if (resp.status === 403) {
      list.innerHTML = '';
      list.appendChild(createEmpty("Les conteneurs ne sont pas exposés sur cette instance."));
      if (hintEl) {
        hintEl.textContent = "Exposition désactivée (summary/details). Activez l'exposition pour voir la liste.";
      }
      if (totalEl) totalEl.textContent = "—";
      if (runningEl) runningEl.textContent = "—";
      if (ageEl) ageEl.textContent = "—";
      return;
    }
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }
    const data = await resp.json();
    const snapshot = data?.containers || {};
    const summary = snapshot.summary;

    if (summary) {
      if (totalEl) totalEl.textContent = String(summary.total ?? "—");
      if (runningEl) runningEl.textContent = String(summary.running ?? "—");
    } else {
      if (totalEl) totalEl.textContent = "—";
      if (runningEl) runningEl.textContent = "—";
    }
    if (typeof data?.age_ms === "number" && ageEl) {
      ageEl.textContent = fmtAge(data.age_ms);
    }
    const containers = Array.isArray(snapshot.containers) ? snapshot.containers : [];
    list.innerHTML = '';
    if (!snapshot.containers) {
      list.appendChild(createEmpty("Seul le résumé est exposé (détails non autorisés)."));
      if (summaryHint) summaryHint.textContent = "Mode résumé uniquement";
      return;
    }
    if (containers.length === 0) {
      list.appendChild(createEmpty("Aucun conteneur détecté."));
      return;
    }
    const header = document.createElement('div');
    header.className = 'service-row service-header';
    ["Nom", "Runtime", "État", "IP", "Image"].forEach((title) => {
      const cell = document.createElement('div');
      cell.textContent = title;
      header.appendChild(cell);
    });
    list.appendChild(header);
    const fragment = document.createDocumentFragment();
    containers.forEach((c) => fragment.appendChild(createRow(c)));
    list.appendChild(fragment);
  } catch (err) {
    if (errorEl) {
      errorEl.hidden = false;
      errorEl.textContent = `Impossible de récupérer les conteneurs: ${err}`;
    }
    list.innerHTML = '';
    list.appendChild(createEmpty("Erreur de chargement."));
    if (totalEl) totalEl.textContent = "—";
    if (runningEl) runningEl.textContent = "—";
    if (ageEl) ageEl.textContent = "—";
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const refresh = document.querySelector('[data-role=\"containers-refresh\"]');
  if (refresh) {
    refresh.addEventListener('click', () => {
      loadContainers();
    });
  }
  loadContainers();
});
