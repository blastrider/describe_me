const tagsEditorManager =
  typeof window.TagsEditorManager === "function"
    ? new window.TagsEditorManager()
    : null;

const MAX_PAGE_LIMIT = 500;
const DEFAULT_PAGE_LIMIT = 20;

let currentSnapshot = null;

const filterState = {
  services: { query: "", status: "all", tags: [] },
  sockets: { query: "", tags: [] },
};

const paginationState = {
  services: { offset: 0, limit: DEFAULT_PAGE_LIMIT },
  sockets: { offset: 0, limit: DEFAULT_PAGE_LIMIT },
};

function getWidthFromBytes(totalBytes, availableBytes) {
  if (typeof widthFromBytes === "function") {
    return widthFromBytes(totalBytes, availableBytes);
  }
  const total = Number(totalBytes);
  if (!Number.isFinite(total) || total <= 0) {
    return "0.0%";
  }
  const rawAvailable = Number(availableBytes);
  const available = Number.isFinite(rawAvailable) ? rawAvailable : 0;
  const clampedAvailable = Math.min(Math.max(available, 0), total);
  const pct = (1 - clampedAvailable / total) * 100;
  const bounded = Math.min(Math.max(pct, 0), 100);
  return `${bounded.toFixed(1)}%`;
}

function formatExtensionValue(value) {
  if (value === null || typeof value === "undefined") {
    return "—";
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return value.toString();
  }
  try {
    return JSON.stringify(value);
  } catch (err) {
    return String(value);
  }
}

function extensionEntries(payload) {
  if (
    payload &&
    typeof payload === "object" &&
    !Array.isArray(payload)
  ) {
    return Object.entries(payload).map(
      ([key, value]) => `${key}: ${formatExtensionValue(value)}`
    );
  }
  return [formatExtensionValue(payload)];
}

function basename(path) {
  if (typeof path !== "string") return "";
  const idx = path.lastIndexOf("/");
  return idx === -1 ? path : path.slice(idx + 1);
}

function formatExecutionScope(scope) {
  const normalized = typeof scope === "string" ? scope.toLowerCase() : "";
  if (normalized === "host") {
    return "Hôte";
  }
  if (normalized === "container" || normalized === "containerself" || normalized === "container_self") {
    return "Conteneur";
  }
  if (normalized.includes("host") && normalized.includes("container")) {
    return "Hôte depuis conteneur";
  }
  if (normalized) {
    return scope;
  }
  return "—";
}

function normalizeText(value) {
  return typeof value === "string" ? value.toLowerCase() : "";
}

function matchesQuery(query, fields, tags) {
  if (!query) return true;
  const needle = query.toLowerCase();
  return (
    fields.some((field) => normalizeText(field).includes(needle)) ||
    tags.some((tag) => tag.includes(needle))
  );
}

function filterServices(list, filters, tags) {
  if (!Array.isArray(list)) return [];
  const status = normalizeText(filters?.status || "all");
  const query = (filters?.query || "").trim().toLowerCase();
  const selectedTags =
    Array.isArray(filters?.tags) && filters.tags.length
      ? filters.tags.map(normalizeText)
      : [];
  const tagPool = Array.isArray(tags) ? tags.map(normalizeText) : [];

  const statusMatchers = {
    running: (state) =>
      state.includes("running") || state.includes("active") || state.includes("listening"),
    exited: (state) =>
      state.includes("exited") || state.includes("dead") || state.includes("inactive"),
    failed: (state) => state.includes("fail"),
  };

  return list.filter((svc) => {
    const state = normalizeText(svc?.state || "");

    if (status !== "all") {
      const matcher = statusMatchers[status];
      if (!matcher || !matcher(state)) {
        return false;
      }
    }

    if (selectedTags.length && !selectedTags.every((tag) => tagPool.includes(tag))) {
      return false;
    }

    const fields = [
      svc?.name,
      svc?.state,
      svc?.summary,
    ].filter(Boolean);

    return matchesQuery(query, fields, tagPool);
  });
}

function sortServices(list) {
  if (!Array.isArray(list)) return [];
  const rank = (state) => {
    const val = normalizeText(state);
    if (!val) return 3;
    if (val.includes("running") || val.includes("active") || val.includes("listening")) {
      return 0;
    }
    if (val.includes("exited") || val.includes("inactive")) {
      return 1;
    }
    if (val.includes("fail")) {
      return 2;
    }
    return 3;
  };
  return list
    .slice()
    .sort((a, b) => {
      const rankDiff = rank(a?.state) - rank(b?.state);
      if (rankDiff !== 0) return rankDiff;
      const nameA = normalizeText(a?.name || "");
      const nameB = normalizeText(b?.name || "");
      if (nameA === nameB) return 0;
      return nameA < nameB ? -1 : 1;
    });
}

function filterSockets(list, filters, tags) {
  if (!Array.isArray(list)) return [];
  const query = (filters?.query || "").trim().toLowerCase();
  const selectedTags =
    Array.isArray(filters?.tags) && filters.tags.length
      ? filters.tags.map(normalizeText)
      : [];
  const tagPool = Array.isArray(tags) ? tags.map(normalizeText) : [];

  return list.filter((sock) => {
    if (selectedTags.length && !selectedTags.every((tag) => tagPool.includes(tag))) {
      return false;
    }
    const pid =
      typeof sock?.process === "number"
        ? String(sock.process)
        : typeof sock?.pid === "number"
          ? String(sock.pid)
          : null;
    const fields = [
      sock?.proto,
      sock?.addr,
      sock?.port != null ? String(sock.port) : null,
      sock?.process_name,
      pid,
    ].filter(Boolean);

    return matchesQuery(query, fields, tagPool);
  });
}

function sortSockets(list) {
  if (!Array.isArray(list)) return [];
  const protoWeight = (proto) => (proto === "udp" ? 1 : 0);
  return list
    .slice()
    .sort((a, b) => {
      const protoA = normalizeText(a?.proto || "tcp");
      const protoB = normalizeText(b?.proto || "tcp");
      const protoDiff = protoWeight(protoA) - protoWeight(protoB);
      if (protoDiff !== 0) return protoDiff;
      const portA = Number(a?.port) || 0;
      const portB = Number(b?.port) || 0;
      if (portA !== portB) return portA - portB;
      const addrA = normalizeText(a?.addr || "");
      const addrB = normalizeText(b?.addr || "");
      if (addrA === addrB) return 0;
      return addrA < addrB ? -1 : 1;
    });
}

function paginate(list, state, maxLimit) {
  const items = Array.isArray(list) ? list : [];
  const total = items.length;
  const cap = maxLimit && maxLimit > 0 ? maxLimit : Number.MAX_SAFE_INTEGER;
  const rawLimit = Number(state?.limit) || 0;
  const desired = rawLimit === 0 ? cap : rawLimit;
  const limit = Math.min(Math.max(desired, 1), cap);
  const offset = Math.min(Math.max(Number(state?.offset) || 0, 0), total);
  const end = Math.min(offset + limit, total);
  return {
    items: items.slice(offset, end),
    total,
    offset,
    limit,
  };
}

function formatExpiryLine(entry) {
  const path = entry.path || "certificat";
  const shortName = basename(path) || path;
  const status = typeof entry.status === "string" ? entry.status : "ok";
  const until = typeof entry.not_after === "string" ? entry.not_after : "";
  const days = Number(entry.days_until_expiry);

  if (status !== "ok") {
    return `${shortName}: ${status}`;
  }

  if (Number.isFinite(days)) {
    if (days >= 0) {
      return `${shortName}: expire dans ${days}j${until ? ` (${until})` : ""}`;
    }
    return `${shortName}: expiré depuis ${Math.abs(days)}j${until ? ` (${until})` : ""}`;
  }

  if (until) {
    return `${shortName}: valide jusqu'au ${until}`;
  }

  return `${shortName}: statut inconnu`;
}

function renderCertificatesPlugin(rawPayload) {
  const payload =
    rawPayload &&
    typeof rawPayload === "object" &&
    !Array.isArray(rawPayload) &&
    rawPayload.values &&
    typeof rawPayload.values === "object" &&
    !Array.isArray(rawPayload.values)
      ? rawPayload.values
      : rawPayload;

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return null;
  }

  const nodes = [];
  const stats = [];
  const found = num(payload.certificates_found);
  if (Number.isFinite(found) && found >= 0) {
    stats.push(`${found} certificat(s) analysé(s)`);
  }
  const pem = num(payload.pem_files);
  if (Number.isFinite(pem) && pem >= 0) {
    stats.push(`${pem} fichier(s) PEM`);
  }
  if (stats.length) {
    nodes.push(createEl('div', 'service-meta', stats.join(' • ')));
  }

  if (Array.isArray(payload.directories) && payload.directories.length) {
    const dirs = payload.directories
      .map((d) => String(d))
      .filter((d) => d.trim() !== "")
      .slice(0, 3)
      .join(", ");
    if (dirs) {
      nodes.push(createEl('div', 'service-meta', `Dossiers: ${dirs}`));
    }
  }

  const certificates = Array.isArray(payload.certificates)
    ? payload.certificates.filter(
        (entry) => entry && typeof entry === "object" && !Array.isArray(entry)
      )
    : [];
  const describeCerts = certificates.filter(
    (entry) =>
      typeof entry.path === "string" &&
      entry.path.includes("/etc/describe_me/certs")
  );
  const selected = describeCerts.length > 0 ? describeCerts : certificates;

  selected
    .sort((a, b) => {
      const ad = Number(a.days_until_expiry);
      const bd = Number(b.days_until_expiry);
      if (Number.isFinite(ad) && Number.isFinite(bd)) return ad - bd;
      if (Number.isFinite(ad)) return -1;
      if (Number.isFinite(bd)) return 1;
      return 0;
    })
    .slice(0, 4)
    .map(formatExpiryLine)
    .forEach((line) => nodes.push(createEl('div', 'service-meta', line)));

  return nodes.length ? nodes : null;
}

function renderTagFilters(tags, elementId, targetKey) {
  const container = el(elementId);
  if (!container) return;
  clearChildren(container);

  const normalizedTags = Array.isArray(tags)
    ? Array.from(new Set(tags.map((tag) => String(tag).trim()).filter(Boolean)))
    : [];

  if (normalizedTags.length === 0) {
    container.appendChild(createEl('div', 'service-empty', 'Aucun tag'));
    return;
  }

  normalizedTags.forEach((tag) => {
    const norm = normalizeText(tag);
    const active =
      Array.isArray(filterState[targetKey].tags) &&
      filterState[targetKey].tags.includes(norm);
    const chip = createEl(
      'button',
      `filter-chip${active ? ' active' : ''}`,
      tag
    );
    chip.type = "button";
    chip.setAttribute('aria-pressed', active.toString());
    chip.addEventListener('click', () => {
      const list = filterState[targetKey].tags || [];
      if (active) {
        filterState[targetKey].tags = list.filter((t) => t !== norm);
      } else {
        filterState[targetKey].tags = [...list, norm];
      }
      paginationState[targetKey].offset = 0;
      applyFiltersAndRender();
    });
    container.appendChild(chip);
  });
}

function updatePaginationControls(kind, page) {
  const pagination = el(`${kind}Pagination`);
  const info = el(`${kind}PageInfo`);
  const prev = el(`${kind}Prev`);
  const next = el(`${kind}Next`);
  if (!pagination || !info || !prev || !next) {
    return;
  }
  if (!page || page.total === 0) {
    pagination.style.display = "none";
    return;
  }

  pagination.style.display = "flex";
  const start = page.offset + 1;
  const end = page.offset + page.items.length;
  const totalPages = Math.max(1, Math.ceil(page.total / page.limit));
  const current = Math.min(totalPages, Math.floor(page.offset / page.limit) + 1);
  info.textContent = `${start}-${end} / ${page.total} (page ${current}/${totalPages})`;
  prev.disabled = page.offset === 0;
  next.disabled = end >= page.total;
}

function renderServices(result) {
  const card = el('servicesCard');
  const list = el('servicesList');
  const filtersPanel = el('servicesFilters');
  const pagination = el('servicesPagination');
  const notExposed = el('servicesNotExposed');
  if (!card || !list) return;

  if (!result.exposed) {
    card.style.display = "none";
    if (pagination) pagination.style.display = "none";
    if (filtersPanel) filtersPanel.style.display = "none";
    if (notExposed) {
      notExposed.style.display = "block";
    }
    return;
  }

  if (notExposed) notExposed.style.display = "none";
  card.style.display = "block";
  if (filtersPanel) filtersPanel.style.display = "flex";
  clearChildren(list);

  if (result.page.total === 0) {
    if (
      result.summary &&
      typeof result.summary.total === "number" &&
      result.summary.total > 0
    ) {
      const row = createEl('div', 'service-row');
      row.appendChild(createEl('span', 'dot service-dot'));
      const details = document.createElement('div');
      details.appendChild(
        createEl('div', 'service-name', `${result.summary.total} service(s) observé(s)`)
      );
      const meta = createEl('div', 'service-meta');
      const byState = Array.isArray(result.summary.by_state)
        ? result.summary.by_state
        : [];
      if (byState.length > 0) {
        byState.forEach((item, index) => {
          const badge = createEl('span', 'badge', `${item.state}: ${item.count}`);
          meta.appendChild(badge);
          if (index < byState.length - 1) {
            meta.appendChild(document.createTextNode(' '));
          }
        });
      } else {
        meta.textContent = "Aucune donnée détaillée";
      }
      details.appendChild(meta);
      row.appendChild(details);
      list.appendChild(row);
    } else {
      const message =
        result.originalTotal > 0
          ? "Aucun service ne correspond aux filtres"
          : "Aucun service actif rapporté";
      list.appendChild(createServiceEmpty(message));
    }
    updatePaginationControls('services', result.page);
    return;
  }

  result.page.items.forEach((svc) => {
    const name = svc?.name ? String(svc.name) : "Service";
    const stateRaw = svc?.state || "";
    const state = stateRaw ? String(stateRaw) : "";
    const summaryText = svc?.summary ? String(svc.summary) : "";
    const dotClass = serviceStateClass(stateRaw);
    const metaParts = [];
    if (state) {
      metaParts.push(state);
    }
    if (summaryText) {
      metaParts.push(summaryText);
    }

    const row = createEl('div', 'service-row');
    row.appendChild(createEl('span', `dot service-dot ${dotClass}`));

    const details = document.createElement('div');
    details.appendChild(createEl('div', 'service-name', name));
    if (metaParts.length) {
      details.appendChild(createEl('div', 'service-meta', metaParts.join(" • ")));
    }

    row.appendChild(details);
    list.appendChild(row);
  });

  updatePaginationControls('services', result.page);
}

function renderSockets(result) {
  const grid = el('socketsGrid');
  const tcpCard = el('socketsTcpCard');
  const udpCard = el('socketsUdpCard');
  const tcpList = el('socketsTcp');
  const udpList = el('socketsUdp');
  const notExposed = el('socketsNotExposed');
  const filtersPanel = el('socketsFilters');
  const pagination = el('socketsPagination');
  if (!grid || !tcpCard || !udpCard || !tcpList || !udpList) return;

  if (!result.exposed) {
    grid.style.display = "none";
    tcpCard.style.display = "none";
    udpCard.style.display = "none";
    if (pagination) pagination.style.display = "none";
    if (filtersPanel) filtersPanel.style.display = "none";
    if (notExposed) {
      notExposed.style.display = "block";
    }
    return;
  }

  if (notExposed) notExposed.style.display = "none";
  if (filtersPanel) filtersPanel.style.display = "flex";
  clearChildren(tcpList);
  clearChildren(udpList);

  if (result.page.total === 0) {
    grid.style.display = "grid";
    tcpCard.style.display = "block";
    udpCard.style.display = "block";
    const message =
      result.originalTotal > 0
        ? "Aucune socket après filtrage"
        : "Aucune socket d’écoute";
    tcpList.appendChild(createServiceEmpty(message));
    udpList.appendChild(createServiceEmpty(message));
    updatePaginationControls('sockets', result.page);
    return;
  }

  const grouped = result.page.items.reduce(
    (acc, sock) => {
      const proto = (sock?.proto || "").toLowerCase() === "udp" ? "udp" : "tcp";
      acc[proto].push(sock);
      return acc;
    },
    { tcp: [], udp: [] }
  );

  grid.style.display = "grid";

  const renderGroup = (list) => {
    const fragment = document.createDocumentFragment();
    list.forEach((sock) => {
      const proto = sock?.proto ? String(sock.proto) : "?";
      const addr = sock?.addr ? String(sock.addr) : "—";
      const port = sock?.port != null ? Number(sock.port) : "—";
      const pidValue =
        typeof sock?.process === "number"
          ? sock.process
          : typeof sock?.pid === "number"
            ? sock.pid
            : null;
      const pid = typeof pidValue === "number" ? `PID ${pidValue}` : "";
      const procName = sock?.process_name ? String(sock.process_name) : "";
      const detailsParts = [`${addr}:${port}`];
      if (procName) {
        detailsParts.push(procName);
      }
      if (pid) {
        detailsParts.push(pid);
      }

      const row = createEl('div', 'service-row');
      row.appendChild(createEl('span', 'dot service-dot ok'));

      const details = document.createElement('div');
      details.appendChild(createEl('div', 'service-name', proto.toUpperCase()));
      details.appendChild(createEl('div', 'service-meta', detailsParts.join(" • ")));
      row.appendChild(details);

      fragment.appendChild(row);
    });
    return fragment;
  };

  if (grouped.tcp.length) {
    tcpCard.style.display = "block";
    tcpList.appendChild(renderGroup(grouped.tcp));
  } else {
    tcpCard.style.display = "block";
    tcpList.appendChild(createServiceEmpty('Aucun port TCP'));
  }

  if (grouped.udp.length) {
    udpCard.style.display = "block";
    udpList.appendChild(renderGroup(grouped.udp));
  } else {
    udpCard.style.display = "block";
    udpList.appendChild(createServiceEmpty('Aucun port UDP'));
  }

  updatePaginationControls('sockets', result.page);
}

function applyFiltersAndRender() {
  if (!currentSnapshot || typeof currentSnapshot !== "object") {
    return;
  }

  const tags = Array.isArray(currentSnapshot.server_tags)
    ? currentSnapshot.server_tags
    : [];

  const normalizedTags = tags.map(normalizeText);
  filterState.services.tags = (filterState.services.tags || []).filter((t) =>
    normalizedTags.includes(t)
  );
  filterState.sockets.tags = (filterState.sockets.tags || []).filter((t) =>
    normalizedTags.includes(t)
  );

  renderTagFilters(tags, 'servicesTags', 'services');
  renderTagFilters(tags, 'socketsTags', 'sockets');

  const hasServicesField = Object.prototype.hasOwnProperty.call(
    currentSnapshot,
    'services_running'
  );
  const rawServices = Array.isArray(currentSnapshot.services_running)
    ? currentSnapshot.services_running
    : null;
  const filteredServices = sortServices(
    filterServices(rawServices || [], filterState.services, tags)
  );
  let servicesPage = paginate(filteredServices, paginationState.services, MAX_PAGE_LIMIT);
  if (
    servicesPage.total > 0 &&
    servicesPage.items.length === 0 &&
    paginationState.services.offset > 0
  ) {
    paginationState.services.offset = Math.max(
      servicesPage.total - servicesPage.limit,
      0
    );
    servicesPage = paginate(filteredServices, paginationState.services, MAX_PAGE_LIMIT);
  }

  renderServices({
    exposed: hasServicesField && rawServices !== null,
    page: servicesPage,
    originalTotal: rawServices ? rawServices.length : 0,
    summary: currentSnapshot.services_summary,
  });

  const hasSocketsField = Object.prototype.hasOwnProperty.call(
    currentSnapshot,
    'listening_sockets'
  );
  const rawSockets = Array.isArray(currentSnapshot.listening_sockets)
    ? currentSnapshot.listening_sockets
    : null;
  const filteredSockets = sortSockets(
    filterSockets(rawSockets || [], filterState.sockets, tags)
  );
  let socketsPage = paginate(filteredSockets, paginationState.sockets, MAX_PAGE_LIMIT);
  if (
    socketsPage.total > 0 &&
    socketsPage.items.length === 0 &&
    paginationState.sockets.offset > 0
  ) {
    paginationState.sockets.offset = Math.max(
      socketsPage.total - socketsPage.limit,
      0
    );
    socketsPage = paginate(filteredSockets, paginationState.sockets, MAX_PAGE_LIMIT);
  }

  renderSockets({
    exposed: hasSocketsField && rawSockets !== null,
    page: socketsPage,
    originalTotal: rawSockets ? rawSockets.length : 0,
  });
}

const servicesSearchInput = el('servicesSearch');
if (servicesSearchInput) {
  servicesSearchInput.addEventListener('input', (event) => {
    filterState.services.query = event.target.value || "";
    paginationState.services.offset = 0;
    applyFiltersAndRender();
  });
}

const servicesStatusSelect = el('servicesStatus');
if (servicesStatusSelect) {
  servicesStatusSelect.addEventListener('change', (event) => {
    filterState.services.status = event.target.value || "all";
    paginationState.services.offset = 0;
    applyFiltersAndRender();
  });
}

const socketsSearchInput = el('socketsSearch');
if (socketsSearchInput) {
  socketsSearchInput.addEventListener('input', (event) => {
    filterState.sockets.query = event.target.value || "";
    paginationState.sockets.offset = 0;
    applyFiltersAndRender();
  });
}

const servicesPrev = el('servicesPrev');
const servicesNext = el('servicesNext');
if (servicesPrev && servicesNext) {
  servicesPrev.addEventListener('click', () => {
    const step = Math.max(paginationState.services.limit || DEFAULT_PAGE_LIMIT, 1);
    paginationState.services.offset = Math.max(
      paginationState.services.offset - step,
      0
    );
    applyFiltersAndRender();
  });
  servicesNext.addEventListener('click', () => {
    const step = Math.max(paginationState.services.limit || DEFAULT_PAGE_LIMIT, 1);
    paginationState.services.offset += step;
    applyFiltersAndRender();
  });
}

const socketsPrev = el('socketsPrev');
const socketsNext = el('socketsNext');
if (socketsPrev && socketsNext) {
  socketsPrev.addEventListener('click', () => {
    const step = Math.max(paginationState.sockets.limit || DEFAULT_PAGE_LIMIT, 1);
    paginationState.sockets.offset = Math.max(
      paginationState.sockets.offset - step,
      0
    );
    applyFiltersAndRender();
  });
  socketsNext.addEventListener('click', () => {
    const step = Math.max(paginationState.sockets.limit || DEFAULT_PAGE_LIMIT, 1);
    paginationState.sockets.offset += step;
    applyFiltersAndRender();
  });
}

function updateUI(data) {
  err.textContent = "";

  if (tagsEditorManager) {
    tagsEditorManager.applySnapshot({
      description:
        typeof data.server_description === "string" ? data.server_description : "",
      tags: Array.isArray(data.server_tags) ? data.server_tags : [],
    });
  }
  el('hostname').textContent = data.hostname || "—";
  el('os').textContent = data.os || data.os_name || "—";
  el('kernel').textContent = data.kernel || data.kernel_release || "—";
  el('executionScope').textContent = formatExecutionScope(data.execution_scope);
  el('uptime').textContent = fmtSecs(data.uptime_seconds || 0);
  el('cpus').textContent = data.cpu_count ?? "—";
  const updatesPendingEl = el('updatesPending');
  const updatesRebootEl = el('updatesReboot');
  const updatesStatusEl = el('updatesStatus');
  if (updatesPendingEl && updatesRebootEl && updatesStatusEl) {
    updatesStatusEl.classList.remove('status-ok', 'status-warn');
    const info = data.updates;
    if (info && typeof info.pending !== 'undefined') {
      if (updatesCard) {
        updatesCard.style.display = "block";
      }
      const pendingRaw = Number(info.pending);
      if (Number.isFinite(pendingRaw) && pendingRaw >= 0) {
        const pending = Math.trunc(pendingRaw);
        const rebootRequired = Boolean(info.reboot_required);
        updatesPendingEl.textContent = pending.toString();
        updatesRebootEl.textContent = rebootRequired ? "Oui" : "Non";
        if (pending === 0 && !rebootRequired) {
          updatesStatusEl.textContent = "À jour";
          updatesStatusEl.classList.add('status-ok');
        } else {
          updatesStatusEl.textContent = rebootRequired
            ? "Redémarrage requis"
            : "Mise à jour disponible";
          updatesStatusEl.classList.add('status-warn');
        }
      } else {
        updatesPendingEl.textContent = "—";
        updatesRebootEl.textContent = "—";
        updatesStatusEl.textContent = "Collecte indisponible";
      }
      if (updatesToggle && updatesDetails && updatesList) {
        const packages = Array.isArray(info.packages) ? info.packages : [];
        clearChildren(updatesList);
        if (packages.length > 0) {
          updatesToggle.style.display = "inline-flex";
          const collapsed = updatesDetails.classList.contains('collapsed');
          updatesToggle.textContent = collapsed ? "Détails" : "Masquer";
          updatesToggle.setAttribute('aria-expanded', (!collapsed).toString());
          const fragment = document.createDocumentFragment();
          packages.forEach((pkg) => fragment.appendChild(formatUpdatePackage(pkg)));
          updatesList.appendChild(fragment);
        } else {
          updatesToggle.style.display = "none";
          updatesDetails.classList.add('collapsed');
          updatesToggle.textContent = "Détails";
          updatesToggle.setAttribute('aria-expanded', 'false');
          updatesList.appendChild(createServiceEmpty());
        }
      }
    } else if (Object.prototype.hasOwnProperty.call(data, 'updates')) {
      if (updatesCard) {
        updatesCard.style.display = "block";
      }
      updatesPendingEl.textContent = "—";
      updatesRebootEl.textContent = "—";
      updatesStatusEl.textContent = "Collecte indisponible";
      if (updatesToggle && updatesDetails && updatesList) {
        updatesToggle.style.display = "none";
        updatesDetails.classList.add('collapsed');
        updatesToggle.textContent = "Détails";
        updatesToggle.setAttribute('aria-expanded', 'false');
        clearChildren(updatesList);
        updatesList.appendChild(createServiceEmpty());
      }
    } else {
      if (updatesCard) {
        updatesCard.style.display = "none";
      }
      updatesPendingEl.textContent = "—";
      updatesRebootEl.textContent = "—";
      updatesStatusEl.textContent = "—";
      if (updatesToggle && updatesDetails && updatesList) {
        updatesToggle.style.display = "none";
        updatesDetails.classList.add('collapsed');
        updatesToggle.textContent = "Détails";
        updatesToggle.setAttribute('aria-expanded', 'false');
        clearChildren(updatesList);
        updatesList.appendChild(createServiceEmpty());
      }
    }
  }

  el('memTotal').textContent = fmtBytes(data.total_memory_bytes || 0);
  el('memUsed').textContent = fmtBytes(data.used_memory_bytes || 0);

  const du = data.disk_usage || {};
  const total = num(du.total_bytes);
  const avail = num(du.available_bytes);
  let used = du.used_bytes != null ? num(du.used_bytes) : Math.max(0, total - avail);
  if (total > 0 && used > total) {
    used = total;
  }

  el('diskTotal').textContent = fmtBytes(total);
  el('diskAvail').textContent = fmtBytes(avail);
  const diskBar = el('diskBar');
  if (diskBar) {
    diskBar.style.width = getWidthFromBytes(total, avail);
  }

  const partitions = Array.isArray(du.partitions) ? du.partitions : [];
  const partitionsEl = el('partitions');
  if (partitionsEl) {
    clearChildren(partitionsEl);
    if (partitions.length > 0) {
      partitions.forEach((p) => {
        const pt = num(p.total_bytes);
        const pa = num(p.available_bytes);
        const mountPoint = p.mount_point ? String(p.mount_point) : "?";
        const fsType = p.fs_type ? String(p.fs_type) : "—";

        const infoLine = createEl(
          'div',
          '',
          `${mountPoint}  (fs: ${fsType}) — total: ${fmtBytes(pt)}, libre: ${fmtBytes(pa)}`
        );
        partitionsEl.appendChild(infoLine);

        const bar = createEl('div', 'bar');
        const span = document.createElement('span');
        span.style.width = getWidthFromBytes(pt, pa);
        bar.appendChild(span);
        partitionsEl.appendChild(bar);
      });
    } else {
      partitionsEl.textContent = "—";
    }
  }

  if (networkCard && networkList) {
    const entries = Array.isArray(data.network_traffic) ? data.network_traffic : [];
    clearChildren(networkList);
    if (entries.length > 0) {
      networkCard.style.display = "block";
      const fragment = document.createDocumentFragment();
      entries.forEach((entry) => {
        const name = entry?.name ? String(entry.name) : "interface";
        const rxBytes = fmtBytes(entry?.rx_bytes || 0);
        const txBytes = fmtBytes(entry?.tx_bytes || 0);
        const rxPackets = Math.trunc(num(entry?.rx_packets)).toLocaleString('fr-FR');
        const txPackets = Math.trunc(num(entry?.tx_packets)).toLocaleString('fr-FR');
        const rxErr = Math.trunc(num(entry?.rx_errors)).toLocaleString('fr-FR');
        const txErr = Math.trunc(num(entry?.tx_errors)).toLocaleString('fr-FR');
        const rxDrop = Math.trunc(num(entry?.rx_dropped)).toLocaleString('fr-FR');
        const txDrop = Math.trunc(num(entry?.tx_dropped)).toLocaleString('fr-FR');
        const rxMeta = `Rx ${rxBytes} (${rxPackets} paquets, err ${rxErr}, drop ${rxDrop})`;
        const txMeta = `Tx ${txBytes} (${txPackets} paquets, err ${txErr}, drop ${txDrop})`;

        const row = createEl('div', 'service-row');
        row.appendChild(createEl('span', 'dot service-dot ok'));

        const details = document.createElement('div');
        details.appendChild(createEl('div', 'service-name', name));
        details.appendChild(createEl('div', 'service-meta', `${rxMeta} • ${txMeta}`));
        row.appendChild(details);

        fragment.appendChild(row);
      });
      networkList.appendChild(fragment);
    } else if (Object.prototype.hasOwnProperty.call(data, 'network_traffic')) {
      networkCard.style.display = "block";
      networkList.appendChild(createServiceEmpty('Aucune interface réseau observée'));
    } else {
      networkCard.style.display = "none";
      networkList.appendChild(createServiceEmpty());
    }
  }

  const extensionsCard = document.getElementById('extensionsCard');
  const extensionsList = document.getElementById('extensionsList');
  if (extensionsCard && extensionsList) {
    const rawExtensions = data.extensions;
    const hasField = Object.prototype.hasOwnProperty.call(data, 'extensions');
    clearChildren(extensionsList);
    if (
      rawExtensions &&
      typeof rawExtensions === 'object' &&
      !Array.isArray(rawExtensions)
    ) {
      const entries = Object.entries(rawExtensions);
      if (entries.length > 0) {
        extensionsCard.style.display = 'block';
        const fragment = document.createDocumentFragment();
        entries
          .sort(([aName], [bName]) => aName.localeCompare(bName))
          .forEach(([pluginName, payload]) => {
            const row = createEl('div', 'service-row');
            row.appendChild(createEl('span', 'dot service-dot ok'));
            const details = document.createElement('div');
            details.appendChild(createEl('div', 'service-name', pluginName));
            const custom = pluginName === 'certificates-demo'
              ? renderCertificatesPlugin(payload)
              : null;
            if (custom && custom.length) {
              custom.forEach((node) => details.appendChild(node));
            } else {
              const values = extensionEntries(payload);
              details.appendChild(createEl('div', 'service-meta', values.join(' • ')));
            }
            row.appendChild(details);
            fragment.appendChild(row);
          });
        extensionsList.appendChild(fragment);
      } else if (hasField) {
        extensionsCard.style.display = 'block';
        extensionsList.appendChild(createServiceEmpty('Aucune extension active'));
      } else {
        extensionsCard.style.display = 'none';
        extensionsList.appendChild(createServiceEmpty());
      }
    } else if (hasField) {
      extensionsCard.style.display = 'block';
      extensionsList.appendChild(createServiceEmpty('Aucune donnée extension'));
    } else {
      extensionsCard.style.display = 'none';
      extensionsList.appendChild(createServiceEmpty());
    }
  }

  if (
    window.HistoryTrends &&
    typeof window.HistoryTrends.handleSnapshot === "function"
  ) {
    window.HistoryTrends.handleSnapshot(data);
  }

  raw.textContent = JSON.stringify(data, null, 2);
  last.textContent = new Date().toLocaleTimeString();
  dot.classList.add('ok');
}

function showError(message) {
  err.textContent = message;
  dot.classList.remove('ok');
}
