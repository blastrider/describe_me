  const WEB_DEBUG = __WEB_DEBUG__;
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

  let currentToken = sessionStorage.getItem('describe_me_token') || "";
  if (currentToken) {
    tokenInput.value = currentToken;
  }
  let abortController = null;
  let reconnectTimer = null;

  tokenForm.addEventListener('submit', (event) => {
    event.preventDefault();
    const value = tokenInput.value.trim();
    if (!value) {
      tokenErrorEl.textContent = "Merci de renseigner un jeton.";
      tokenInput.focus();
      return;
    }
    currentToken = value;
    sessionStorage.setItem('describe_me_token', currentToken);
    hideTokenPrompt();
    restartStream();
  });

  tokenForget.addEventListener('click', () => {
    sessionStorage.removeItem('describe_me_token');
    currentToken = "";
    tokenInput.value = "";
    tokenErrorEl.textContent = "";
    showTokenPrompt("");
  });

  if (tokenOpen) {
    tokenOpen.addEventListener('click', () => {
      tokenInput.value = currentToken;
      tokenErrorEl.textContent = "";
      if (abortController) {
        abortController.abort();
        abortController = null;
      }
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      showTokenPrompt("");
    });
  }

  const sensitiveNodes = Array.from(document.querySelectorAll('[data-sensitive]'));
  let overlayTimeout = null;

  function showTokenPrompt(message) {
    if (typeof message === "string" && message) {
      tokenErrorEl.textContent = message;
    }
    tokenOverlay.classList.add('visible');
    setTimeout(() => tokenInput.focus(), 0);
    if (!overlayTimeout) {
      overlayTimeout = setTimeout(() => {
        sensitiveNodes.forEach((node) => node.classList.add('blurred')); 
      }, 1500);
    }
  }

  function hideTokenPrompt() {
    tokenOverlay.classList.remove('visible');
    tokenErrorEl.textContent = "";
    if (overlayTimeout) {
      clearTimeout(overlayTimeout);
      overlayTimeout = null;
    }
    sensitiveNodes.forEach((node) => node.classList.remove('blurred'));
  }

  function restartStream() {
    if (abortController) {
      abortController.abort();
      abortController = null;
    }
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    connectSse();
  }

  async function connectSse() {
    if (abortController) {
      abortController.abort();
    }
    abortController = new AbortController();
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }

    try {
      const headers = {};
      if (currentToken) {
        headers["Authorization"] = `Bearer ${currentToken}`;
      }

      const response = await fetch('/sse', {
        method: 'GET',
        headers,
        signal: abortController.signal,
        credentials: 'same-origin',
      });

      if (response.status === 401) {
        const message = await readErrorMessage(response);
        sessionStorage.removeItem('describe_me_token');
        currentToken = "";
        tokenInput.value = "";
        clearTokenCookie();
        showError(message || "Jeton requis pour accéder aux métriques.");
        showTokenPrompt(message || "Jeton requis pour accéder aux métriques.");
        return;
      }

      if (response.status === 403) {
        const message = await readErrorMessage(response);
        showError(message || "Adresse IP non autorisée.");
        scheduleReconnect();
        return;
      }

      if (!response.ok || !response.body) {
        showError(`Flux SSE indisponible (HTTP ${response.status}).`);
        scheduleReconnect();
        return;
      }

      hideTokenPrompt();
      sensitiveNodes.forEach((node) => node.classList.remove('blurred'));
      await consumeSse(response.body);
      abortController = null;
      scheduleReconnect();
    } catch (err) {
      if (err && err.name === 'AbortError') {
        return;
      }
      showError("Flux SSE interrompu (nouvelle tentative dans quelques secondes).");
      sensitiveNodes.forEach((node) => node.classList.add('blurred'));
      scheduleReconnect();
    }
  }

  async function readErrorMessage(response) {
    try {
      const text = await response.text();
      if (!text) return "";
      const data = JSON.parse(text);
      if (data && typeof data.error === "string") {
        return data.error;
      }
      return text;
    } catch (_) {
      return "";
    }
  }

  async function consumeSse(body) {
    const reader = body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';

    while (true) {
      const { value, done } = await reader.read();
      if (done) {
        buffer += decoder.decode();
        buffer = processSseBuffer(buffer, true);
        break;
      }
      buffer += decoder.decode(value, { stream: true });
      buffer = processSseBuffer(buffer, false);
    }
  }

  function processSseBuffer(buffer, flush) {
    let index;
    while ((index = buffer.indexOf('\n\n')) !== -1) {
      const chunk = buffer.slice(0, index);
      buffer = buffer.slice(index + 2);
      handleSseEvent(chunk);
    }
    if (flush && buffer.trim() !== "") {
      handleSseEvent(buffer);
      return "";
    }
    return buffer;
  }

  function handleSseEvent(rawEvent) {
    const lines = rawEvent.split(/\r?\n/);
    const dataLines = [];
    for (const line of lines) {
      if (line.startsWith('data:')) {
        dataLines.push(line.slice(5).trimStart());
      }
    }
    if (dataLines.length === 0) {
      return;
    }
    const payload = dataLines.join('\n');
    try {
      const parsed = JSON.parse(payload);
      if (parsed && parsed.error) {
        showError(parsed.error);
        return;
      }
      updateUI(parsed);
    } catch (e) {
      showError("Erreur de parsing JSON: " + (e && e.message ? e.message : e));
    }
  }

  function scheduleReconnect(delay = 4000) {
    if (tokenOverlay.classList.contains('visible')) {
      return;
    }
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
    }
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connectSse();
    }, delay);
  }

  function updateUI(data) {
    err.textContent = "";

    el('hostname').textContent = data.hostname || "—";
    el('os').textContent = data.os || data.os_name || "—";
    el('kernel').textContent = data.kernel || data.kernel_release || "—";
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
    el('diskBar').style.width = pct(used, total).toFixed(1) + "%";

    const partitions = Array.isArray(du.partitions) ? du.partitions : [];
    const partitionsEl = el('partitions');
    if (partitionsEl) {
      clearChildren(partitionsEl);
      if (partitions.length > 0) {
        partitions.forEach((p) => {
          const pt = num(p.total_bytes);
          const pa = num(p.available_bytes);
          const usedPart = Math.max(0, Math.min(pt, pt - pa));
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
          span.style.width = pct(usedPart, pt).toFixed(1) + "%";
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

    const servicesCard = document.getElementById('servicesCard');
    const servicesList = document.getElementById('servicesList');
    if (servicesCard && servicesList) {
      const services = Array.isArray(data.services_running) ? data.services_running : [];
      const summary = data.services_summary;
      clearChildren(servicesList);
      if (services.length > 0) {
        servicesCard.style.display = "block";
        const fragment = document.createDocumentFragment();
        services.forEach((svc) => {
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
          fragment.appendChild(row);
        });
        servicesList.appendChild(fragment);
      } else if (summary && typeof summary.total === 'number') {
        servicesCard.style.display = "block";
        const items = Array.isArray(summary.by_state) ? summary.by_state : [];
        const row = createEl('div', 'service-row');
        row.appendChild(createEl('span', 'dot service-dot'));

        const details = document.createElement('div');
        details.appendChild(
          createEl('div', 'service-name', `${summary.total} service(s) observé(s)`)
        );

        const meta = createEl('div', 'service-meta');
        if (items.length > 0) {
          items.forEach((item, index) => {
            const badgeText = `${item.state}: ${item.count}`;
            const badge = createEl('span', 'badge', badgeText);
            meta.appendChild(badge);
            if (index < items.length - 1) {
              meta.appendChild(document.createTextNode(' '));
            }
          });
        } else {
          meta.textContent = "Aucune donnée détaillée";
        }

        details.appendChild(meta);
        row.appendChild(details);
        servicesList.appendChild(row);
      } else if ('services_running' in data) {
        servicesCard.style.display = "block";
        servicesList.appendChild(createServiceEmpty('Aucun service actif rapporté'));
      } else {
        servicesCard.style.display = "none";
      }
    }

    const socketsCard = document.getElementById('socketsCard');
    const socketsGrid = document.getElementById('socketsGrid');
    const socketsTcpCard = document.getElementById('socketsTcpCard');
    const socketsUdpCard = document.getElementById('socketsUdpCard');
    const socketsTcp = document.getElementById('socketsTcp');
    const socketsUdp = document.getElementById('socketsUdp');
    if (socketsGrid && socketsTcp && socketsUdp && socketsTcpCard && socketsUdpCard) {
      const sockets = Array.isArray(data.listening_sockets) ? data.listening_sockets : [];
      if (sockets.length > 0) {
        socketsGrid.style.display = "grid";
        const grouped = sockets.reduce(
          (acc, sock) => {
            const proto = (sock?.proto || "").toLowerCase();
            const normalized = proto === "udp" ? "udp" : "tcp";
            acc[normalized].push(sock);
            return acc;
          },
          { tcp: [], udp: [] }
        );

        const renderSockets = (list) => {
          const fragment = document.createDocumentFragment();
          list.forEach((sock) => {
            const proto = sock?.proto ? String(sock.proto) : "?";
            const addr = sock?.addr ? String(sock.addr) : "—";
            const port = sock?.port != null ? Number(sock.port) : "—";
            const pid =
              sock && typeof sock.pid === "number"
                ? `PID ${sock.pid}`
                : "";
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

        clearChildren(socketsTcp);
        if (grouped.tcp.length) {
          socketsTcpCard.style.display = "block";
          socketsTcp.appendChild(renderSockets(grouped.tcp));
        } else {
          socketsTcpCard.style.display = "block";
          socketsTcp.appendChild(createServiceEmpty('Aucun port TCP'));
        }

        clearChildren(socketsUdp);
        if (grouped.udp.length) {
          socketsUdpCard.style.display = "block";
          socketsUdp.appendChild(renderSockets(grouped.udp));
        } else {
          socketsUdpCard.style.display = "block";
          socketsUdp.appendChild(createServiceEmpty('Aucun port UDP'));
        }
      } else if ('listening_sockets' in data) {
        socketsGrid.style.display = "grid";
        socketsTcpCard.style.display = "block";
        socketsUdpCard.style.display = "block";
        clearChildren(socketsTcp);
        clearChildren(socketsUdp);
        socketsTcp.appendChild(createServiceEmpty('Aucun port TCP'));
        socketsUdp.appendChild(createServiceEmpty('Aucun port UDP'));
      } else {
        socketsGrid.style.display = "none";
        socketsTcpCard.style.display = "none";
        socketsUdpCard.style.display = "none";
        clearChildren(socketsTcp);
        clearChildren(socketsUdp);
      }
    }

    raw.textContent = JSON.stringify(data, null, 2);
    last.textContent = new Date().toLocaleTimeString();
    dot.classList.add('ok');
  }

  function showError(message) {
    err.textContent = message;
    dot.classList.remove('ok');
  }

  connectSse();
