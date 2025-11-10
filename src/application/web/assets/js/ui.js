let latestDescription = "";
let descriptionEditing = false;
let descriptionSaving = false;

function updateUI(data) {
  err.textContent = "";

  syncDescriptionUI(
    typeof data.server_description === "string" ? data.server_description : ""
  );
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

function syncDescriptionUI(value) {
  if (!descriptionCard || !descriptionText || !descriptionEmpty) {
    return;
  }
  latestDescription = typeof value === "string" ? value : "";
  const hasContent = latestDescription.trim().length > 0;
  if (hasContent) {
    descriptionText.textContent = latestDescription;
    descriptionText.style.display = "block";
    descriptionEmpty.style.display = "none";
  } else {
    descriptionText.textContent = "";
    descriptionText.style.display = "none";
    descriptionEmpty.style.display = "block";
  }
  if (!descriptionEditing && descriptionInput) {
    descriptionInput.value = latestDescription;
  }
}

function openDescriptionEditor() {
  if (!descriptionForm) {
    return;
  }
  descriptionEditing = true;
  descriptionForm.hidden = false;
  if (descriptionEdit) {
    descriptionEdit.setAttribute('disabled', 'disabled');
  }
  if (descriptionInput) {
    descriptionInput.value = latestDescription;
    descriptionInput.focus();
  }
  setDescriptionHint("", "");
}

function closeDescriptionEditor(reset = true) {
  if (!descriptionForm) {
    return;
  }
  descriptionEditing = false;
  descriptionForm.hidden = true;
  if (descriptionEdit) {
    descriptionEdit.removeAttribute('disabled');
  }
  if (reset && descriptionInput) {
    descriptionInput.value = latestDescription;
  }
  setDescriptionHint("", "");
}

function setDescriptionHint(message, tone = "") {
  if (!descriptionHint) {
    return;
  }
  descriptionHint.textContent = message || "";
  descriptionHint.classList.remove('error', 'success');
  if (tone) {
    descriptionHint.classList.add(tone);
  }
}

async function submitDescriptionForm() {
  if (!descriptionInput || descriptionSaving) {
    return;
  }
  descriptionSaving = true;
  setDescriptionHint("Enregistrement…");
  if (descriptionSave) {
    descriptionSave.disabled = true;
  }
  try {
    const payload = { text: descriptionInput.value };
    const headers = { "Content-Type": "application/json" };
    if (currentToken) {
      headers["Authorization"] = `Bearer ${currentToken}`;
    }
    const response = await fetch('/api/description', {
      method: 'POST',
      headers,
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    if (response.status === 401) {
      const message = await readJsonMessage(response);
      showTokenPrompt(message || "Jeton requis pour modifier la description.");
      return;
    }
    if (response.status === 403) {
      const message = await readJsonMessage(response);
      setDescriptionHint(message || "Adresse IP non autorisée.", 'error');
      return;
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message =
        (data && typeof data.error === "string" && data.error) ||
        "Impossible d'enregistrer la description.";
      setDescriptionHint(message, 'error');
      return;
    }
    const nextValue =
      data && typeof data.description === "string" ? data.description : "";
    syncDescriptionUI(nextValue);
    closeDescriptionEditor();
  } catch (_) {
    setDescriptionHint("Impossible d'enregistrer la description.", 'error');
  } finally {
    descriptionSaving = false;
    if (descriptionSave) {
      descriptionSave.disabled = false;
    }
  }
}

async function readJsonMessage(response) {
  try {
    const text = await response.text();
    if (!text) {
      return "";
    }
    const data = JSON.parse(text);
    if (data && typeof data.error === "string") {
      return data.error;
    }
    return text;
  } catch (_) {
    return "";
  }
}
