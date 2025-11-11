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
      clearPersistedToken();
      currentToken = "";
      tokenInput.value = "";
      clearSessionCookie();
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
