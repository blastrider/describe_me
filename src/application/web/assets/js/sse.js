let eventSource = null;
let reconnectTimer = null;
let reconnectAttempt = 0;

const RECONNECT_BASE_MS = 4000;
const RECONNECT_MAX_MS = 30000;

function restartStream() {
  stopStream();
  connectSse();
}

function stopStream() {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}

function connectSse() {
  if (tokenOverlay.classList.contains('visible')) {
    return;
  }
  stopStream();

  try {
    eventSource = new EventSource("/sse");
  } catch (err) {
    showError("Flux SSE indisponible.");
    scheduleReconnect();
    return;
  }

  eventSource.onopen = () => {
    hideTokenPrompt();
    reconnectAttempt = 0;
    sensitiveNodes.forEach((node) => node.classList.remove('blurred'));
  };

  eventSource.onmessage = (event) => {
    handleSseMessage(event.data);
  };

  eventSource.onerror = async () => {
    stopStream();
    sensitiveNodes.forEach((node) => node.classList.add('blurred'));
    const status = await probeSseStatus();
    if (status === 401) {
      showError("Authentification requise pour accéder aux métriques.");
      showTokenPrompt("Jeton requis pour accéder aux métriques.");
      return;
    }
    if (status === 403) {
      showError("Adresse IP non autorisée pour le flux SSE.");
      return;
    }
    showError("Flux SSE interrompu (reconnexion dans quelques secondes).");
    scheduleReconnect();
  };
}

async function probeSseStatus() {
  if (tokenOverlay.classList.contains('visible')) {
    return 401;
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 1500);
  try {
    const response = await fetch("/sse", {
      method: "GET",
      headers: { Accept: "text/event-stream" },
      credentials: "same-origin",
      signal: controller.signal,
    });
    clearTimeout(timeout);
    controller.abort();
    return response.status;
  } catch (_) {
    clearTimeout(timeout);
    return 0;
  }
}

function handleSseMessage(payload) {
  if (!payload) {
    return;
  }
  try {
    const parsed = JSON.parse(payload);
    if (parsed && parsed.error) {
      showError(parsed.error);
      return;
    }
    currentSnapshot = parsed;
    applyFiltersAndRender();
    updateUI(parsed);
  } catch (e) {
    const message = e && e.message ? e.message : String(e);
    showError("Erreur de parsing JSON: " + message);
  }
}

function scheduleReconnect() {
  if (tokenOverlay.classList.contains('visible')) {
    return;
  }
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
  }
  const backoff = RECONNECT_BASE_MS * Math.pow(2, reconnectAttempt);
  const capped = Math.min(RECONNECT_MAX_MS, backoff);
  const jitter = Math.floor(capped * 0.2 * Math.random());
  const delay = capped + jitter;
  reconnectAttempt = Math.min(reconnectAttempt + 1, 8);
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectSse();
  }, delay);
}
