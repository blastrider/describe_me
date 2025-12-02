(function () {
  const API_ENDPOINT = "/api/history";
  const HISTORY_WINDOW = 1800;
  const HISTORY_LIMIT = 180;
  const REFRESH_INTERVAL_MS = 60_000;
  const COLORS = {
    cpu: "#3ad29f",
    mem: "#5c92ff",
    disk: "#f5a623",
  };

  let initialized = false;
  let card;
  let errorEl;
  let refreshBtn;
  let valueLabels = {};
  let canvases = {};
  let pendingFetch = null;
  let lastFetch = 0;
  let paranoidBlocked = false;

  function init() {
    card = document.getElementById("historyCard");
    if (!card) {
      return;
    }
    errorEl = card.querySelector('[data-role="history-error"]');
    refreshBtn = card.querySelector('[data-role="history-refresh"]');
    valueLabels = {
      cpu: card.querySelector('[data-role="history-value-cpu"]'),
      mem: card.querySelector('[data-role="history-value-mem"]'),
      disk: card.querySelector('[data-role="history-value-disk"]'),
    };
    canvases = {
      cpu: card.querySelector('[data-role="history-canvas-cpu"]'),
      mem: card.querySelector('[data-role="history-canvas-mem"]'),
      disk: card.querySelector('[data-role="history-canvas-disk"]'),
    };
    if (refreshBtn) {
      refreshBtn.addEventListener("click", () => fetchHistory());
    }
    initialized = true;
    scheduleRefresh();
  }

  function handleSnapshot(snapshot) {
    if (!initialized || !card || paranoidBlocked) {
      return;
    }
    updateMetricValue("cpu", computeCpuPercentage(snapshot));
    updateMetricValue("mem", computeMemoryPercentage(snapshot));
    updateMetricValue("disk", computeDiskPercentage(snapshot));
    scheduleRefresh();
  }

  function scheduleRefresh(force = false) {
    if (!initialized || !card || paranoidBlocked) {
      return;
    }
    const now = Date.now();
    if (force || (!pendingFetch && now - lastFetch > REFRESH_INTERVAL_MS)) {
      fetchHistory();
    }
  }

  async function fetchHistory() {
    if (!initialized || !card || paranoidBlocked) {
      return;
    }
    if (pendingFetch) {
      return;
    }
    showError("");
    const params = new URLSearchParams();
    params.set("window", HISTORY_WINDOW.toString());
    params.set("limit", HISTORY_LIMIT.toString());
    pendingFetch = fetch(`${API_ENDPOINT}?${params.toString()}`, {
      method: "GET",
      credentials: "same-origin",
    })
      .then(async (response) => {
        const text = await response.text();
        let payload = null;
        if (text) {
          try {
            payload = JSON.parse(text);
          } catch (_) {
            payload = null;
          }
        }
        if (!response.ok) {
          const message =
            payload && typeof payload.error === "string"
              ? payload.error
              : `Historique indisponible (HTTP ${response.status})`;
          throw { status: response.status, message };
        }
        return payload;
      })
      .then((payload) => {
        if (!payload) {
          throw { status: 500, message: "Réponse vide de l'historique." };
        }
        paranoidBlocked = false;
        applyHistory(payload);
      })
      .catch((err) => {
        handleHistoryError(err);
      })
      .finally(() => {
        pendingFetch = null;
      });
  }

  function handleHistoryError(err) {
    const status = err && typeof err.status === "number" ? err.status : 0;
    const message =
      err && typeof err.message === "string"
        ? err.message
        : "Historique indisponible.";
    if (status === 403) {
      paranoidBlocked = true;
      showCard(true);
      showError(message || "Historique désactivé pour cette vue.");
      return;
    }
    if (status === 404) {
      showCard(true);
      showError("Aucun point historique disponible pour le moment.");
      return;
    }
    showError(message);
  }

  function applyHistory(payload) {
    if (!payload || !Array.isArray(payload.points)) {
      showError("Réponse historique invalide.");
      return;
    }
    showError("");
    lastFetch = Date.now();
    showCard(true);
    const cpuValues = payload.points.map((point) =>
      sanitizePercent(metricAverage(point && point.cpu)),
    );
    const memValues = payload.points.map((point) =>
      sanitizePercent(metricAverage(point && point.mem)),
    );
    const diskValues = payload.points.map((point) =>
      sanitizePercent(metricAverage(point && point.disk)),
    );
    drawSparkline(canvases.cpu, cpuValues, COLORS.cpu);
    drawSparkline(canvases.mem, memValues, COLORS.mem);
    drawSparkline(canvases.disk, diskValues, COLORS.disk);
    toggleMetricVisibility("disk", diskValues.some((v) => typeof v === "number"));

    const lastPoint = payload.points[payload.points.length - 1];
    if (lastPoint) {
      updateMetricValue("cpu", sanitizePercent(metricAverage(lastPoint.cpu)));
      updateMetricValue("mem", sanitizePercent(metricAverage(lastPoint.mem)));
      updateMetricValue("disk", sanitizePercent(metricAverage(lastPoint.disk)));
    }
  }

  function showCard(visible) {
    if (!card) {
      return;
    }
    card.style.display = visible ? "block" : "none";
  }

  function showError(message) {
    if (!errorEl) {
      return;
    }
    if (message) {
      errorEl.textContent = message;
      errorEl.classList.add("history-error-visible");
      errorEl.removeAttribute("hidden");
      showCard(true);
    } else {
      errorEl.textContent = "";
      errorEl.classList.remove("history-error-visible");
      errorEl.setAttribute("hidden", "hidden");
    }
  }

  function updateMetricValue(metric, value) {
    const label = valueLabels[metric];
    if (!label) {
      return;
    }
    if (typeof value === "number" && Number.isFinite(value)) {
      label.textContent = `${value.toFixed(1)}%`;
    } else {
      label.textContent = "—";
    }
  }

  function toggleMetricVisibility(metric, visible) {
    const block = card && card.querySelector(`[data-role="history-block-${metric}"]`);
    if (!block) return;
    if (visible) {
      block.removeAttribute("hidden");
    } else {
      block.setAttribute("hidden", "hidden");
    }
  }

  function drawSparkline(canvas, values, color) {
    if (!canvas) {
      return;
    }
    const validValues = values.filter((v) => typeof v === "number");
    const width = canvas.clientWidth || 220;
    const height = canvas.clientHeight || 60;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    const ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.lineWidth = Math.max(1.5 * dpr, 1);
    ctx.strokeStyle = color;
    ctx.lineJoin = "round";
    ctx.lineCap = "round";
    ctx.globalAlpha = validValues.length === 0 ? 0.15 : 1;
    if (validValues.length === 0 || values.length === 0) {
      return;
    }
    ctx.beginPath();
    const step = values.length > 1 ? canvas.width / (values.length - 1) : 0;
    let started = false;
    values.forEach((value, index) => {
      if (typeof value !== "number") {
        started = false;
        return;
      }
      const clamped = Math.min(Math.max(value, 0), 100);
      const x = index * step;
      const y = canvas.height - (clamped / 100) * canvas.height;
      if (!started) {
        ctx.moveTo(x, y);
        started = true;
      } else {
        ctx.lineTo(x, y);
      }
    });
    ctx.stroke();
  }

  function metricAverage(metric) {
    if (!metric || typeof metric.avg !== "number" || !Number.isFinite(metric.avg)) {
      return undefined;
    }
    return metric.avg;
  }

  function sanitizePercent(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
      return undefined;
    }
    return Math.min(Math.max(value, 0), 100);
  }

  function computeCpuPercentage(snapshot) {
    if (
      !snapshot ||
      !Array.isArray(snapshot.load_average) ||
      snapshot.load_average.length === 0
    ) {
      return undefined;
    }
    const la = Number(snapshot.load_average[0]);
    const cpuCount = Number(snapshot.cpu_count || 1);
    if (!Number.isFinite(la) || !Number.isFinite(cpuCount) || cpuCount <= 0) {
      return undefined;
    }
    const ratio = la / cpuCount;
    return Math.min(Math.max(ratio * 100, 0), 100);
  }

  function computeMemoryPercentage(snapshot) {
    if (
      !snapshot ||
      typeof snapshot.total_memory_bytes === "undefined" ||
      typeof snapshot.used_memory_bytes === "undefined"
    ) {
      return undefined;
    }
    const total = Number(snapshot.total_memory_bytes);
    const used = Number(snapshot.used_memory_bytes);
    if (!Number.isFinite(total) || total <= 0 || !Number.isFinite(used)) {
      return undefined;
    }
    const pct = (Math.min(Math.max(used, 0), total) / total) * 100;
    return Math.min(Math.max(pct, 0), 100);
  }

  function computeDiskPercentage(snapshot) {
    if (!snapshot || typeof snapshot.disk_usage !== "object" || !snapshot.disk_usage) {
      return undefined;
    }
    const used = Number(snapshot.disk_usage.used_bytes);
    const total = Number(snapshot.disk_usage.total_bytes);
    if (!Number.isFinite(total) || total <= 0 || !Number.isFinite(used)) {
      return undefined;
    }
    const pct = (Math.min(Math.max(used, 0), total) / total) * 100;
    return Math.min(Math.max(pct, 0), 100);
  }

  window.HistoryTrends = {
    init,
    handleSnapshot,
  };
})();
