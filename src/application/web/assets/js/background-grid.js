(function () {
  const canvas = document.getElementById("backgroundGridCanvas");
  if (!canvas || !canvas.getContext) {
    return;
  }

  const ctx = canvas.getContext("2d", { alpha: true });
  const rootStyles = getComputedStyle(document.documentElement);
  const colorLight = (rootStyles.getPropertyValue("--text") || "#ffffff").trim();
  const colorMid = (rootStyles.getPropertyValue("--bg-wave-1") || "#0f1115").trim();
  const colorDeep = (rootStyles.getPropertyValue("--bg-wave-2") || colorMid).trim();
  const colorHighlight =
    (rootStyles.getPropertyValue("--bg-wave-highlight") || colorMid).trim();
  const bgColor = (rootStyles.getPropertyValue("--bg") || "#0f1115").trim();

  let width = 0;
  let height = 0;
  let gradientCache = null;
  let deviceRatio = window.devicePixelRatio || 1;

  const gridCols = 68;
  const gridRows = 32;

  const pointStore = [];
  function ensureStore() {
    for (let r = 0; r <= gridRows; r += 1) {
      if (!pointStore[r]) {
        pointStore[r] = [];
      }
    }
  }

  function resizeCanvas() {
    deviceRatio = window.devicePixelRatio || 1;
    const cssWidth = window.innerWidth;
    const cssHeight = window.innerHeight;
    canvas.width = Math.round(cssWidth * deviceRatio);
    canvas.height = Math.round(cssHeight * deviceRatio);
    width = canvas.width;
    height = canvas.height;
    gradientCache = null;
  }

  function getGradient() {
    if (gradientCache) {
      return gradientCache;
    }
    const gradient = ctx.createLinearGradient(0, height * 0.9, width, height * 0.1);
    gradient.addColorStop(0, colorHighlight);
    gradient.addColorStop(0.35, colorMid);
    gradient.addColorStop(1, colorDeep);
    gradientCache = gradient;
    return gradient;
  }

  function projectPoint(u, v, time) {
    const horizon = height * 0.12;
    const depth = height * 0.88;
    const perspective = Math.pow(v, 1.42);
    let y = horizon + perspective * depth;
    const spread = 1 + 0.7 * (1 - v);
    let x = (u - 0.5) * width * spread;
    const diagonalPull = (u - 0.5) * depth * 0.22;
    y -= diagonalPull;

    const waveA = Math.sin(u * 8 - time * 0.8 + v * 2.4);
    const waveB = Math.cos(v * 5.6 + time * 0.6 - u * 3.2);
    const combinedWave = waveA + waveB;
    const amplitude = 16 + v * 26;
    const perspectiveBoost = 0.3 + 0.7 * v;
    const waveOffset = combinedWave * amplitude * perspectiveBoost;
    y += waveOffset;
    x += Math.sin(v * 4.8 + time * 0.3) * 16;

    const waveLuma = 0.4 + 0.6 * (1 / (1 + Math.exp(-waveOffset / 20)));

    x += width / 2;
    return { x, y, waveLuma };
  }

  function renderFrame(timestamp) {
    const time = timestamp * 0.001;
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, width, height);

    ctx.save();
    ctx.globalAlpha = 0.35;
    ctx.fillStyle = getGradient();
    ctx.fillRect(0, 0, width, height);
    ctx.restore();

    ensureStore();
    for (let row = 0; row <= gridRows; row += 1) {
      const v = row / gridRows;
      for (let col = 0; col <= gridCols; col += 1) {
        const u = col / gridCols;
        pointStore[row][col] = projectPoint(u, v, time);
      }
    }

    ctx.save();
    ctx.lineWidth = Math.max(0.65 * deviceRatio, 0.4);
    ctx.strokeStyle = colorLight || bgColor;

    const alphaBase = 0.18;
    const alphaRange = 0.45;

    for (let row = 0; row <= gridRows; row += 1) {
      for (let col = 0; col < gridCols; col += 1) {
        const start = pointStore[row][col];
        const end = pointStore[row][col + 1];
        const intensity = alphaBase + alphaRange * ((start.waveLuma + end.waveLuma) * 0.5);
        ctx.globalAlpha = intensity;
        ctx.beginPath();
        ctx.moveTo(start.x, start.y);
        ctx.lineTo(end.x, end.y);
        ctx.stroke();
      }
    }

    for (let col = 0; col <= gridCols; col += 1) {
      for (let row = 0; row < gridRows; row += 1) {
        const start = pointStore[row][col];
        const end = pointStore[row + 1][col];
        const intensity = alphaBase + alphaRange * ((start.waveLuma + end.waveLuma) * 0.5);
        ctx.globalAlpha = intensity;
        ctx.beginPath();
        ctx.moveTo(start.x, start.y);
        ctx.lineTo(end.x, end.y);
        ctx.stroke();
      }
    }

    ctx.restore();
    requestAnimationFrame(renderFrame);
  }

  function start() {
    document.body.classList.add("has-bg-canvas");
    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);
    requestAnimationFrame(renderFrame);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})();
