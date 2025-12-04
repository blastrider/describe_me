tokenForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const value = tokenInput.value.trim();
  if (!value) {
    tokenErrorEl.textContent = "Merci de renseigner un jeton.";
    tokenInput.focus();
    return;
  }
  const ok = await submitToken(value);
  if (ok) {
    tokenInput.value = "";
    hideTokenPrompt();
    restartStream();
  }
});

tokenForget.addEventListener('click', async () => {
  await logoutServerSession();
  tokenInput.value = "";
  tokenErrorEl.textContent = "";
  showTokenPrompt("");
});

if (tokenOpen) {
  tokenOpen.addEventListener('click', () => {
    tokenErrorEl.textContent = "";
    if (typeof stopStream === "function") {
      stopStream();
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

async function logoutServerSession() {
  try {
    await fetch("/auth/logout", {
      method: "POST",
      credentials: "same-origin",
    });
  } catch (_) {
    // ignore network failures
  }
}

async function submitToken(token) {
  try {
    const res = await fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ token }),
    });
    if (res.ok || res.status === 303) {
      return true;
    }
    const message = await readLoginError(res);
    tokenErrorEl.textContent = message || "Jeton invalide.";
    return false;
  } catch (err) {
    tokenErrorEl.textContent = "Connexion impossible (réessayez).";
    return false;
  }
}

async function readLoginError(response) {
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
