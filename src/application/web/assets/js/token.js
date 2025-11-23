const TOKEN_STORAGE_KEY = 'describe_me_token';
let lastFocusedBeforeOverlay = null;

function loadPersistedToken() {
  try {
    return window.localStorage.getItem(TOKEN_STORAGE_KEY) || "";
  } catch (_) {
    try {
      return window.sessionStorage.getItem(TOKEN_STORAGE_KEY) || "";
    } catch (_) {
      return "";
    }
  }
}

function persistToken(value) {
  try {
    window.localStorage.setItem(TOKEN_STORAGE_KEY, value);
  } catch (_) {
    try {
      window.sessionStorage.setItem(TOKEN_STORAGE_KEY, value);
    } catch (_) {
      // ignore
    }
  }
}

function clearPersistedToken() {
  try {
    window.localStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch (_) {
    // ignore
  }
  try {
    window.sessionStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch (_) {
    // ignore
  }
}

let currentToken = loadPersistedToken();
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
  persistToken(currentToken);
  hideTokenPrompt();
  restartStream();
});

tokenForget.addEventListener('click', () => {
  clearPersistedToken();
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

const getFocusableOverlayNodes = () => {
  if (!tokenOverlay) return [];
  const candidates = tokenOverlay.querySelectorAll(
    'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
  );
  return Array.from(candidates).filter((el) => {
    const rect = el.getBoundingClientRect();
    return !(el.offsetParent === null && rect.width === 0 && rect.height === 0);
  });
};

if (tokenOverlay) {
  tokenOverlay.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      hideTokenPrompt();
      return;
    }
    if (event.key !== 'Tab') {
      return;
    }
    const focusables = getFocusableOverlayNodes();
    if (focusables.length === 0) {
      return;
    }
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const active = document.activeElement;
    if (event.shiftKey) {
      if (active === first || !tokenOverlay.contains(active)) {
        event.preventDefault();
        last.focus();
      }
    } else if (active === last) {
      event.preventDefault();
      first.focus();
    }
  });
}

function showTokenPrompt(message) {
  lastFocusedBeforeOverlay =
    document.activeElement && typeof document.activeElement.focus === "function"
      ? document.activeElement
      : null;
  if (typeof message === "string" && message) {
    tokenErrorEl.textContent = message;
  }
  tokenOverlay.classList.add('visible');
  tokenOverlay.setAttribute('aria-hidden', 'false');
  setTimeout(() => tokenInput.focus(), 0);
  if (!overlayTimeout) {
    overlayTimeout = setTimeout(() => {
      sensitiveNodes.forEach((node) => node.classList.add('blurred')); 
    }, 1500);
  }
}

function hideTokenPrompt() {
  tokenOverlay.classList.remove('visible');
  tokenOverlay.setAttribute('aria-hidden', 'true');
  tokenErrorEl.textContent = "";
  if (overlayTimeout) {
    clearTimeout(overlayTimeout);
    overlayTimeout = null;
  }
  sensitiveNodes.forEach((node) => node.classList.remove('blurred'));
  if (lastFocusedBeforeOverlay && document.contains(lastFocusedBeforeOverlay)) {
    lastFocusedBeforeOverlay.focus();
  } else if (tokenOpen) {
    tokenOpen.focus();
  }
  lastFocusedBeforeOverlay = null;
}

function clearSessionCookie() {
  document.cookie = `${SESSION_COOKIE_NAME}=; Max-Age=0; path=/; SameSite=Strict`;
}
