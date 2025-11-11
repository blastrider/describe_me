const TOKEN_STORAGE_KEY = 'describe_me_token';

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

function clearSessionCookie() {
  document.cookie = `${SESSION_COOKIE_NAME}=; Max-Age=0; path=/; SameSite=Strict`;
}
