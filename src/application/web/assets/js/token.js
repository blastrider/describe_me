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

function clearTokenCookie() {
  document.cookie = `${TOKEN_COOKIE_NAME}=; Max-Age=0; path=/; SameSite=Strict`;
}
