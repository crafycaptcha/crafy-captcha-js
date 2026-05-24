import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

const CONFIG = {
  iframeUrl: 'https://captcha.crafy.net/challenge/',
  turnstileScript: 'https://challenges.cloudflare.com/turnstile/v0/api.js'
};

const DICTIONARY = {
  es: { 'Verifica que eres humano': "Verifica que eres humano", 'Nuevo Desafío': "Nuevo Desafío", 'Error de conexión. Recarga la página.': "Error de conexión. Recarga la página." },
  en: { 'Verifica que eres humano': "Verify that you are human", 'Nuevo Desafío': "New Challenge", 'Error de conexión. Recarga la página.': "Connection error. Please reload the page." },
  fr: { 'Verifica que eres humano': "Vérifiez que vous êtes humain", 'Nuevo Desafío': "Nouveau défi", 'Error de conexión. Recarga la página.': "Erreur de connexion. Veuillez recharger la page." },
  pt: { 'Verifica que eres humano': "Verifique se você é humano", 'Nuevo Desafío': "Novo Desafio", 'Error de conexión. Recarga la página.': "Erro de conexão. Por favor, recarregue a página." },
  de: { 'Verifica que eres humano': "Bestätigen Sie, dass Sie ein Mensch sind", 'Nuevo Desafío': "Neue Herausforderung", 'Error de conexión. Recarga la página.': "Verbindungsfehler. Bitte laden Sie die Seite neu." },
  it: { 'Verifica que eres humano': "Verifica di essere umano", 'Nuevo Desafío': "Nuova sfida", 'Error de conexión. Recarga la página.': "Errore di connessione. Ricarica la pagina." },
  ru: { 'Verifica que eres humano': "Подтвердите, что вы человек", 'Nuevo Desafío': "Новое испытание", 'Error de conexión. Recarga la página.': "Ошибка подключения. Пожалуйста, перезагрузите страницу." },
  zh: { 'Verifica que eres humano': "验证您是人类", 'Nuevo Desafío': "新挑战", 'Error de conexión. Recarga la página.': "连接错误。请重新加载页面。" },
  ja: { 'Verifica que eres humano': "人間であることを確認してください", 'Nuevo Desafío': "新しいチャレンジ", 'Error de conexión. Recarga la página.': "接続エラー。ページを再読み込みしてください。" },
  hi: { 'Verifica que eres humano': "सत्यापित करें कि आप मानव हैं", 'Nuevo Desafío': "नई चुनौती", 'Error de conexión. Recarga la página.': "कनेक्शन त्रुटि। कृपया पृष्ठ को पुनः लोड करें।" }
};

function utf8ToBase64(str) {
  const bytes = new TextEncoder().encode(str);
  const binString = String.fromCodePoint(...bytes);
  return btoa(binString);
}

class CrafyCAPTCHA {
  constructor() {
    this.publicKey = null;
    this.publicToken = null;
    this.signingKey = null;
    this.encryptedOptions = null;
    this.container = null;
    this.iframe = null;
    this.startWidget = null;
    this.footerControl = null;
    this.turnstileWidgetId = null;
    this.flowToken = null;
    this._turnstileStatus = 'pending'; // 'pending' | 'solved' | 'error'
    this._turnstileToken = null;
    this._turnstileInitReceived = false;
    this.iframeUrl = CONFIG.iframeUrl;
    this.debug = false;
    this.isSolved = false;
    this.lang = 'es';
    this.computedStyles = {};
    this.shadowRoot = null;

    const rawLang = (typeof navigator !== 'undefined' && navigator.languages && navigator.languages.length)
      ? navigator.languages[0]
      : (typeof navigator !== 'undefined' ? (navigator.language || navigator.userLanguage) : 'es');
    const langIso2 = rawLang.split(/[-_]/)[0].toLowerCase();
    if (langIso2.length) {
      this.lang = langIso2;
    }
  }

  setDebug(value) {
    this.debug = !!value;
  }

  _log(...args) {
    if (this.debug) console.log('[CrafyCAPTCHA JS SDK]', ...args);
  }

  _warn(...args) {
    if (this.debug) console.warn('[CrafyCAPTCHA JS SDK]', ...args);
  }

  _error(...args) {
    if (this.debug) console.error('[CrafyCAPTCHA JS SDK]', ...args);
  }

  async init(containerRef, publicKey, publicToken, signingPublicKey, encryptedOptions, options = {}) {
    // 1. Ceder el hilo de ejecución momentáneamente (Yield) 
    // Evita bloquear la renderización inicial del DOM de la página del cliente
    await new Promise(resolve => setTimeout(resolve, 0));

    this.publicKey = publicKey;
    this.publicToken = publicToken;
    this.signingKey = signingPublicKey;
    this.encryptedOptions = encryptedOptions;
    this.options = options;

    this.computedStyles = this._resolveStyles(options.theme, options.style);
    if (this.options.iframeUrl) this.iframeUrl = this.options.iframeUrl;

    this.container = typeof containerRef === 'string'
      ? document.getElementById(containerRef)
      : containerRef;

    if (!this.container) return;

    if (this.container.hasAttribute('data-crafy-initialized')) {
      this._warn('El widget ya está inicializado en este contenedor.');
      return;
    }
    this.container.setAttribute('data-crafy-initialized', 'true');

    this.shadowRoot = this.container.attachShadow({ mode: 'closed' });

    this._injectStyles();
    this._renderInterface();

    if (typeof window !== 'undefined') {
      this._messageHandler = this._handleMessage.bind(this);
      window.addEventListener('message', this._messageHandler);
      // Start loading Turnstile in the background to speed up subsequent renders
      this._loadTurnstile().catch(() => { });

      this._onlineHandler = () => this._recoverNetwork();
      this._offlineHandler = () => this._showOfflineWarning();
      window.addEventListener('online', this._onlineHandler);
      window.addEventListener('offline', this._offlineHandler);
    }

    this.parentForm = this.container.closest('form');
    if (this.parentForm) {
      this.parentForm.addEventListener('submit', (e) => {
        if (!this.isSolved) {
          e.preventDefault();
          if (this._showCaptchaUI) this._showCaptchaUI();
          this._pendingSubmit = true;
        }
      });
    }
  }

  destroy() {
    if (typeof window !== 'undefined' && this._messageHandler) {
      window.removeEventListener('message', this._messageHandler);
      window.removeEventListener('online', this._onlineHandler);
      window.removeEventListener('offline', this._offlineHandler);
    }
    if (this._turnstileRetryInterval) {
      clearInterval(this._turnstileRetryInterval);
      this._turnstileRetryInterval = null;
    }
    if (this._tamperObserver) {
      this._tamperObserver.disconnect();
      this._tamperObserver = null;
    }
    if (this._expireTimer) {
      clearTimeout(this._expireTimer);
      this._expireTimer = null;
    }
    if (this.container) {
      this.container.removeAttribute('data-crafy-initialized');
      if (this.shadowRoot) {
        this.shadowRoot.innerHTML = '';
      }
      this.container.innerHTML = '';
    }
  }

  _translate(text) {
    if (this.lang && DICTIONARY[this.lang] && DICTIONARY[this.lang][text]) {
      return DICTIONARY[this.lang][text];
    }
    return DICTIONARY['es'][text] || text;
  }

  _resolveStyles(theme = 'light', customStyle = {}) {
    const isDark = theme === 'dark';
    const defaults = {
      bg: isDark ? '#1f2937' : '#f9fafb',
      bgHover: isDark ? '#374151' : '#f3f4f6',
      text: isDark ? '#e5e7eb' : '#374151',
      border: isDark ? '#4b5563' : '#d1d5db',
      primary: '#2563eb',
      footerText: isDark ? '#9ca3af' : '#6b7280'
    };
    return {
      bg: customStyle.background || defaults.bg,
      bgHover: customStyle.backgroundHover || defaults.bgHover,
      text: customStyle.color || defaults.text,
      border: customStyle.borderColor || defaults.border,
      primary: customStyle.primary || defaults.primary,
      footerText: customStyle.footerColor || defaults.footerText,
      theme: theme
    };
  }

  _injectStyles() {
    if (typeof document === 'undefined') return;

    const s = this.computedStyles;
    const css = `
      .crafy-wrapper { all: initial; display: block; width: 100%; height: 100%; }
      iframe { border: none; margin: 0; padding: 0; }
      .crafy-start-box { margin: auto; display: flex; align-items: center; justify-content: space-between; background: ${s.bg}; border: 1px solid ${s.border}; border-radius: 6px; padding: 12px 16px; cursor: pointer; font-family: -apple-system, system-ui, sans-serif; transition: all 0.2s ease; user-select: none; max-width: 350px; }
      .crafy-start-box:hover { background: ${s.bgHover}; border-color: ${s.text}; }
      .crafy-content { display: flex; align-items: center; gap: 12px; }
      .crafy-checkbox { width: 24px; height: 24px; border: 2px solid ${s.border}; border-radius: 4px; background: ${s.theme === 'dark' ? '#374151' : 'white'}; }
      .crafy-text { font-size: 14px; color: ${s.text}; font-weight: 500; }
      .crafy-logo { width: 20px; opacity: 0.5; filter: ${s.theme === 'dark' ? 'invert(1)' : 'none'}; }
      .crafy-footer { margin: auto; display: flex; justify-content: space-between; align-items: center; width: 100%; max-width: 350px; font-family: -apple-system, system-ui, sans-serif; font-size: 15px; color: ${s.footerText}; margin-top: 5px; }
      .crafy-reload-btn { background: none; border: none; color: ${s.primary}; cursor: pointer; padding: 4px; display: flex; align-items: center; gap: 4px; font-size: 15px; font-weight: 500; }
      .crafy-reload-btn:hover { text-decoration: underline; opacity: 0.8; }
      .crafy-reload-icon { font-size: 14px; line-height: 1; }
      .crafy-link { color: ${s.primary}; text-decoration: none; }
      .crafy-link:hover { text-decoration: underline; }
    `;
    const style = document.createElement('style');
    style.id = 'crafy-styles';
    style.appendChild(document.createTextNode(css));

    const oldStyle = this.shadowRoot.querySelector('#crafy-styles');
    if (oldStyle) oldStyle.remove();
    this.shadowRoot.appendChild(style);
  }

  _renderInterface() {
    if (typeof document === 'undefined') return;

    const children = Array.from(this.shadowRoot.childNodes);
    children.forEach(child => {
      if (child.id !== 'crafy-styles') {
        this.shadowRoot.removeChild(child);
      }
    });

    const url = new URL(this.iframeUrl);
    url.searchParams.set('pt', this.publicToken);
    url.searchParams.set('eo', this.encryptedOptions);
    url.searchParams.set('theme', this.computedStyles.theme);

    const fragment = document.createDocumentFragment();

    const wrapper = document.createElement('div');
    wrapper.className = 'crafy-wrapper';

    // 1. Widget UI (Síncrono para que se vea rápido)
    this.startWidget = document.createElement('div');
    this.startWidget.className = 'crafy-start-box';
    this.startWidget.innerHTML = `<div class="crafy-content"><div class="crafy-checkbox"></div><span class="crafy-text">${this._translate('Verifica que eres humano')}</span></div><div class="crafy-logo">🛡️</div>`;

    // 2. Iframe (Estructura base, SIN src inicialmente)
    this.iframe = document.createElement('iframe');
    // No usar loading='lazy': el iframe está off-screen y el navegador nunca lo cargaría
    this.iframe.sandbox = "allow-scripts allow-same-origin allow-popups allow-forms";
    this.iframe.title = this._translate('Verifica que eres humano');
    this.iframe.setAttribute('aria-label', 'CrafyCAPTCHA Security Check');
    this.iframe.setAttribute('aria-hidden', 'true');
    this.iframe.tabIndex = -1;
    this.iframe.style.cssText = `
      position: absolute !important;
      top: -9999px !important;
      left: -9999px !important;
      width: 1px !important;
      height: 1px !important;
      visibility: visible !important;
      opacity: 1 !important;
      pointer-events: none !important;
      z-index: -2147483648 !important;
      border: none !important;
    `;

    // Footer UI
    this.footerControl = document.createElement('div');
    this.footerControl.className = 'crafy-footer';
    this.footerControl.style.visibility = 'hidden';
    this.footerControl.innerHTML = `<span>Protected by <a href="https://captcha.crafy.net/" target="_blank" rel="noopener noreferrer" class="crafy-link">CrafyCAPTCHA</a></span><button type="button" class="crafy-reload-btn"><span class="crafy-reload-icon">↻</span> ${this._translate('Nuevo Desafío')}</button>`;

    this.footerControl.querySelector('.crafy-reload-btn').addEventListener('click', (e) => {
      e.preventDefault(); e.stopPropagation(); this.reset();
    });

    // Ensamblar en memoria
    wrapper.appendChild(this.startWidget);
    wrapper.appendChild(this.iframe);
    wrapper.appendChild(this.footerControl);

    fragment.appendChild(wrapper);

    // Inyectar TODO de un solo golpe al DOM real (1 solo reflow) dentro del shadowRoot
    this.shadowRoot.appendChild(fragment);

    // --- ESTRATEGIA DE PRE-CARGA DEL IFRAME ---
    // El iframe se carga en segundo plano (invisible pero renderizable por el navegador)
    // para que cuando el usuario haga clic, el contenido ya esté listo.
    let iframeSrcSet = false;
    const preloadIframe = () => {
      if (iframeSrcSet) return;
      this.iframe.src = url.toString();
      iframeSrcSet = true;
    };

    this._showCaptchaUI = () => {
      preloadIframe();
      this.startWidget.style.display = 'none';
      this.iframe.style.cssText = `
        position: relative !important;
        width: 100% !important;
        height: 420px !important;
        pointer-events: auto !important;
        z-index: 1000 !important;
        border: none !important;
        overflow: hidden !important;
      `;
      this.iframe.removeAttribute('aria-hidden');
      this.iframe.tabIndex = 0;
      this.footerControl.style.visibility = 'visible';
    };

    // Evento Click: mostrar el iframe ya pre-cargado (o forzar carga si aún no ocurrió)
    this.startWidget.addEventListener('click', this._showCaptchaUI);

    // Pre-cargar el iframe de forma no intrusiva:
    // requestIdleCallback (con timeout de 2s) > setTimeout 500ms como fallback.
    // Esto asegura que el iframe empiece a cargar poco después del render inicial
    // de la página, sin competir con los recursos críticos del host.
    if (typeof window !== 'undefined') {
      if (window.requestIdleCallback) {
        window.requestIdleCallback(preloadIframe, { timeout: 2000 });
      } else {
        setTimeout(preloadIframe, 500);
      }
    }
  }

  reset() {
    if (!this.iframe || !this.iframe.src) return;
    const url = new URL(this.iframe.src);
    url.searchParams.set('retry', Date.now());
    this.iframe.src = url.toString();
    this._turnstileStatus = 'pending';
    this._turnstileToken = null;
    this._turnstileInitReceived = false;
    if (typeof window !== 'undefined' && window.turnstile && this.turnstileWidgetId) {
      turnstile.reset(this.turnstileWidgetId);
    }
    this._hideTurnstileWidget();
  }

  async _handleMessage(event) {
    const expectedOrigin = new URL(this.iframeUrl).origin;
    if (event.origin !== expectedOrigin) {
      return;
    }
    if (event.source !== this.iframe.contentWindow) {
      if (event.data?.action === 'INIT_TURNSTILE') {
        this._warn('Aceptando INIT_TURNSTILE a pesar del desajuste de event.source (posible quirk del navegador durante reload rápido).');
      } else {
        this._warn('Mensaje ignorado porque event.source no coincide con el contentWindow del iframe.', { action: event.data?.action });
        return;
      }
    }
    const { action, payload, signature, server_sign } = event.data;

    if (action && action !== 'RESIZE') {
      this._log('Mensaje recibido del iframe:', action);
    }

    if (action === 'RESIZE' && payload?.height && this.iframe) {
      this.iframe.style.height = payload.height + 'px';
      return;
    }

    if (!action) return;

    if (action === 'INIT_TURNSTILE') {
      this._turnstileInitReceived = true;
      this._log('Procesando INIT_TURNSTILE...');
      setTimeout(async () => {
        if (!this._verifySignature(payload, signature)) {
          this._error('Firma inválida para INIT_TURNSTILE.');
          return;
        }
        let decoded_payload = typeof payload === 'string' ? JSON.parse(payload).payload : (payload.payload || payload);
        this.flowToken = decoded_payload.flow_token;
        this._log('INIT_TURNSTILE verificado. site_key:', decoded_payload.site_key);

        if (decoded_payload.site_key) {
          this._log('Cargando widget Turnstile real...');
          try {
            await this._loadTurnstile();
            this._renderTurnstile(decoded_payload.site_key);
          } catch (e) {
            this._error('Error cargando Turnstile:', e);
            this._turnstileStatus = 'error';
            this._sendToIframe('TURNSTILE_ERROR', { message: 'Network error' });
          }
        } else {
          this._log('Modo sin Turnstile, enviando TURNSTILE_SOLVED: skipped');
          this._turnstileStatus = 'solved';
          this._turnstileToken = 'skipped';
          this._sendToIframe('TURNSTILE_SOLVED', { token: 'skipped' });
        }
      }, 0);
    }

    if (action === 'REQUEST_TURNSTILE_STATUS') {
      this._log(`Iframe solicitó estado de Turnstile. Estado actual: ${this._turnstileStatus}`);
      if (this._turnstileStatus === 'solved') {
        this._sendToIframe('TURNSTILE_SOLVED', { token: this._turnstileToken });
      } else if (this._turnstileStatus === 'error') {
        this._sendToIframe('TURNSTILE_ERROR', { message: 'Network error' });
      } else if (this._turnstileStatus === 'pending') {
        if (!this._turnstileInitReceived) {
          this._warn('Estado es pending y no se ha recibido INIT_TURNSTILE. Solicitando al iframe que re-envíe (REQUEST_HANDSHAKE_RETRY).');
          this._sendToIframe('REQUEST_HANDSHAKE_RETRY', {});
        } else {
          this._log('Estado es pending pero INIT_TURNSTILE ya fue recibido. Esperando resolución de Turnstile.');
        }
      }
      return;
    }

    if (action === 'CHALLENGE_COMPLETE') {
      setTimeout(() => {
        if (!this._verifySignature(payload, signature)) return;
        this._handleSuccess(payload, server_sign);
      }, 0);
    }
  }

  _verifySignature(payloadStr, signatureBase64) {
    try {
      const messageUint8 = naclUtil.decodeUTF8(payloadStr);
      const signatureUint8 = naclUtil.decodeBase64(signatureBase64);
      const publicKeyUint8 = naclUtil.decodeBase64(this.signingKey);
      return nacl.sign.detached.verify(messageUint8, signatureUint8, publicKeyUint8);
    } catch (e) {
      this._error('Error verificando firma:', e);
      return false;
    }
  }

  _loadTurnstile() {
    if (this._turnstileLoadPromise) return this._turnstileLoadPromise;

    this._turnstileLoadPromise = new Promise((resolve, reject) => {
      if (typeof window === 'undefined' || window.turnstile) return resolve();

      if (document.getElementById('crafy-turnstile-script')) {
        const checkTurnstile = setInterval(() => {
          if (window.turnstile) { clearInterval(checkTurnstile); resolve(); }
        }, 50);
        return;
      }

      const preconnect = document.createElement('link');
      preconnect.rel = 'preconnect';
      preconnect.href = 'https://challenges.cloudflare.com';
      document.head.appendChild(preconnect);

      const script = document.createElement('script');
      script.id = 'crafy-turnstile-script';
      script.src = CONFIG.turnstileScript;
      script.async = true;
      script.defer = true;
      if (this.options && this.options.cspNonce) {
        script.nonce = this.options.cspNonce;
      }

      const timeout = setTimeout(() => {
        reject(new Error('Turnstile load timeout'));
        this._showOfflineWarning();
      }, 7000);

      script.onload = () => {
        clearTimeout(timeout);
        resolve();
      };

      script.onerror = () => {
        clearTimeout(timeout);
        this._reportFatalError('TURNSTILE_BLOCKED', 'No se pudo cargar el script de Cloudflare');
        reject(new Error('Turnstile blocked by network'));
        this._showOfflineWarning();
      };

      document.head.appendChild(script);
    });

    return this._turnstileLoadPromise;
  }

  _showTurnstileWidget() {
    const tDiv = document.getElementById('crafy-turnstile-hidden');
    if (tDiv) {
      tDiv.style.cssText = `
        display: flex !important;
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        background-color: rgba(0, 0, 0, 0.6) !important;
        z-index: 2147483647 !important;
        align-items: center !important;
        justify-content: center !important;
        pointer-events: auto !important;
        visibility: visible !important;
        opacity: 1 !important;
      `;
    }
  }

  _hideTurnstileWidget() {
    const tDiv = document.getElementById('crafy-turnstile-hidden');
    if (tDiv) {
      tDiv.style.cssText = `
        position: absolute !important;
        top: -9999px !important;
        left: -9999px !important;
        width: 1px !important;
        height: 1px !important;
        visibility: visible !important;
        opacity: 1 !important;
        pointer-events: none !important;
        z-index: -2147483648 !important;
      `;
    }
  }

  _renderTurnstile(siteKey) {
    if (typeof document === 'undefined') return;
    let tDiv = document.getElementById('crafy-turnstile-hidden');
    if (!tDiv) {
      tDiv = document.createElement('div');
      tDiv.id = 'crafy-turnstile-hidden';
      tDiv.style.cssText = `
        position: absolute !important;
        top: -9999px !important;
        left: -9999px !important;
        width: 1px !important;
        height: 1px !important;
        visibility: visible !important;
        opacity: 1 !important;
        pointer-events: none !important;
        z-index: -2147483648 !important;
      `;
      tDiv.addEventListener('click', (e) => {
        if (e.target === tDiv) this._hideTurnstileWidget();
      });
      document.body.appendChild(tDiv);
    }

    // Si ya existe el widget, simplemente lo reseteamos para que lance un nuevo desafío.
    if (this.turnstileWidgetId !== null && typeof turnstile !== 'undefined') {
      turnstile.reset(this.turnstileWidgetId);
      return;
    }

    try {
      this.turnstileWidgetId = turnstile.render('#crafy-turnstile-hidden', {
        sitekey: siteKey,
        appearance: 'interaction-only',
        callback: (token) => {
          this._hideTurnstileWidget();
          this._turnstileStatus = 'solved';
          this._turnstileToken = token;
          this._sendToIframe('TURNSTILE_SOLVED', { token });
        },
        'error-callback': () => {
          this._hideTurnstileWidget();
          this._warn('Error Turnstile');
        },
        'before-interactive-callback': () => this._showTurnstileWidget(),
        'after-interactive-callback': () => this._hideTurnstileWidget(),
        'unsupported-callback': () => this._hideTurnstileWidget()
      });
    } catch (e) {
      if (typeof turnstile !== 'undefined') turnstile.reset('#crafy-turnstile-hidden');
    }
  }

  _sendToIframe(action, data) {
    if (this.iframe && this.iframe.contentWindow) {
      this._log(`Enviando ${action} al iframe...`);
      const msg = { action, ...data };
      this.iframe.contentWindow.postMessage(msg, '*');
    } else {
      this._warn(`Intento de enviar ${action} fallido: iframe o contentWindow no existen.`);
    }
  }

  _handleSuccess(payload, server_sign) {
    if (typeof document === 'undefined') return;
    this.isSolved = true;
    if (this.footerControl) {
      this.footerControl.style.visibility = 'hidden';
      setTimeout(() => this.footerControl.style.visibility = 'visible', 10000);
    }

    const inputName = this.options.inputName || 'CrafyCAPTCHA_token';
    let input = document.querySelector(`input[name="${inputName}"]`);
    if (!input) {
      input = document.createElement('input');
      input.type = 'hidden';
      input.name = inputName;
      (this.container.closest('form') || this.container).appendChild(input);
    }

    const payload_for_server_str = utf8ToBase64(JSON.stringify({ payload, server_sign }));
    input.value = payload_for_server_str;
    this.container.dispatchEvent(new CustomEvent('crafy:success', { detail: payload_for_server_str }));
    if (this.options.onSuccess) this.options.onSuccess(payload_for_server_str);

    this._protectTokenInput(input, payload_for_server_str);

    if (this._expireTimer) clearTimeout(this._expireTimer);
    this._expireTimer = setTimeout(() => {
      input.value = '';
      this.isSolved = false;
      this._showExpiredUI();
      if (this.options.onExpire) this.options.onExpire();
    }, 19 * 60 * 1000);

    if (this._pendingSubmit && this.parentForm) {
      if (typeof this.parentForm.requestSubmit === 'function') {
        this.parentForm.requestSubmit();
      } else {
        this.parentForm.submit();
      }
    }
  }

  _protectTokenInput(inputElement, validToken) {
    if (this._tamperObserver) this._tamperObserver.disconnect();

    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'attributes' && mutation.attributeName === 'value') {
          if (inputElement.value !== validToken && inputElement.value !== '') {
            this._warn('Intento de manipulación detectado.');
            inputElement.value = validToken;
          }
        }
        if (mutation.type === 'childList' && Array.from(mutation.removedNodes).includes(inputElement)) {
          const parent = this.parentForm || this.container;
          if (parent) parent.appendChild(inputElement);
        }
      });
    });

    observer.observe(inputElement, { attributes: true });
    const parent = this.parentForm || this.container;
    if (parent) observer.observe(parent, { childList: true });

    this._tamperObserver = observer;
  }

  _showExpiredUI() {
    this.reset();
    if (this.startWidget) {
      this.startWidget.style.display = 'flex';
      this.startWidget.style.borderColor = 'red';
      const textSpan = this.startWidget.querySelector('.crafy-text');
      if (textSpan) textSpan.style.color = 'red';
    }
    if (this.iframe) {
      this.iframe.style.cssText = `
        position: absolute !important;
        top: -9999px !important;
        left: -9999px !important;
        width: 1px !important;
        height: 1px !important;
        visibility: visible !important;
        opacity: 1 !important;
        pointer-events: none !important;
        z-index: -2147483648 !important;
        border: none !important;
      `;
      this.iframe.setAttribute('aria-hidden', 'true');
      this.iframe.tabIndex = -1;
    }
    if (this.footerControl) {
      this.footerControl.style.visibility = 'hidden';
    }
  }

  _showOfflineWarning() {
    if (this.startWidget) {
      const textSpan = this.startWidget.querySelector('.crafy-text');
      if (textSpan) {
        this._originalText = textSpan.innerText;
        textSpan.innerText = this._translate('Error de conexión. Recarga la página.');
        textSpan.style.color = 'orange';
      }
    }
  }

  _recoverNetwork() {
    if (this.startWidget) {
      const textSpan = this.startWidget.querySelector('.crafy-text');
      if (textSpan && this._originalText) {
        textSpan.innerText = this._originalText;
        textSpan.style.color = this.computedStyles.text;
      }
    }
    if (!window.turnstile) {
      this._turnstileLoadPromise = null;
      this._loadTurnstile().catch(() => { });
    }
  }

  _reportFatalError(errorType, message) {
    if (typeof navigator !== 'undefined' && navigator.sendBeacon) {
      const payload = JSON.stringify({
        pk: this.publicKey,
        error: errorType,
        msg: message,
        url: window.location.hostname
      });
      navigator.sendBeacon('https://captcha.crafy.net/api/telemetry.php?code=crafy_telemetry_secure_2026', payload);
    }
  }
}

// Soporte para Singleton
CrafyCAPTCHA._instance = null;
CrafyCAPTCHA.init = function (...args) {
  if (!CrafyCAPTCHA._instance) CrafyCAPTCHA._instance = new CrafyCAPTCHA();
  CrafyCAPTCHA._instance.init(...args);
  return CrafyCAPTCHA._instance;
};
CrafyCAPTCHA.setDebug = function (value) {
  if (!CrafyCAPTCHA._instance) CrafyCAPTCHA._instance = new CrafyCAPTCHA();
  CrafyCAPTCHA._instance.setDebug(value);
};
CrafyCAPTCHA.reset = function () {
  if (CrafyCAPTCHA._instance) return CrafyCAPTCHA._instance.reset();
};

// Exponemos la clase de manera global para que se pueda llamar con etiquetas script en el navegador
if (typeof window !== 'undefined') {
  window.CrafyCAPTCHA = CrafyCAPTCHA;
}

export default CrafyCAPTCHA;