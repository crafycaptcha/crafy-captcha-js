import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

const CONFIG = {
  iframeUrl: 'https://captcha.crafy.net/challenge/',
  turnstileScript: 'https://challenges.cloudflare.com/turnstile/v0/api.js'
};

const DICTIONARY = {
  es: { 'Verifica que eres humano': "Verifica que eres humano", 'Nuevo Desafío': "Nuevo Desafío" },
  en: { 'Verifica que eres humano': "Verify that you are human", 'Nuevo Desafío': "New Challenge" },
  fr: { 'Verifica que eres humano': "Vérifiez que vous êtes humain", 'Nuevo Desafío': "Nouveau défi" },
  pt: { 'Verifica que eres humano': "Verifique se você é humano", 'Nuevo Desafío': "Novo Desafio" },
  de: { 'Verifica que eres humano': "Bestätigen Sie, dass Sie ein Mensch sind", 'Nuevo Desafío': "Neue Herausforderung" },
  it: { 'Verifica que eres humano': "Verifica di essere umano", 'Nuevo Desafío': "Nuova sfida" },
  ru: { 'Verifica que eres humano': "Подтвердите, что вы человек", 'Nuevo Desafío': "Новое испытание" },
  zh: { 'Verifica que eres humano': "验证您是人类", 'Nuevo Desafío': "新挑战" },
  ja: { 'Verifica que eres humano': "人間であることを確認してください", 'Nuevo Desafío': "新しいチャレンジ" },
  hi: { 'Verifica que eres humano': "सत्यापित करें कि आप मानव हैं", 'Nuevo Desafío': "नई चुनौती" }
};

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
    this.iframeUrl = CONFIG.iframeUrl;
    this.isSolved = false;
    this.lang = 'es';
    this.computedStyles = {};

    const rawLang = (typeof navigator !== 'undefined' && navigator.languages && navigator.languages.length)
      ? navigator.languages[0]
      : (typeof navigator !== 'undefined' ? (navigator.language || navigator.userLanguage) : 'es');
    const langIso2 = rawLang.split(/[-_]/)[0].toLowerCase();
    if (langIso2.length) {
      this.lang = langIso2;
    }
  }

  async init(containerRef, publicKey, publicToken, signingPublicKey, encryptedOptions, options = {}) {
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

    this._injectStyles();
    this._renderInterface();

    if (typeof window !== 'undefined') {
      window.addEventListener('message', this._handleMessage.bind(this));
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
    if (document.getElementById('crafy-styles')) document.getElementById('crafy-styles').remove();

    const s = this.computedStyles;
    const css = `
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
    `;
    const style = document.createElement('style');
    style.id = 'crafy-styles';
    style.appendChild(document.createTextNode(css));
    document.head.appendChild(style);
  }

  _renderInterface() {
    if (typeof document === 'undefined') return;
    this.container.innerHTML = '';

    const url = new URL(this.iframeUrl);
    url.searchParams.set('pt', this.publicToken);
    url.searchParams.set('eo', this.encryptedOptions);
    url.searchParams.set('theme', this.computedStyles.theme);

    this.startWidget = document.createElement('div');
    this.startWidget.className = 'crafy-start-box';
    this.startWidget.innerHTML = `<div class="crafy-content"><div class="crafy-checkbox"></div><span class="crafy-text">${this._translate('Verifica que eres humano')}</span></div><div class="crafy-logo">🛡️</div>`;

    this.startWidget.addEventListener('click', () => {
      this.startWidget.style.display = 'none';
      this.iframe.style.display = 'block';
      this.footerControl.style.visibility = 'visible';
    });

    this.iframe = document.createElement('iframe');
    this.iframe.src = url.toString();
    this.iframe.style = 'width: 100%; height: 420px; border: none; overflow: hidden; display: none;';

    this.footerControl = document.createElement('div');
    this.footerControl.className = 'crafy-footer';
    this.footerControl.style.visibility = 'hidden';
    this.footerControl.innerHTML = `<span>Protected by CrafyCAPTCHA</span><button type="button" class="crafy-reload-btn"><span class="crafy-reload-icon">↻</span> ${this._translate('Nuevo Desafío')}</button>`;

    this.footerControl.querySelector('.crafy-reload-btn').addEventListener('click', (e) => {
      e.preventDefault(); e.stopPropagation(); this.reset();
    });

    this.container.append(this.startWidget, this.iframe, this.footerControl);
  }

  reset() {
    const url = new URL(this.iframe.src);
    url.searchParams.set('retry', Date.now());
    this.iframe.src = url.toString();
    if (typeof window !== 'undefined' && window.turnstile && this.turnstileWidgetId) {
      turnstile.reset(this.turnstileWidgetId);
    }
  }

  async _handleMessage(event) {
    if (event.origin !== new URL(this.iframeUrl).origin) return;
    const { action, payload, signature, server_sign } = event.data;

    if (action === 'RESIZE' && payload?.height && this.iframe) {
      this.iframe.style.height = payload.height + 'px';
      return;
    }

    if (!action || !payload) return;

    if (action === 'INIT_TURNSTILE') {
      if (!this._verifySignature(payload, signature)) return;
      let decoded_payload = typeof payload === 'string' ? JSON.parse(payload).payload : (payload.payload || payload);
      this.flowToken = decoded_payload.flow_token;
      await this._loadTurnstile();
      this._renderTurnstile(decoded_payload.site_key);
    }

    if (action === 'CHALLENGE_COMPLETE') {
      if (!this._verifySignature(payload, signature)) return;
      this._handleSuccess(payload, server_sign);
    }
  }

  _verifySignature(payloadStr, signatureBase64) {
    try {
      const messageUint8 = naclUtil.decodeUTF8(payloadStr);
      const signatureUint8 = naclUtil.decodeBase64(signatureBase64);
      const publicKeyUint8 = naclUtil.decodeBase64(this.signingKey);
      return nacl.sign.detached.verify(messageUint8, signatureUint8, publicKeyUint8);
    } catch (e) {
      console.error('[Crafy] Error verificando firma:', e);
      return false;
    }
  }

  _loadTurnstile() {
    return new Promise((resolve) => {
      if (typeof window === 'undefined' || window.turnstile) return resolve();
      const script = document.createElement('script');
      script.src = CONFIG.turnstileScript;
      script.async = true;
      script.defer = true;
      script.onload = resolve;
      document.head.appendChild(script);
    });
  }

  _renderTurnstile(siteKey) {
    if (typeof document === 'undefined') return;
    let tDiv = document.getElementById('crafy-turnstile-hidden');
    if (!tDiv) {
      tDiv = document.createElement('div');
      tDiv.id = 'crafy-turnstile-hidden';
      tDiv.style.display = 'none';
      document.body.appendChild(tDiv);
    }
    try {
      this.turnstileWidgetId = turnstile.render('#crafy-turnstile-hidden', {
        sitekey: siteKey,
        callback: (token) => this._sendToIframe('TURNSTILE_SOLVED', { token }),
        'error-callback': () => console.warn('[Crafy] Error Turnstile')
      });
    } catch (e) {
      if (typeof turnstile !== 'undefined') turnstile.reset('#crafy-turnstile-hidden');
    }
  }

  _sendToIframe(action, data) {
    if (this.iframe && this.iframe.contentWindow) {
      this.iframe.contentWindow.postMessage({ action, ...data }, '*');
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

    const payload_for_server_str = btoa(JSON.stringify({ payload, server_sign }));
    input.value = payload_for_server_str;
    this.container.dispatchEvent(new CustomEvent('crafy:success', { detail: payload_for_server_str }));
    if (this.options.onSuccess) this.options.onSuccess(payload_for_server_str);
  }
}

// Soporte para Singleton
CrafyCAPTCHA._instance = null;
CrafyCAPTCHA.init = function (...args) {
  if (!CrafyCAPTCHA._instance) CrafyCAPTCHA._instance = new CrafyCAPTCHA();
  return CrafyCAPTCHA._instance.init(...args);
};
CrafyCAPTCHA.reset = function () {
  if (CrafyCAPTCHA._instance) return CrafyCAPTCHA._instance.reset();
};

// Exponemos la clase de manera global para que se pueda llamar con etiquetas script en el navegador
if (typeof window !== 'undefined') {
  window.CrafyCAPTCHA = CrafyCAPTCHA;
}

export default CrafyCAPTCHA;