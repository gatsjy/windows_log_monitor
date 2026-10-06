// 모던 다이얼로그 & 토스트 알림 컴포넌트
// 브라우저 기본 alert(), confirm() 대신 부드럽고 일관된 UI 제공
import { html, raw } from './util.js';

let toastContainer = null;

function ensureToastContainer() {
  if (!toastContainer || !toastContainer.isConnected) {
    toastContainer = document.createElement('div');
    toastContainer.className = 'toast-container';
    toastContainer.setAttribute('aria-live', 'polite');
    document.body.appendChild(toastContainer);
  }
  return toastContainer;
}

const TOAST_ICONS = {
  success: '<svg viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>',
  error: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>',
  warning: '<svg viewBox="0 0 24 24"><path d="M10.3 3.4L1.7 18.5A2 2 0 0 0 3.4 21.5h17.2a2 2 0 0 0 1.7-3L13.7 3.4a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/></svg>',
  info: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>',
};

/**
 * 토스트 메시지를 화면에 띄웁니다.
 * @param {string} message - 안내 문구
 * @param {{type?: 'info'|'success'|'error'|'warning', duration?: number}} options
 */
export function toast(message, { type = 'info', duration = 3200 } = {}) {
  const container = ensureToastContainer();
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.innerHTML = `
    <div class="toast-icon">${TOAST_ICONS[type] || TOAST_ICONS.info}</div>
    <div class="toast-msg">${message}</div>
    <button type="button" class="toast-close" aria-label="닫기">✕</button>
  `;

  const remove = () => {
    if (el.classList.contains('toast-out')) return;
    el.classList.add('toast-out');
    el.addEventListener('animationend', () => el.remove(), { once: true });
  };

  el.querySelector('.toast-close').addEventListener('click', remove);

  container.appendChild(el);

  if (duration > 0) {
    setTimeout(remove, duration);
  }
  return el;
}

/**
 * 모던 확인창 (confirm 대체)
 * @param {string|{title?: string, message: string, confirmText?: string, cancelText?: string, danger?: boolean}} opt
 * @returns {Promise<boolean>}
 */
export function confirmModal(opt) {
  const options = typeof opt === 'string' ? { message: opt } : opt;
  const {
    title = '확인',
    message,
    confirmText = '확인',
    cancelText = '취소',
    danger = false,
  } = options;

  return new Promise((resolve) => {
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    const dangerIcon = danger
      ? '<span class="modal-danger-badge" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 9v4M12 17h.01M10.3 3.4L1.7 18.5A2 2 0 0 0 3.4 21.5h17.2a2 2 0 0 0 1.7-3L13.7 3.4a2 2 0 0 0-3.4 0z"/></svg></span>'
      : '';

    overlay.innerHTML = html`
      <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="modal-title">
        <div class="modal-head">
          <div class="modal-title" id="modal-title">${danger ? raw(dangerIcon) : ''}${title}</div>
          <button type="button" class="modal-close" data-cancel aria-label="닫기">✕</button>
        </div>
        <div class="modal-body">
          <p class="modal-text">${message}</p>
        </div>
        <div class="modal-foot">
          <button type="button" class="btn" data-cancel>${cancelText}</button>
          <button type="button" class="btn ${danger ? 'danger primary' : 'primary'}" data-confirm>${confirmText}</button>
        </div>
      </div>
    `.s;

    const close = (result) => {
      document.body.style.overflow = prevOverflow;
      document.removeEventListener('keydown', onKeyDown);
      overlay.classList.add('closing');
      overlay.addEventListener('animationend', () => overlay.remove(), { once: true });
      resolve(result);
    };

    const onKeyDown = (e) => {
      if (e.key === 'Escape') close(false);
      else if (e.key === 'Enter') close(true);
    };

    overlay.querySelectorAll('[data-cancel]').forEach((b) => b.addEventListener('click', () => close(false)));
    overlay.querySelector('[data-confirm]').addEventListener('click', () => close(true));

    let isMouseDownOnOverlay = false;
    overlay.addEventListener('mousedown', (e) => {
      isMouseDownOnOverlay = e.target === overlay;
    });
    overlay.addEventListener('click', (e) => {
      if (isMouseDownOnOverlay && e.target === overlay) close(false);
    });

    document.addEventListener('keydown', onKeyDown);
    document.body.appendChild(overlay);

    const btnToFocus = danger ? overlay.querySelector('[data-cancel]') : overlay.querySelector('[data-confirm]');
    setTimeout(() => btnToFocus?.focus(), 50);
  });
}

/**
 * 모던 알림창 (alert 대체)
 * @param {string|{title?: string, message: string, confirmText?: string}} opt
 * @returns {Promise<void>}
 */
export function alertModal(opt) {
  const options = typeof opt === 'string' ? { message: opt } : opt;
  const { title = '알림', message, confirmText = '확인' } = options;

  return new Promise((resolve) => {
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = html`
      <div class="modal-card" role="dialog" aria-modal="true">
        <div class="modal-head">
          <div class="modal-title">${title}</div>
          <button type="button" class="modal-close" data-confirm aria-label="닫기">✕</button>
        </div>
        <div class="modal-body">
          <p class="modal-text">${message}</p>
        </div>
        <div class="modal-foot">
          <button type="button" class="btn primary" data-confirm>${confirmText}</button>
        </div>
      </div>
    `.s;

    const close = () => {
      document.body.style.overflow = prevOverflow;
      document.removeEventListener('keydown', onKeyDown);
      overlay.classList.add('closing');
      overlay.addEventListener('animationend', () => overlay.remove(), { once: true });
      resolve();
    };

    const onKeyDown = (e) => {
      if (e.key === 'Escape' || e.key === 'Enter') close();
    };

    overlay.querySelectorAll('[data-confirm]').forEach((b) => b.addEventListener('click', close));

    let isMouseDownOnOverlay = false;
    overlay.addEventListener('mousedown', (e) => {
      isMouseDownOnOverlay = e.target === overlay;
    });
    overlay.addEventListener('click', (e) => {
      if (isMouseDownOnOverlay && e.target === overlay) close();
    });

    document.addEventListener('keydown', onKeyDown);
    document.body.appendChild(overlay);
    setTimeout(() => overlay.querySelector('[data-confirm]')?.focus(), 50);
  });
}

/**
 * 모던 입력창 (prompt 대체)
 * @param {string|{title?: string, message: string, defaultValue?: string, placeholder?: string, confirmText?: string, cancelText?: string}} opt
 * @returns {Promise<string|null>}
 */
export function promptModal(opt) {
  const options = typeof opt === 'string' ? { message: opt } : opt;
  const {
    title = '입력',
    message,
    defaultValue = '',
    placeholder = '',
    confirmText = '확인',
    cancelText = '취소',
  } = options;

  return new Promise((resolve) => {
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = html`
      <div class="modal-card" role="dialog" aria-modal="true">
        <div class="modal-head">
          <div class="modal-title">${title}</div>
          <button type="button" class="modal-close" data-cancel aria-label="닫기">✕</button>
        </div>
        <div class="modal-body">
          <p class="modal-text">${message}</p>
          <div style="margin-top: 14px;">
            <input type="text" class="input" data-input value="${defaultValue}" placeholder="${placeholder}" style="width: 100%; box-sizing: border-box;">
          </div>
        </div>
        <div class="modal-foot">
          <button type="button" class="btn" data-cancel>${cancelText}</button>
          <button type="button" class="btn primary" data-confirm>${confirmText}</button>
        </div>
      </div>
    `.s;

    const input = overlay.querySelector('[data-input]');

    const close = (result) => {
      document.body.style.overflow = prevOverflow;
      document.removeEventListener('keydown', onKeyDown);
      overlay.classList.add('closing');
      overlay.addEventListener('animationend', () => overlay.remove(), { once: true });
      resolve(result);
    };

    const onKeyDown = (e) => {
      if (e.key === 'Escape') close(null);
      else if (e.key === 'Enter') close(input.value);
    };

    overlay.querySelectorAll('[data-cancel]').forEach((b) => b.addEventListener('click', () => close(null)));
    overlay.querySelector('[data-confirm]').addEventListener('click', () => close(input.value));

    let isMouseDownOnOverlay = false;
    overlay.addEventListener('mousedown', (e) => {
      isMouseDownOnOverlay = e.target === overlay;
    });
    overlay.addEventListener('click', (e) => {
      if (isMouseDownOnOverlay && e.target === overlay) close(null);
    });

    document.addEventListener('keydown', onKeyDown);
    document.body.appendChild(overlay);
    setTimeout(() => {
      input.focus();
      input.select();
    }, 50);
  });
}

