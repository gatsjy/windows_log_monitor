// 로그인 화면, 비밀번호 변경, 현재 사용자 상태.
// main.js 가 init({ onReady, onSignedOut }) 으로 시작한다.
import * as api from './api.js';
import { errorBox, html } from './util.js';

let me = null;
let hooks = { onReady: () => {}, onSignedOut: () => {} };
let appRunning = false;
let screen = null; // 'login' | 'password' | null — 같은 화면을 여러 번 다시 그리지 않도록

export const currentUser = () => me;
export const isAdmin = () => me?.role === 'admin';
/** 기능 권한 (서버 auth/groups.py PERMISSIONS). 관리자는 전부 */
export const can = (permission) => isAdmin() || (me?.permissions || []).includes(permission);

const POLICY = '영문 대·소문자, 숫자, 특수문자 중 3종류 이상이면 8자 이상, 2종류면 10자 이상. 아이디 포함·같은 문자 4번 연속 불가.';

function root() {
  return document.getElementById('auth-root');
}

function hide() {
  screen = null;
  root().innerHTML = '';
  document.body.classList.remove('auth-open');
}

function shell(content) {
  document.body.classList.add('auth-open');
  root().innerHTML = html`<div class="auth-screen"><div class="auth-card">
    <div class="brand auth-brand">
      <img class="brand-mark" src="/favicon.svg" width="40" height="40" alt="">
      <span>Log Monitor<small>통합 로그 모니터링</small></span>
    </div>${content}</div></div>`;
}

function stopApp() {
  if (appRunning) {
    appRunning = false;
    hooks.onSignedOut();
  }
}

function startApp() {
  hide();
  if (!appRunning) {
    appRunning = true;
    hooks.onReady(me);
  }
}

function proceed() {
  if (me.must_change_password || me.password_expired) showPasswordChange({ forced: true });
  else startApp();
}

export async function showLogin(message = '') {
  if (screen === 'login') return;
  screen = 'login';
  stopApp();
  me = null;
  const info = await api.get('/api/auth/info').catch(() => ({ notice: '' }));
  shell(html`
    <h1 class="auth-title">로그인</h1>
    ${message ? html`<div class="hint-box" style="margin-bottom:12px">${message}</div>` : ''}
    <form class="auth-form" autocomplete="on">
      <label>아이디<input class="input" name="username" autocomplete="username" required autofocus></label>
      <label>비밀번호<input class="input" name="password" type="password" autocomplete="current-password" required></label>
      <div data-error></div>
      <button class="btn primary auth-submit" type="submit">로그인</button>
    </form>
    ${info.notice ? html`<p class="auth-notice">${info.notice}</p>` : ''}
    ${info.version ? html`<p class="auth-notice muted">v${info.version}</p>` : ''}`);
  const form = root().querySelector('form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const button = form.querySelector('button');
    button.disabled = true;
    try {
      me = await api.send('POST', '/api/auth/login', {
        username: form.username.value, password: form.password.value,
      });
      screen = null;
      proceed();
    } catch (err) {
      form.querySelector('[data-error]').innerHTML = errorBox(err);
      form.password.value = '';
      form.password.focus();
    } finally {
      button.disabled = false;
    }
  });
}

/** forced = 첫 로그인/만료로 반드시 바꿔야 하는 경우 (닫기 없음, 로그아웃만 가능) */
export function showPasswordChange({ forced = false } = {}) {
  if (screen === 'password') return;
  screen = 'password';
  if (forced) stopApp();
  const reason = me?.must_change_password ? '임시 비밀번호로 로그인했습니다. 새 비밀번호로 바꿔야 계속할 수 있습니다.'
    : me?.password_expired ? `비밀번호를 바꾼 지 ${me.password_max_age_days}일이 지났습니다. 새 비밀번호로 바꿔 주세요.` : '';
  shell(html`
    <h1 class="auth-title">비밀번호 변경</h1>
    ${me ? html`<p class="muted" style="margin:-6px 0 12px">${me.display_name || me.username} (${me.username})</p>` : ''}
    ${reason ? html`<div class="hint-box" style="margin-bottom:12px">${reason}</div>` : ''}
    <form class="auth-form">
      <label>현재 비밀번호<input class="input" name="current" type="password" autocomplete="current-password" required autofocus></label>
      <label>새 비밀번호<input class="input" name="next" type="password" autocomplete="new-password" required></label>
      <label>새 비밀번호 확인<input class="input" name="confirm" type="password" autocomplete="new-password" required></label>
      <p class="auth-notice" style="margin:0">${POLICY}</p>
      <div data-error></div>
      <button class="btn primary auth-submit" type="submit">변경</button>
      <button class="btn ghost" type="button" data-cancel>${forced ? '로그아웃' : '취소'}</button>
    </form>`);
  const form = root().querySelector('form');
  form.querySelector('[data-cancel]').addEventListener('click', () => (forced ? logout() : hide()));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const errorEl = form.querySelector('[data-error]');
    if (form.next.value !== form.confirm.value) {
      errorEl.innerHTML = errorBox(new Error('새 비밀번호와 확인 값이 다릅니다'));
      return;
    }
    try {
      await api.send('POST', '/api/auth/password', { current_password: form.current.value, new_password: form.next.value });
      me = await api.get('/api/auth/me');
      if (forced) startApp(); else hide();
    } catch (err) {
      errorEl.innerHTML = errorBox(err);
    }
  });
}

export async function logout() {
  try { await api.send('POST', '/api/auth/logout'); } catch { /* 이미 만료된 세션 */ }
  screen = null;
  await showLogin('로그아웃되었습니다.');
}

export async function init(callbacks) {
  hooks = callbacks;
  try {
    me = await api.get('/api/auth/me');
    proceed();
  } catch {
    await showLogin();
  }
  // 앱을 쓰는 중에 세션이 만료되거나(401) 비밀번호 변경이 필요해지면(403) 해당 화면으로
  window.addEventListener('wlm:auth', (e) => {
    if (e.detail.reason === 'password') showPasswordChange({ forced: true });
    else showLogin(appRunning ? '세션이 만료되었습니다. 다시 로그인하세요.' : '');
  });
}
