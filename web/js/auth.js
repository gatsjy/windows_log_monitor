// 로그인 화면, 비밀번호 변경, 현재 사용자 상태.
// main.js 가 init({ onReady, onSignedOut }) 으로 시작한다.
import * as api from './api.js';
import { errorBox, html } from './util.js';

let me = null;
let hooks = { onReady: () => {}, onSignedOut: () => {} };
let appRunning = false;
let screen = null; // 'login' | 'password' | 'mfa' | 'mfa_setup' | null — 같은 화면을 여러 번 다시 그리지 않도록

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
  if (me.mfa_pending) showMfaCode();
  else if (me.must_change_password || me.password_expired) showPasswordChange({ forced: true });
  else if (me.mfa_setup_required) showMfaSetup({ forced: true });
  else startApp();
}

/** 비밀번호 다음 — 인증 앱의 6자리 코드 또는 복구 코드 (B-74) */
export function showMfaCode(message = '') {
  if (screen === 'mfa') return;
  screen = 'mfa';
  stopApp();
  shell(html`
    <h1 class="auth-title">인증 코드</h1>
    ${me ? html`<p class="muted" style="margin:-6px 0 12px">${me.display_name || me.username} (${me.username})</p>` : ''}
    ${message ? html`<div class="hint-box" style="margin-bottom:12px">${message}</div>` : ''}
    <form class="auth-form">
      <label>인증 앱의 6자리 코드<input class="input mono" name="code" inputmode="numeric" autocomplete="one-time-code"
        maxlength="20" required autofocus placeholder="123456"></label>
      <p class="auth-notice" style="margin:0">휴대폰을 잃었으면 등록할 때 받은 복구 코드(abcd-efgh-jk)를 같은 칸에 넣으세요(한 번씩만).
        들어간 뒤 메뉴 '2단계 인증 > 휴대폰 바꾸기'에서 남은 복구 코드로 다시 등록합니다. 복구 코드도 없으면 관리자에게 '2단계 초기화'를 요청하세요.</p>
      <div data-error></div>
      <button class="btn primary auth-submit" type="submit">확인</button>
      <button class="btn ghost" type="button" data-cancel>로그아웃</button>
    </form>`);
  const form = root().querySelector('form');
  form.querySelector('[data-cancel]').addEventListener('click', () => logout());
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const button = form.querySelector('button[type=submit]');
    button.disabled = true;
    try {
      me = await api.send('POST', '/api/auth/mfa/verify', { code: form.code.value });
      screen = null;
      proceed();
    } catch (err) {
      if (err.status === 401 || err.status === 423) { screen = null; showLogin(err.message); return; }
      form.querySelector('[data-error]').innerHTML = errorBox(err);
      form.code.value = '';
      form.code.focus();
    } finally {
      button.disabled = false;
    }
  });
}

/** 2단계 인증 등록 — forced = 필수라 등록해야 계속할 수 있음 (닫기 없음, 로그아웃만) */
export async function showMfaSetup({ forced = false } = {}) {
  if (screen === 'mfa_setup') return;
  screen = 'mfa_setup';
  if (forced) stopApp();
  let setup;
  try {
    setup = await api.send('POST', '/api/auth/mfa/setup');
  } catch (err) {
    shell(html`<h1 class="auth-title">2단계 인증 등록</h1>${errorBox(err)}
      <button class="btn ghost" type="button" data-cancel>${forced ? '로그아웃' : '닫기'}</button>`);
    root().querySelector('[data-cancel]').addEventListener('click', () => (forced ? logout() : hide()));
    return;
  }
  const grouped = setup.secret.match(/.{1,4}/g).join(' ');
  shell(html`
    <h1 class="auth-title">2단계 인증 등록</h1>
    ${forced ? html`<div class="hint-box" style="margin-bottom:12px">관리 권한이 있는 계정은 2단계 인증을 써야 계속할 수 있습니다.</div>` : ''}
    <ol class="auth-steps">
      <li>휴대폰에 인증 앱(Google Authenticator·Microsoft Authenticator 등)을 엽니다.</li>
      <li>'키 직접 입력'(설정 키 입력)을 고르고 계정 이름에 <b>${me?.username ?? ''}</b>, 키에 아래 값을 넣습니다 (시간 기준).
        <div class="mfa-secret mono" data-secret>${grouped}</div>
        <details class="muted" style="font-size:12px"><summary>등록 주소 (otpauth)</summary><code style="word-break:break-all">${setup.uri}</code></details></li>
      <li>앱에 나온 6자리 코드를 넣습니다.</li>
    </ol>
    <form class="auth-form">
      <label>6자리 코드<input class="input mono" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="10" required autofocus></label>
      <div data-error></div>
      <button class="btn primary auth-submit" type="submit">등록</button>
      <button class="btn ghost" type="button" data-cancel>${forced ? '로그아웃' : '취소'}</button>
    </form>`);
  const form = root().querySelector('form');
  form.querySelector('[data-cancel]').addEventListener('click', () => (forced ? logout() : hide()));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const res = await api.send('POST', '/api/auth/mfa/enroll', { code: form.code.value });
      me = await api.get('/api/auth/me');
      showRecoveryCodes(res.recovery_codes, forced);
    } catch (err) {
      form.querySelector('[data-error]').innerHTML = errorBox(err);
    }
  });
}

/** 복구 코드 — 이 화면에서만 보인다 (서버는 원문을 저장하지 않는다) */
function showRecoveryCodes(codes, forced) {
  screen = 'mfa_codes';
  shell(html`
    <h1 class="auth-title">복구 코드</h1>
    <div class="hint-box" style="margin-bottom:12px">휴대폰을 잃었을 때 인증 코드 대신 한 번씩 쓸 수 있습니다. <b>지금만 보입니다</b> —
      인쇄하거나 안전한 곳(금고·비밀번호 관리자)에 적어 두세요.</div>
    <div class="mfa-codes mono">${codes.map((c) => html`<span>${c}</span>`)}</div>
    <div class="auth-form">
      <button class="btn" type="button" data-copy>복사</button>
      <button class="btn primary auth-submit" type="button" data-done>적어 두었습니다</button>
    </div>`);
  root().querySelector('[data-copy]').addEventListener('click', async (e) => {
    try { await navigator.clipboard.writeText(codes.join('\n')); e.target.textContent = '복사했습니다'; } catch { /* 클립보드 권한 없음 */ }
  });
  root().querySelector('[data-done]').addEventListener('click', () => {
    screen = null;
    if (forced) proceed(); else hide();
  });
}

/** 내 2단계 인증 — 상태, 복구 코드 새로 받기, (필수가 아니면) 끄기 */
export async function showMfaPanel() {
  const status = await api.get('/api/auth/mfa').catch(() => null);
  if (!status) return;
  if (!status.enabled) { showMfaSetup(); return; }
  screen = 'mfa_panel';
  shell(html`
    <h1 class="auth-title">2단계 인증</h1>
    <p class="muted" style="margin:-6px 0 12px">사용 중 · 남은 복구 코드 ${status.recovery_left}개${status.required ? ' · 이 계정은 필수' : ''}</p>
    <form class="auth-form">
      <label>지금 인증 앱의 6자리 코드 (휴대폰 바꾸기는 복구 코드도 됨)<input class="input mono" name="code" autocomplete="one-time-code" maxlength="20" required autofocus></label>
      <div data-error></div>
      <button class="btn" type="submit" data-act="recovery">복구 코드 새로 받기</button>
      <button class="btn" type="submit" data-act="reenroll" title="지금 코드나 남은 복구 코드 하나로 지우고 새 휴대폰에 등록합니다">휴대폰 바꾸기 (다시 등록)</button>
      ${status.required ? '' : html`<button class="btn ghost tag-bad" type="submit" data-act="disable">2단계 인증 끄기</button>`}
      <button class="btn ghost" type="button" data-cancel>닫기</button>
    </form>`);
  const form = root().querySelector('form');
  form.querySelector('[data-cancel]').addEventListener('click', () => hide());
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const act = e.submitter?.dataset.act || 'recovery';
    try {
      if (act === 'disable') {
        await api.send('POST', '/api/auth/mfa/disable', { code: form.code.value });
        me = await api.get('/api/auth/me');
        hide();
      } else if (act === 'reenroll') {
        await api.send('POST', '/api/auth/mfa/reenroll', { code: form.code.value });
        me = await api.get('/api/auth/me');
        screen = null;
        showMfaSetup({ forced: Boolean(me.mfa?.required) });
      } else {
        const res = await api.send('POST', '/api/auth/mfa/recovery', { code: form.code.value });
        showRecoveryCodes(res.recovery_codes, false);
      }
    } catch (err) {
      form.querySelector('[data-error]').innerHTML = errorBox(err);
    }
  });
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
      proceed();   // 2단계 인증을 쓰면 me.mfa_pending — 인증 코드 화면으로
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
      if (forced) { screen = null; proceed(); } else hide();
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
    else if (e.detail.reason === 'mfa') showMfaCode();
    else if (e.detail.reason === 'mfa_setup') showMfaSetup({ forced: true });
    else showLogin(appRunning ? '세션이 만료되었습니다. 다시 로그인하세요.' : '');
  });
}
