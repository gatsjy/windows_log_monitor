// 앱 진입점: 로그인 확인 → 해시 라우터(#/화면/하위?파라미터), 사이드바 상태·사용자 표시, 테마 전환.
// 새 화면 추가 = views/ 에 mount(root, params, sub) 를 export 하는 파일 + 아래 VIEWS 등록 + index.html 메뉴.
// 관리자 전용 화면은 ADMIN_VIEWS 에도 넣고, 메뉴 링크에 data-admin 을 붙인다 (서버도 따로 막는다).
import * as api from './api.js';
import * as auth from './auth.js';
import { closeDrawer } from './drawer.js';
import { categoryLabel } from './levels.js';
import { enhance } from './responsive.js';
import { fmtNum, html, store } from './util.js';
import * as agents from './views/agents.js';
import * as alerts from './views/alerts.js';
import * as audit from './views/audit.js';
import * as dashboard from './views/dashboard.js';
import * as events from './views/events.js';
import * as fields from './views/fields.js';
import * as live from './views/live.js';
import * as settingsView from './views/settings.js';
import * as users from './views/users.js';

const VIEWS = { dashboard, live, events, alerts, agents, fields, users, audit, settings: settingsView };
// 화면별 필요한 권한 ('admin' = 관리자만). 서버도 같은 권한으로 API 를 막는다
const VIEW_PERMS = { users: 'admin', audit: 'audit.view', settings: 'settings.manage' };
const allowedView = (name) => !VIEW_PERMS[name] || (VIEW_PERMS[name] === 'admin' ? auth.isAdmin() : auth.can(VIEW_PERMS[name]));
const root = document.getElementById('view');
let unmount = null;
let seq = 0;
let running = false;
let statusTimer = null;

function parseHash() {
  const [path, query = ''] = location.hash.replace(/^#\/?/, '').split('?');
  const [name, ...rest] = path.split('/');
  const allowed = VIEWS[name] && allowedView(name);
  return {
    name: allowed ? name : 'dashboard',
    sub: rest.join('/'),
    params: Object.fromEntries(new URLSearchParams(query)),
  };
}

function teardownView() {
  seq++;
  closeDrawer();
  try { unmount?.(); } catch { /* 무시 */ }
  unmount = null;
}

async function route() {
  if (!running) return;
  teardownView();
  const my = seq;
  const { name, sub, params } = parseHash();
  document.querySelectorAll('[data-nav]').forEach((a) => a.classList.toggle('active', a.dataset.nav === name));
  const current = document.querySelector(`[data-nav="${name}"] span`);
  document.getElementById('topbar-page').textContent = current ? current.textContent : '';
  setNavOpen(false);
  root.innerHTML = '';
  window.scrollTo(0, 0);
  try {
    const cleanup = await VIEWS[name].mount(root, params, sub);
    if (my !== seq) cleanup?.(); else unmount = cleanup || null;
  } catch (err) {
    if (my === seq) root.innerHTML = html`<div class="error-box">화면을 불러오지 못했습니다: ${err.message}</div>`;
  }
}

// ------------------------------------------------------------ 상태 표시
async function refreshStatus() {
  const el = document.getElementById('ingest-status');
  try {
    const s = await api.get('/api/stats/summary');
    const flowing = s.ingest_per_min > 0;
    el.innerHTML = html`
      <div class="row"><span class="pulse ${flowing ? '' : 'off'}"></span>${flowing ? '수집 중' : '대기 중'}
        <span class="muted num">${fmtNum(Math.round(s.ingest_per_min))}건/분</span></div>
      <div class="row muted">PC ${s.agents.online}/${s.agents.total} 온라인</div>`;
    const badge = document.getElementById('alert-badge');
    badge.hidden = !s.alerts_24h;
    badge.textContent = s.alerts_24h > 99 ? '99+' : String(s.alerts_24h);
  } catch (err) {
    if (err.status !== 401 && err.status !== 403) {
      el.innerHTML = html`<div class="row"><span class="pulse bad"></span>서버 연결 끊김</div>`;
    }
  }
}

function renderUser(me) {
  document.getElementById('user-box').innerHTML = html`
    <div class="user-name" title="마지막 로그인 ${me.last_login_ip || ''}">
      <span class="avatar">${(me.display_name || me.username).slice(0, 1).toUpperCase()}</span>
      <span><b>${me.display_name || me.username}</b><small>${me.username} · ${me.role_label}${me.groups?.length ? ` · ${me.groups.join(', ')}` : ''}</small></span>
    </div>
    ${me.scope ? html`<div class="scope-note" title="사용자 그룹으로 정해진 조회 범위">볼 수 있는 범위: ${me.scope.map((s) => [
      s.categories.map(categoryLabel).join('·'), s.hosts.join('·')].filter(Boolean).join(' / ')).join(' + ')}</div>` : ''}
    <div class="user-actions">
      <button class="btn ghost sm" type="button" data-pw>비밀번호 변경</button>
      <button class="btn ghost sm" type="button" data-logout>로그아웃</button>
    </div>`;
  document.querySelector('#user-box [data-pw]').addEventListener('click', () => auth.showPasswordChange());
  document.querySelector('#user-box [data-logout]').addEventListener('click', () => auth.logout());
  document.querySelectorAll('[data-admin]').forEach((el) => { el.hidden = !auth.isAdmin(); });
  document.querySelectorAll('[data-perm]').forEach((el) => { el.hidden = !auth.can(el.dataset.perm); });
  const section = document.querySelector('[data-nav-section]');
  section.hidden = ![...document.querySelectorAll('.nav [data-admin], .nav [data-perm]')].some((el) => !el.hidden);
}

// ------------------------------------------------- 좁은 화면 메뉴 (왼쪽 패널)
const navToggle = document.getElementById('nav-toggle');
function setNavOpen(open) {
  document.body.classList.toggle('nav-open', open);
  navToggle.setAttribute('aria-expanded', String(open));
  if (open) document.querySelector('.sidebar .nav a.active, .sidebar .nav a')?.focus({ preventScroll: true });
}
navToggle.addEventListener('click', () => setNavOpen(!document.body.classList.contains('nav-open')));
document.querySelectorAll('[data-nav-close]').forEach((el) => el.addEventListener('click', () => setNavOpen(false)));
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && document.body.classList.contains('nav-open')) { setNavOpen(false); navToggle.focus(); }
});
// 넓은 화면으로 돌아가면 열린 상태를 정리
matchMedia('(min-width: 1000px)').addEventListener('change', (e) => { if (e.matches) setNavOpen(false); });

// ----------------------------------------------------------------- 테마
function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
  const dark = theme ? theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  document.getElementById('theme-toggle').textContent = dark ? '라이트 모드' : '다크 모드';
}

document.getElementById('theme-toggle').addEventListener('click', () => {
  const current = document.documentElement.dataset.theme
    || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark';
  store.set('wlm.theme', next);
  applyTheme(next);
});

applyTheme(store.get('wlm.theme'));
enhance(root);
enhance(document.getElementById('drawer-root'));
window.addEventListener('hashchange', route);

auth.init({
  onReady(me) {
    running = true;
    renderUser(me);
    route();
    refreshStatus();
    clearInterval(statusTimer);
    statusTimer = setInterval(() => { if (!document.hidden) refreshStatus(); }, 15000);
  },
  onSignedOut() {
    running = false;
    clearInterval(statusTimer);
    teardownView(); // 실시간 연결·타이머 정리
    root.innerHTML = '';
  },
});
