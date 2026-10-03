// 사용자 관리 (관리자 전용): 계정 추가, 역할·활성 변경, 비밀번호 초기화, 잠금 해제.
import * as api from '../api.js';
import { currentUser } from '../auth.js';
import { closeDrawer, openDrawer } from '../drawer.js';
import { errorBox, fmtRelative, fmtTime, html } from '../util.js';

function statusOf(u) {
  if (!u.is_active) return html`<span class="status offline"><span class="dot"></span>비활성</span>`;
  if (u.locked) return html`<span class="status stale"><span class="dot"></span>잠김</span>`;
  if (u.must_change_password) return html`<span class="status stale"><span class="dot"></span>임시 비밀번호</span>`;
  if (u.password_expired) return html`<span class="status stale"><span class="dot"></span>비밀번호 만료</span>`;
  return html`<span class="status online"><span class="dot"></span>정상</span>`;
}

function showTempPassword(body, username, password, title) {
  body.innerHTML = html`
    <div class="hint-box">${title}</div>
    <p>아이디 <b>${username}</b> 의 임시 비밀번호입니다. 사용자에게 안전한 방법으로 전달하세요.</p>
    <div class="temp-password">${password}</div>
    <div class="toolbar"><button class="btn" data-copy>복사</button><button class="btn primary" data-done>확인</button></div>
    <p class="muted" style="font-size:12.5px">이 창을 닫으면 다시 볼 수 없습니다 (서버에는 해시만 저장). 사용자는 첫 로그인 때 비밀번호를 바꿔야 합니다.</p>`;
  body.querySelector('[data-copy]').addEventListener('click', async (e) => {
    try { await navigator.clipboard.writeText(password); e.target.textContent = '복사됨'; } catch { e.target.textContent = '복사 실패'; }
  });
  body.querySelector('[data-done]').addEventListener('click', closeDrawer);
}

export async function mount(root) {
  let data = { items: [], roles: {} };

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">사용자</h1>
        <p class="page-sub">로그인 계정과 권한을 관리합니다. 관리자: 모든 작업 · 조회자: 보기만 가능.</p></div>
      <div class="toolbar"><button class="btn primary" data-add>사용자 추가</button></div>
    </div>
    <section class="card" style="margin-bottom:14px"><div class="card-body flush" data-table><div class="skeleton"></div></div></section>
    <section class="card"><div class="card-body">
      <div class="section-title" style="margin-top:0">적용 중인 보안 정책</div>
      <ul class="ref-list" data-policy></ul>
    </div></section>`;

  async function load() {
    try {
      data = await api.get('/api/users');
    } catch (err) {
      root.querySelector('[data-table]').innerHTML = errorBox(err);
      return;
    }
    const me = currentUser();
    root.querySelector('[data-table]').innerHTML = html`<div class="table-wrap"><table class="table">
      <thead><tr><th>아이디</th><th>이름</th><th>역할</th><th>상태</th><th>마지막 로그인</th><th>비밀번호 변경</th>
        <th class="r">접속 중</th><th></th></tr></thead>
      <tbody>${data.items.map((u) => html`<tr>
        <td class="nowrap"><b>${u.username}</b>${u.id === me.id ? html` <span class="type-tag">나</span>` : ''}</td>
        <td class="nowrap">${u.display_name || '–'}</td>
        <td class="nowrap">${u.role_label}</td>
        <td class="nowrap">${statusOf(u)}${u.failed_count ? html` <span class="muted">(실패 ${u.failed_count}회)</span>` : ''}</td>
        <td class="nowrap" title="${u.last_login_at ? fmtTime(u.last_login_at) : ''}">${u.last_login_at ? html`${fmtRelative(u.last_login_at)} <span class="muted num">${u.last_login_ip || ''}</span>` : html`<span class="muted">없음</span>`}</td>
        <td class="nowrap muted">${fmtTime(u.password_changed_at, { seconds: false })}</td>
        <td class="r num">${u.sessions}</td>
        <td class="nowrap r">
          ${u.locked ? html`<button class="btn sm" data-unlock="${u.id}">잠금 해제</button>` : ''}
          <button class="btn sm" data-reset="${u.id}" data-name="${u.username}">비밀번호 초기화</button>
          <button class="btn sm" data-edit="${u.id}">수정</button>
        </td>
      </tr>`)}</tbody></table></div>`;

    root.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () =>
      openEditor(data.items.find((u) => u.id === Number(b.dataset.edit)))));
    root.querySelectorAll('[data-unlock]').forEach((b) => b.addEventListener('click', async () => {
      try { await api.send('POST', `/api/users/${b.dataset.unlock}/unlock`); load(); } catch (err) { alert(err.message); }
    }));
    root.querySelectorAll('[data-reset]').forEach((b) => b.addEventListener('click', async () => {
      if (!confirm(`${b.dataset.name} 의 비밀번호를 초기화할까요?\n지금 접속 중인 세션은 모두 끊기고, 임시 비밀번호가 발급됩니다.`)) return;
      try {
        const res = await api.send('POST', `/api/users/${b.dataset.reset}/reset-password`);
        showTempPassword(openDrawer({ title: '비밀번호 초기화' }), res.username, res.temp_password, '비밀번호를 초기화했습니다.');
        load();
      } catch (err) { alert(err.message); }
    }));
  }

  async function renderPolicy() {
    const me = currentUser();
    root.querySelector('[data-policy]').innerHTML = html`
      <li>비밀번호: 영문 대·소문자, 숫자, 특수문자 중 3종 이상이면 8자 이상, 2종이면 10자 이상 · 아이디 포함 금지</li>
      <li>비밀번호 변경 주기: ${me.password_max_age_days ? `${me.password_max_age_days}일` : '사용 안 함'} · 임시 비밀번호는 첫 로그인 때 변경</li>
      <li>로그인 연속 실패 시 계정 잠금 (기본 5회 / 10분) · ${me.session_idle_min}분 동안 조작이 없으면 자동 로그아웃</li>
      <li>모든 로그인·계정 변경·로그 조회는 <a href="#/audit">감사 로그</a>에 남습니다</li>
      <li class="muted">설정 값: 서버 <code>.env</code> 의 WLM_LOGIN_MAX_FAILURES, WLM_LOGIN_LOCKOUT_MIN, WLM_SESSION_IDLE_MIN, WLM_PASSWORD_MAX_AGE_DAYS</li>`;
  }

  function openEditor(user) {
    const isNew = !user;
    const me = currentUser();
    const body = openDrawer({ title: isNew ? '사용자 추가' : `사용자 수정 — ${user.username}` });
    body.innerHTML = html`
      <form class="auth-form" data-form>
        ${isNew ? html`<label>아이디<input class="input" name="username" required maxlength="64" pattern="[A-Za-z0-9._\\-]+" placeholder="영문/숫자/._-"></label>` : ''}
        <label>이름<input class="input" name="display_name" maxlength="100" value="${user?.display_name ?? ''}"></label>
        <label>역할<select class="select" name="role" ${!isNew && user.id === me.id ? 'disabled' : ''}>
          ${Object.entries(data.roles).map(([v, l]) => html`<option value="${v}" ${(user?.role ?? 'viewer') === v ? 'selected' : ''}>${l}</option>`)}
        </select></label>
        ${isNew ? '' : html`<label style="flex-direction:row;align-items:center;gap:8px">
          <input type="checkbox" name="is_active" ${user.is_active ? 'checked' : ''} ${user.id === me.id ? 'disabled' : ''}> 활성 (끄면 로그인 불가, 접속 중인 세션 종료)</label>`}
        <div data-error></div>
        <button class="btn primary auth-submit" type="submit">${isNew ? '추가하고 임시 비밀번호 받기' : '저장'}</button>
      </form>`;
    const form = body.querySelector('[data-form]');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        if (isNew) {
          const res = await api.send('POST', '/api/users', {
            username: form.username.value, display_name: form.display_name.value, role: form.role.value,
          });
          showTempPassword(body, res.user.username, res.temp_password, '사용자를 추가했습니다.');
        } else {
          const changes = { display_name: form.display_name.value };
          if (!form.role.disabled) changes.role = form.role.value;
          if (!form.is_active.disabled) changes.is_active = form.is_active.checked;
          await api.send('PATCH', `/api/users/${user.id}`, changes);
          closeDrawer();
        }
        load();
      } catch (err) {
        form.querySelector('[data-error]').innerHTML = errorBox(err);
      }
    });
  }

  root.querySelector('[data-add]').addEventListener('click', () => openEditor(null));
  renderPolicy();
  await load();
}
