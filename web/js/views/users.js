// 사용자 관리 (관리자 전용): 계정 추가, 역할·활성 변경, 비밀번호 초기화, 잠금 해제.
// 탭 '사용자 그룹'(#/users/groups): DB팀·보안팀처럼 묶어 기능 권한과 볼 수 있는 범위(분류·PC)를 준다.
// 탭 '권한 검토'(#/users/reviews, B-72 2단계): 분기마다 계정별 유지·회수·조정 → 점검자 서명 → 다른 관리자 승인 (ISMS 2.5.6).
import * as api from '../api.js';
import { currentUser } from '../auth.js';
import { closeDrawer, openDrawer } from '../drawer.js';
import { exportCsv } from '../exportcsv.js';
import { categoryLabel } from '../levels.js';
import { confirmModal, errorBox, fmtNum, fmtRelative, fmtTime, html, promptModal, toast } from '../util.js';

const TABS = (on) => html`<div class="tabs" role="tablist">
  <a role="tab" href="#/users" class="${on === '' ? 'on' : ''}" aria-selected="${on === ''}">사용자</a>
  <a role="tab" href="#/users/groups" class="${on === 'groups' ? 'on' : ''}" aria-selected="${on === 'groups'}">사용자 그룹</a>
  <a role="tab" href="#/users/reviews" class="${on === 'reviews' ? 'on' : ''}" aria-selected="${on === 'reviews'}">권한 검토</a></div>`;

function statusOf(u) {
  if (!u.is_active) return html`<span class="status offline" title="${u.disabled_reason === 'dormant' ? '오래 로그인하지 않아 자동으로 꺼짐 — 다시 켜면 그때부터 다시 셉니다' : ''}"><span class="dot"></span>${u.disabled_reason === 'dormant' ? '장기 미사용으로 꺼짐' : '비활성'}</span>`;
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

export async function mount(root, params, sub) {
  if (sub === 'groups') return mountGroups(root);
  if (sub === 'reviews') return mountReviews(root);
  let data = { items: [], roles: {} };

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">사용자</h1>
        <p class="page-sub">로그인 계정과 권한을 관리합니다. 관리자: 모든 작업 · 조회자: 보기 + 속한 그룹의 권한.</p></div>
      <div class="toolbar"><button class="btn primary" data-add>사용자 추가</button></div>
    </div>
    ${TABS('')}
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
      <thead><tr><th>아이디</th><th>이름</th><th>역할</th><th>그룹</th><th>상태</th><th>2단계</th><th>마지막 로그인</th><th>비밀번호 변경</th>
        <th class="r">접속 중</th><th></th></tr></thead>
      <tbody>${data.items.map((u) => html`<tr>
        <td class="nowrap"><b>${u.username}</b>${u.id === me.id ? html` <span class="type-tag">나</span>` : ''}</td>
        <td class="nowrap">${u.display_name || '–'}</td>
        <td class="nowrap">${u.role_label}</td>
        <td>${u.groups.length ? u.groups.map((g) => html`<span class="type-tag" style="margin-right:4px">${g}</span>`) : html`<span class="muted">–</span>`}</td>
        <td class="nowrap">${statusOf(u)}${u.failed_count ? html` <span class="muted">(실패 ${u.failed_count}회)</span>` : ''}</td>
        <td class="nowrap">${u.mfa_enabled ? html`<span class="status online"><span class="dot"></span>사용</span>` : html`<span class="muted">–</span>`}</td>
        <td class="nowrap" title="${u.last_login_at ? fmtTime(u.last_login_at) : ''}">${u.last_login_at ? html`${fmtRelative(u.last_login_at)} <span class="muted num">${u.last_login_ip || ''}</span>` : html`<span class="muted">없음</span>`}</td>
        <td class="nowrap muted">${fmtTime(u.password_changed_at, { seconds: false })}</td>
        <td class="r num">${u.sessions}</td>
        <td class="nowrap r">
          ${u.locked ? html`<button class="btn sm" data-unlock="${u.id}">잠금 해제</button>` : ''}
          ${u.mfa_enabled ? html`<button class="btn sm" data-mfa-reset="${u.id}" data-name="${u.username}">2단계 초기화</button>` : ''}
          <button class="btn sm" data-reset="${u.id}" data-name="${u.username}">비밀번호 초기화</button>
          <button class="btn sm" data-edit="${u.id}">수정</button>
        </td>
      </tr>`)}</tbody></table></div>`;

    root.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () =>
      openEditor(data.items.find((u) => u.id === Number(b.dataset.edit)))));
    root.querySelectorAll('[data-unlock]').forEach((b) => b.addEventListener('click', async () => {
      try {
        await api.send('POST', `/api/users/${b.dataset.unlock}/unlock`);
        toast('계정 잠금을 해제했습니다.', { type: 'success' });
        load();
      } catch (err) {
        toast(err.message, { type: 'error' });
      }
    }));
    root.querySelectorAll('[data-mfa-reset]').forEach((b) => b.addEventListener('click', async () => {
      const ok = await confirmModal({
        title: '2단계 인증 초기화',
        message: `${b.dataset.name} 의 2단계 인증을 초기화할까요?\n인증 앱을 잃은 경우에만 — 접속 중인 세션은 끊기고, 다음 로그인 때 다시 등록합니다.\n다른 관리자에게 '관리 작업 알림'이 갑니다.`,
        danger: true,
        confirmText: '초기화',
      });
      if (!ok) return;
      try {
        await api.send('POST', `/api/users/${b.dataset.mfaReset}/mfa/reset`);
        toast('2단계 인증을 초기화했습니다.', { type: 'success' });
        load();
      } catch (err) {
        toast(err.message, { type: 'error' });
      }
    }));
    root.querySelectorAll('[data-reset]').forEach((b) => b.addEventListener('click', async () => {
      const okReset = await confirmModal({
        title: '비밀번호 초기화',
        message: `${b.dataset.name} 의 비밀번호를 초기화할까요?\n지금 접속 중인 세션은 모두 끊기고, 임시 비밀번호가 발급됩니다.`,
        danger: true,
        confirmText: '초기화',
      });
      if (!okReset) return;
      try {
        const res = await api.send('POST', `/api/users/${b.dataset.reset}/reset-password`);
        showTempPassword(openDrawer({ title: '비밀번호 초기화' }), res.username, res.temp_password, '비밀번호를 초기화했습니다.');
        load();
      } catch (err) {
        toast(err.message, { type: 'error' });
      }
    }));
  }

  async function renderPolicy() {
    const me = currentUser();
    root.querySelector('[data-policy]').innerHTML = html`
      <li>비밀번호: 영문 대·소문자, 숫자, 특수문자 중 3종 이상이면 8자 이상, 2종이면 10자 이상 · 아이디 포함 금지</li>
      <li>비밀번호 변경 주기: ${me.password_max_age_days ? `${me.password_max_age_days}일` : '사용 안 함'} · 임시 비밀번호는 첫 로그인 때 변경</li>
      <li>로그인 연속 실패 시 계정 잠금 (기본 5회 / 10분, 인증 코드 실패도 셈) · ${me.session_idle_min}분 동안 조작이 없으면 자동 로그아웃</li>
      <li>2단계 인증(인증 앱 6자리): 관리자와 관리 권한 그룹은 필수(WLM_MFA_REQUIRED) · 휴대폰 분실은 '2단계 초기화' 또는 서버에서 <code>python -m app.cli reset-mfa</code></li>
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


// ------------------------------------------------------------- 사용자 그룹
function scopeText(g) {
  const cats = g.scope_categories.map(categoryLabel).join(', ');
  const hosts = g.scope_hosts.join(', ');
  if (!cats && !hosts) return html`<span class="muted">전체</span>`;
  return [cats && `분류: ${cats}`, hosts && `PC: ${hosts}`].filter(Boolean).join(' · ');
}

async function mountGroups(root) {
  let data = { items: [], permissions: {}, categories: {} };
  let users = [];

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">사용자</h1>
        <p class="page-sub">팀·부서 단위로 묶어 기능 권한과 볼 수 있는 로그 범위를 줍니다. 예: DB팀 → DB(MSSQL) 로그만, 의료정보과 → MED-* PC 만.</p></div>
      <div class="toolbar"><button class="btn primary" data-add>그룹 추가</button></div>
    </div>
    ${TABS('groups')}
    <div data-list><div class="skeleton"></div></div>
    <section class="card" style="margin-top:16px"><div class="card-body">
      <div class="section-title" style="margin-top:0">규칙</div>
      <ul class="ref-list">
        <li>관리자는 그룹과 상관없이 모든 기능·모든 로그를 봅니다. 사용자 관리는 관리자만 할 수 있습니다.</li>
        <li>조회자는 속한 그룹들의 기능 권한을 <b>합친 만큼</b> 할 수 있습니다.</li>
        <li>볼 수 있는 범위는 그룹들의 <b>합집합</b>입니다. 범위가 비어 있는 그룹에 속하거나 그룹이 없으면 전체를 봅니다.</li>
        <li>범위는 서버에서 검색·대시보드·실시간·수집 PC·알림 이력에 모두 적용됩니다. 변경은 감사 로그에 남습니다.</li>
      </ul></div></section>`;

  async function load() {
    try {
      [data, { items: users }] = await Promise.all([api.get('/api/user-groups'), api.get('/api/users')]);
    } catch (err) {
      root.querySelector('[data-list]').innerHTML = errorBox(err);
      return;
    }
    const name = (id) => users.find((u) => u.id === id)?.display_name || users.find((u) => u.id === id)?.username || `#${id}`;
    const el = root.querySelector('[data-list]');
    if (!data.items.length) {
      el.innerHTML = html`<section class="card"><div class="empty">그룹이 없습니다. '그룹 추가'로 DB팀·보안팀 같은 그룹을 만드세요.</div></section>`;
      return;
    }
    el.innerHTML = html`<div class="group-cards">${data.items.map((g) => html`
      <section class="card group-card" data-id="${g.id}" role="button" tabindex="0">
        <div class="card-head"><h2 class="card-title" style="color:var(--ink);font-size:15px">${g.name}</h2>
          <span class="muted num" style="font-size:12.5px">${g.member_ids.length}명</span></div>
        <div class="card-body">
          ${g.description ? html`<p class="muted" style="margin:0 0 10px;font-size:13px">${g.description}</p>` : ''}
          <div class="kv" style="margin:0">
            <dt>기능 권한</dt><dd style="flex-wrap:wrap;gap:4px">${g.permissions.length ? g.permissions.map((p) => html`<span class="type-tag">${(data.permissions[p] || p).split(' (')[0]}</span>`) : html`<span class="muted">보기만</span>`}</dd>
            <dt>볼 수 있는 범위</dt><dd>${scopeText(g)}</dd>
            <dt>구성원</dt><dd>${g.member_ids.length ? g.member_ids.map(name).join(', ') : html`<span class="muted">없음</span>`}</dd>
          </div>
        </div>
      </section>`)}</div>`;
    el.querySelectorAll('[data-id]').forEach((card) => {
      const open = () => openGroup(data.items.find((g) => g.id === Number(card.dataset.id)));
      card.addEventListener('click', open);
      card.addEventListener('keydown', (e) => { if (e.key === 'Enter') open(); });
    });
  }

  function openGroup(group) {
    const isNew = !group;
    const g = {
      name: group?.name ?? '', description: group?.description ?? '', permissions: new Set(group?.permissions ?? []),
      cats: new Set(group?.scope_categories ?? []), hosts: (group?.scope_hosts ?? []).join(', '), members: new Set(group?.member_ids ?? []),
    };
    const body = openDrawer({ title: isNew ? '사용자 그룹 추가' : `사용자 그룹 — ${group.name}` });
    body.innerHTML = html`
      <section class="form-section">
        <h3>그룹</h3>
        <label class="field"><span>이름 <em>*</em></span><input class="input" data-name value="${g.name}" maxlength="64" placeholder="예: DB팀, 보안팀, 의료정보과"></label>
        <label class="field"><span>설명</span><input class="input" data-desc value="${g.description}" maxlength="200"></label>
      </section>
      <section class="form-section">
        <h3>할 수 있는 일 (기능 권한)</h3>
        <p class="muted" style="margin:0;font-size:13px">아무것도 고르지 않으면 보기만 할 수 있습니다.</p>
        <div class="check-list tall" style="max-height:none">${Object.entries(data.permissions).map(([k, label]) => html`
          <label><input type="checkbox" data-perm="${k}" ${g.permissions.has(k) ? 'checked' : ''}>${label}</label>`)}</div>
      </section>
      <section class="form-section">
        <h3>볼 수 있는 로그 (조회 범위)</h3>
        <p class="muted" style="margin:0;font-size:13px">둘 다 비우면 전체. 둘 다 정하면 '그 분류이면서 그 PC' 인 로그만 보입니다.</p>
        <div class="field"><span>분류</span><div class="chips">${Object.keys(data.categories).map((c) => html`
          <button type="button" class="chip ${g.cats.has(c) ? 'on' : ''}" data-cat="${c}">${categoryLabel(c)}</button>`)}</div></div>
        <label class="field"><span>PC 이름 (쉼표로 구분, * 사용 가능)</span><input class="input" data-hosts value="${g.hosts}" placeholder="MED-*, DB-01"></label>
      </section>
      <section class="form-section">
        <h3>구성원</h3>
        <div class="check-list tall">${users.map((u) => html`
          <label><input type="checkbox" data-member="${u.id}" ${g.members.has(u.id) ? 'checked' : ''}>${u.display_name || u.username}
            <span class="muted" style="font-size:12px">${u.username} · ${u.role_label}${u.is_active ? '' : ' · 비활성'}</span></label>`)}</div>
      </section>
      <div data-msg></div>
      <div class="form-actions">
        ${isNew ? '' : html`<button type="button" class="btn ghost danger" data-delete>그룹 삭제</button>`}
        <span style="flex:1"></span>
        <button type="button" class="btn" data-cancel>취소</button>
        <button type="button" class="btn primary" data-save>${isNew ? '그룹 추가' : '저장'}</button>
      </div>`;
    body.querySelectorAll('[data-cat]').forEach((b) => b.addEventListener('click', () => {
      const c = b.dataset.cat;
      g.cats.has(c) ? g.cats.delete(c) : g.cats.add(c);
      b.classList.toggle('on', g.cats.has(c));
    }));
    body.querySelector('[data-cancel]').addEventListener('click', closeDrawer);
    body.querySelector('[data-save]').addEventListener('click', async () => {
      const payload = {
        name: body.querySelector('[data-name]').value.trim(),
        description: body.querySelector('[data-desc]').value.trim(),
        permissions: [...body.querySelectorAll('[data-perm]:checked')].map((x) => x.dataset.perm),
        scope_categories: [...g.cats],
        scope_hosts: body.querySelector('[data-hosts]').value.split(',').map((x) => x.trim()).filter(Boolean),
        member_ids: [...body.querySelectorAll('[data-member]:checked')].map((x) => Number(x.dataset.member)),
      };
      try {
        await api.send(isNew ? 'POST' : 'PUT', isNew ? '/api/user-groups' : `/api/user-groups/${group.id}`, payload);
        closeDrawer();
        load();
      } catch (err) {
        body.querySelector('[data-msg]').innerHTML = errorBox(err);
      }
    });
    body.querySelector('[data-delete]')?.addEventListener('click', async () => {
      const okDel = await confirmModal({
        title: '사용자 그룹 삭제',
        message: `'${group.name}' 그룹을 삭제할까요? 구성원의 권한·범위가 이 그룹만큼 줄어듭니다.`,
        danger: true,
        confirmText: '삭제',
      });
      if (!okDel) return;
      try {
        await api.send('DELETE', `/api/user-groups/${group.id}`);
        closeDrawer();
        toast('사용자 그룹을 삭제했습니다.', { type: 'success' });
        load();
      } catch (err) {
        body.querySelector('[data-msg]').innerHTML = errorBox(err);
      }
    });
  }

  root.querySelector('[data-add]').addEventListener('click', () => openGroup(null));
  await load();
}


// ------------------------------------------------------------------ 권한 검토 (B-72 2단계, ISMS 2.5.6, ADR-058)
const REVIEW_STATUS = { open: ['stale', '진행 중'], signed: ['stale', '서명 — 승인 대기'], approved: ['online', '승인됨'] };
const DECISIONS = [['keep', '유지'], ['revoke', '회수'], ['change', '조정']];
const DECISION_LABEL = Object.fromEntries(DECISIONS);
const ENTRY_LABEL = { decision: '결정', sign: '서명', approve: '승인', reject: '반려' };

function reviewStatus(status) {
  const [cls, label] = REVIEW_STATUS[status] ?? ['offline', status];
  return html`<span class="status ${cls}"><span class="dot"></span>${label}</span>`;
}

function defaultTitle(now = new Date()) {
  return `${now.getFullYear()}년 ${Math.floor(now.getMonth() / 3) + 1}분기 권한 검토`;
}

async function mountReviews(root) {
  let disposed = false;
  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">사용자</h1>
        <p class="page-sub">분기마다 계정·권한이 아직 필요한지 검토합니다 — 계정마다 유지·회수·조정을 정하고, 점검자가 서명하면 다른 관리자가 승인합니다.</p></div>
      <div class="toolbar"><button class="btn primary" data-start>새 권한 검토 시작</button></div>
    </div>
    ${TABS('reviews')}
    <div data-list><div class="skeleton"></div></div>
    <section class="card" style="margin-top:16px"><div class="card-body">
      <div class="section-title" style="margin-top:0">진행 방법</div>
      <ul class="ref-list">
        <li>시작하면 그때의 모든 계정·역할·그룹·권한·조회 범위·마지막 사용을 그대로 남기고, 그 목록으로 검토합니다.</li>
        <li>켜진 계정마다 <b>유지·회수·조정</b>을 정합니다(회수·조정은 사유 필수). 회수는 결정만 남기므로 사용자 탭에서 계정을 끄세요 — 끄지 않으면 운영 준비도·점검 보고서가 알립니다.</li>
        <li>모두 정하면 점검자가 서명하고, <b>서명한 사람이 아닌 다른 관리자</b>가 승인하거나 사유를 적어 반려합니다(반려하면 다시 고칠 수 있음).</li>
        <li>결정·서명·승인·반려는 고치거나 지울 수 없게 남고(감사로그에도), 결과를 CSV 로 받아 심사 증적으로 씁니다.</li>
      </ul></div></section>`;

  async function load() {
    let data;
    try {
      data = await api.get('/api/access-reviews');
    } catch (err) {
      root.querySelector('[data-list]').innerHTML = errorBox(err);
      return;
    }
    if (disposed) return;
    const due = data.days ? html`<p class="muted rule-foot">검토 주기 ${data.days}일 (WLM_ACCESS_REVIEW_DAYS) — 마지막 승인 뒤 이만큼 지나면 운영 준비도·점검 보고서가 알립니다.</p>` : '';
    root.querySelector('[data-list]').innerHTML = html`<section class="card"><div class="card-body flush">
      ${data.items.length ? html`<div class="table-wrap"><table class="table">
        <thead><tr><th>검토</th><th>상태</th><th class="r">결정</th><th class="r">회수</th><th>시작</th><th>서명</th><th>승인</th></tr></thead>
        <tbody>${data.items.map((r) => html`<tr class="clickable" data-review="${r.id}">
          <td><b>${r.title}</b></td>
          <td class="nowrap">${reviewStatus(r.status)}</td>
          <td class="r num">${fmtNum(r.decided)}/${fmtNum(r.active)}</td>
          <td class="r num">${r.revokes ? fmtNum(r.revokes) : '–'}</td>
          <td class="nowrap muted">${r.started_by} · ${fmtTime(r.started_at, { seconds: false })}</td>
          <td class="nowrap">${r.signed_by || html`<span class="muted">–</span>`}</td>
          <td class="nowrap">${r.approved_by ? html`${r.approved_by} <span class="muted">${fmtTime(r.approved_at, { seconds: false })}</span>` : html`<span class="muted">–</span>`}</td>
        </tr>`)}</tbody></table></div>` : html`<div class="empty">아직 권한 검토가 없습니다 — '새 권한 검토 시작'</div>`}
    </div></section>${due}`;
    root.querySelectorAll('[data-review]').forEach((tr) => tr.addEventListener('click', () => openReview(Number(tr.dataset.review))));
  }

  root.querySelector('[data-start]').addEventListener('click', async () => {
    const title = await promptModal({ title: '새 권한 검토', message: '검토 이름 — 지금의 계정·권한을 그대로 남기고 시작합니다.',
      defaultValue: defaultTitle(), confirmText: '시작' });
    if (title == null) return;
    try {
      const res = await api.send('POST', '/api/access-reviews', { title: title.trim() });
      toast('권한 검토를 시작했습니다.', { type: 'success' });
      await load();
      openReview(res.id);
    } catch (err) {
      toast(err.message, { type: 'error' });
    }
  });

  async function post(id, body) {
    await api.send('POST', `/api/access-reviews/${id}/entries`, body);
    await load();
    await openReview(id, true);
  }

  async function openReview(id, keep = false) {
    let r;
    try {
      r = await api.get(`/api/access-reviews/${id}`);
    } catch (err) {
      toast(err.message, { type: 'error' });
      return;
    }
    if (disposed) return;
    const scroll = keep ? document.querySelector('.drawer-body')?.scrollTop : 0;
    const body = openDrawer({ title: r.title, subtitle: `${r.started_by} 시작 · ${fmtTime(r.started_at, { seconds: false })}`,
      actions: html`<button class="btn sm" data-csv>CSV 내려받기</button>` });
    const me = currentUser();
    const open = r.status === 'open';
    const signedByMe = r.signed && r.signed.author === me.username;
    body.innerHTML = html`
      <p>${reviewStatus(r.status)} <span class="muted">켜진 계정 ${fmtNum(r.active)}개 중 ${fmtNum(r.decided)}개 결정</span></p>
      ${r.rejected && open ? html`<div class="hint-box">반려됨 — ${r.rejected.author}: ${r.rejected.note}</div>` : ''}
      ${r.follow_up.length ? html`<div class="error-box">회수로 정했는데 아직 켜진 계정: ${r.follow_up.join(', ')} — 아래 '지금 끄기'</div>` : ''}
      <div class="table-wrap"><table class="table">
        <thead><tr><th>계정</th><th>역할·그룹</th><th>권한</th><th>마지막 사용</th><th>결정</th></tr></thead>
        <tbody>${r.users.map((u) => html`<tr>
          <td class="nowrap"><b>${u.username}</b>${u.display_name ? html` <span class="muted">${u.display_name}</span>` : ''}
            ${u.is_active ? '' : html`<div class="muted">검토 때 꺼짐${u.disabled_reason === 'dormant' ? ' (장기 미사용)' : ''}</div>`}
            ${u.now_active === null ? html`<div class="muted">지금은 지운 계정</div>` : ''}</td>
          <td>${u.role_label}${u.groups.length ? html`<div>${u.groups.map((g) => html`<span class="type-tag" style="margin-right:4px">${g}</span>`)}</div>` : ''}
            ${u.scoped ? html`<div class="muted">조회 범위 있음</div>` : ''}</td>
          <td style="font-size:12.5px">${u.permissions.length ? u.permissions.join(', ') : html`<span class="muted">보기만</span>`}${u.mfa ? html`<div class="muted">2단계 인증 사용</div>` : ''}</td>
          <td class="nowrap muted">${u.last_used ? fmtRelative(u.last_used) : '없음'}</td>
          <td>${u.is_active && open ? html`<div class="toolbar" style="flex-wrap:wrap;gap:6px">
              <select class="input" data-decision="${u.id}" aria-label="${u.username} 결정">
                <option value="">결정…</option>${DECISIONS.map(([v, l]) => html`<option value="${v}" ${u.decision?.decision === v ? 'selected' : ''}>${l}</option>`)}</select>
              <input class="input" data-note="${u.id}" maxlength="1000" placeholder="사유 (회수·조정은 필수)" value="${u.decision?.note || ''}" aria-label="${u.username} 사유">
              <button class="btn sm" data-save="${u.id}">저장</button></div>
              ${u.decision ? html`<div class="muted" style="font-size:12px">${u.decision.author} · ${fmtTime(u.decision.at, { seconds: false })}</div>` : ''}`
            : u.decision ? html`<b>${DECISION_LABEL[u.decision.decision]}</b> ${u.decision.note ? html`<span class="muted">— ${u.decision.note}</span>` : ''}
              <div class="muted" style="font-size:12px">${u.decision.author} · ${fmtTime(u.decision.at, { seconds: false })}</div>` : html`<span class="muted">–</span>`}
            ${u.decision?.decision === 'revoke' && u.now_active ? html`<div><button class="btn sm danger" data-disable="${u.id}" data-name="${u.username}">지금 끄기</button></div>` : ''}</td>
        </tr>`)}</tbody></table></div>
      <div class="section-title">결재</div>
      ${r.status === 'open' ? html`<div class="toolbar" style="flex-wrap:wrap">
          <input class="input" data-sign-note maxlength="1000" placeholder="점검 의견 (선택)" style="flex:1;min-width:200px">
          <button class="btn primary" data-sign ${r.missing.length ? 'disabled' : ''}>점검 완료 — 서명</button></div>
          ${r.missing.length ? html`<p class="muted" style="font-size:12.5px">결정하지 않은 계정 ${r.missing.length}개: ${r.missing.slice(0, 5).join(', ')}${r.missing.length > 5 ? ' …' : ''}</p>` : ''}`
        : r.status === 'signed' ? html`<p>${r.signed.author} 서명 · ${fmtTime(r.signed.at, { seconds: false })}${r.signed.note ? ` — ${r.signed.note}` : ''}</p>
          ${signedByMe ? html`<p class="muted">서명한 사람이 아닌 다른 관리자가 승인·반려합니다.</p>` : html`<div class="toolbar" style="flex-wrap:wrap">
            <input class="input" data-approve-note maxlength="1000" placeholder="의견 (반려는 필수)" style="flex:1;min-width:200px">
            <button class="btn primary" data-approve>승인</button><button class="btn" data-reject>반려</button></div>`}`
        : html`<p>${r.signed?.author} 서명 → <b>${r.approved.author}</b> 승인 · ${fmtTime(r.approved.at, { seconds: false })}${r.approved.note ? ` — ${r.approved.note}` : ''}</p>`}
      <div class="section-title">기록</div>
      <ul class="ref-list" style="font-size:12.5px">${r.entries.slice().reverse().map((e) => html`<li>${fmtTime(e.at)} · ${e.author} · <b>${ENTRY_LABEL[e.kind]}</b>
        ${e.username ? ` ${e.username} → ${DECISION_LABEL[e.decision]}` : ''}${e.note ? html` <span class="muted">— ${e.note}</span>` : ''}</li>`)}</ul>`;
    if (scroll) body.scrollTop = scroll;   // 저장한 뒤 같은 줄 근처를 계속 보게

    const run = async (fn) => {
      try { await fn(); } catch (err) { toast(err.message, { type: 'error' }); }
    };
    body.querySelectorAll('[data-save]').forEach((b) => b.addEventListener('click', () => run(async () => {
      const userId = Number(b.dataset.save);
      const decision = body.querySelector(`[data-decision="${userId}"]`).value;
      if (!decision) { toast('유지·회수·조정 중 하나를 고르세요', { type: 'error' }); return; }
      await post(id, { kind: 'decision', user_id: userId, decision, note: body.querySelector(`[data-note="${userId}"]`).value });
    })));
    body.querySelector('[data-sign]')?.addEventListener('click', () => run(() =>
      post(id, { kind: 'sign', note: body.querySelector('[data-sign-note]').value })));
    body.querySelector('[data-approve]')?.addEventListener('click', () => run(() =>
      post(id, { kind: 'approve', note: body.querySelector('[data-approve-note]').value })));
    body.querySelector('[data-reject]')?.addEventListener('click', () => run(() =>
      post(id, { kind: 'reject', note: body.querySelector('[data-approve-note]').value })));
    body.querySelectorAll('[data-disable]').forEach((b) => b.addEventListener('click', () => run(async () => {
      const ok = await confirmModal({ title: '계정 끄기', message: `${b.dataset.name} 계정을 끌까요? (권한 검토에서 회수로 정함)`, danger: true, confirmText: '끄기' });
      if (!ok) return;
      await api.send('PATCH', `/api/users/${b.dataset.disable}`, { is_active: false });
      toast(`${b.dataset.name} 계정을 껐습니다.`, { type: 'success' });
      await load();
      await openReview(id, true);
    })));
    document.querySelector('.drawer [data-csv]')?.addEventListener('click', () =>
      exportCsv(`/api/access-reviews/${id}/csv`, {}, { what: '권한 검토 결과', format: '' }));
  }

  await load();
  return () => { disposed = true; };
}
