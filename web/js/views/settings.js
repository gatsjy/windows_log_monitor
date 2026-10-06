// 환경설정 (관리자 전용): 알림 수신자 · 수신 그룹 · 외부 연동(웹훅/Oracle) · 메일 서버.
// 하위 주소: #/settings/contacts | groups | channels | smtp
// 비밀값(비밀번호·웹훅 주소·헤더)은 서버가 돌려주지 않는다 → 입력란이 비어 있으면 '기존 값 유지'.
import * as api from '../api.js';
import { closeDrawer, openDrawer } from '../drawer.js';
import { confirmModal, errorBox, fmtNum, fmtRelative, fmtTime, html, navigate, promptModal, toast } from '../util.js';

const TABS = [
  ['contacts', '수신자'], ['groups', '수신 그룹'], ['channels', '외부 연동 (웹훅·Oracle)'], ['smtp', '메일 서버'],
  ['retention', '로그 보관'],
];
const SECRET_HINT = '저장되어 있음 — 바꿀 때만 입력';
const MIN_SEVERITY = [['info', '모든 알림 (정보 이상)'], ['warning', '경고 이상'], ['error', '오류 이상'], ['critical', '심각만']];
const MIN_LABEL = Object.fromEntries(MIN_SEVERITY);

function minSeveritySelect(value = 'info') {
  return html`<label>받을 최소 알림 수준<select class="select" name="min_severity">
    ${MIN_SEVERITY.map(([k, l]) => html`<option value="${k}" ${value === k ? 'selected' : ''}>${l}</option>`)}</select></label>`;
}

function ok(text) {
  return html`<div class="hint-box">✓ ${text}</div>`;
}

function usedBy(list) {
  return list?.length ? html`<span class="muted" title="${list.join(', ')}">규칙 ${list.length}개에서 사용</span>` : html`<span class="muted">미사용</span>`;
}

async function run(button, out, fn) {
  button.disabled = true;
  out.innerHTML = '<div class="muted" style="font-size:12.5px">처리 중…</div>';
  try {
    await fn();
  } catch (err) {
    out.innerHTML = errorBox(err);
  } finally {
    button.disabled = false;
  }
}

export async function mount(root, params, sub) {
  const tab = TABS.some(([k]) => k === sub) ? sub : 'contacts';
  let meta = {};

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">환경설정</h1>
        <p class="page-sub">알림을 받을 사람·그룹, 사내 메신저·Oracle DB 연동, 메일 서버를 설정합니다. 모든 변경은 감사 로그에 남습니다.</p></div>
    </div>
    <div class="seg" style="margin-bottom:14px" data-tabs>${TABS.map(([k, l]) =>
      html`<button class="${k === tab ? 'on' : ''}" data-tab="${k}">${l}</button>`)}</div>
    <div data-warn></div>
    <div data-body><div class="skeleton"></div></div>`;
  root.querySelectorAll('[data-tab]').forEach((b) => b.addEventListener('click', () => navigate(`settings/${b.dataset.tab}`)));
  const body = root.querySelector('[data-body]');

  try {
    meta = await api.get('/api/settings/meta');
  } catch (err) {
    body.innerHTML = errorBox(err);
    return;
  }
  if (!meta.secret_key_set) {
    root.querySelector('[data-warn]').innerHTML = html`<div class="error-box" style="margin-bottom:14px">
      서버에 <code>WLM_SECRET_KEY</code> 가 없어 비밀번호(메일 서버·Oracle)와 웹훅 주소를 저장할 수 없습니다. <code>.env</code> 에 설정 후 서버를 다시 시작하세요.</div>`;
  }

  const renderers = { contacts, groups, channels, smtp, retention };
  await renderers[tab](body, meta);
}

// ================================================================ 수신자

async function contacts(body) {
  const [{ items }, { items: groupList }] = await Promise.all([
    api.get('/api/settings/contacts'), api.get('/api/settings/groups'),
  ]);
  body.innerHTML = html`
    <section class="card">
      <div class="card-head"><h2 class="card-title">알림 받는 사람 ${fmtNum(items.length)}명</h2>
        <button class="btn primary sm" data-add>수신자 추가</button></div>
      <div class="card-body flush">${items.length ? html`<div class="table-wrap"><table class="table">
        <thead><tr><th>이름</th><th>부서</th><th>이메일</th><th>전화</th><th>수신 그룹</th><th>상태</th><th></th></tr></thead>
        <tbody>${items.map((c) => html`<tr class="${c.is_active ? '' : 'muted'}">
          <td class="nowrap"><b>${c.name}</b></td>
          <td class="nowrap">${c.department || '–'}</td>
          <td class="nowrap mono" style="font-size:12.5px">${c.email || html`<span class="tag-bad">없음</span>`}</td>
          <td class="nowrap">${c.phone || '–'}</td>
          <td>${c.groups.length ? c.groups.map((g) => html`<span class="dlv">${g}</span>`) : html`<span class="muted">없음</span>`}</td>
          <td class="nowrap">${c.is_active ? '받음' : '받지 않음'}</td>
          <td class="nowrap r"><button class="btn sm" data-edit="${c.id}">수정</button></td>
        </tr>`)}</tbody></table></div>` : html`<div class="empty">아직 수신자가 없습니다. '수신자 추가'로 알림 받을 사람을 등록하세요.</div>`}</div>
    </section>
    <p class="muted" style="font-size:12.5px">수신자는 로그인 계정과 별개입니다. 알림 규칙은 <b>수신 그룹</b> 단위로 보내므로, 수신자를 그룹에 넣어야 메일을 받습니다.</p>`;

  const edit = (c) => {
    const drawer = openDrawer({ title: c ? `수신자 수정 — ${c.name}` : '수신자 추가' });
    const inGroup = new Set(c?.group_ids ?? []);
    drawer.innerHTML = html`<form class="auth-form" data-form>
      <label>이름<input class="input" name="name" required maxlength="100" value="${c?.name ?? ''}"></label>
      <label>이메일<input class="input" name="email" type="email" maxlength="254" value="${c?.email ?? ''}" placeholder="kim@example.com"></label>
      <label>전화 (참고용)<input class="input" name="phone" maxlength="40" value="${c?.phone ?? ''}"></label>
      <label>부서<input class="input" name="department" maxlength="100" value="${c?.department ?? ''}"></label>
      <label>메모<input class="input" name="memo" maxlength="500" value="${c?.memo ?? ''}"></label>
      <label style="flex-direction:row;align-items:center;gap:8px"><input type="checkbox" name="is_active" ${c?.is_active ?? true ? 'checked' : ''}> 알림 받음</label>
      <div class="section-title" style="margin:4px 0 0">수신 그룹</div>
      <div class="check-list">${groupList.map((g) => html`<label><input type="checkbox" name="group" value="${g.id}" ${inGroup.has(g.id) ? 'checked' : ''}> ${g.name}</label>`)}</div>
      <div data-error></div>
      <div class="toolbar"><button class="btn primary" type="submit">저장</button>
        ${c ? html`<button class="btn ghost tag-bad" type="button" data-delete>삭제</button>` : ''}</div>
    </form>`;
    const form = drawer.querySelector('form');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const data = {
        name: form.name.value, email: form.email.value || null, phone: form.phone.value || null,
        department: form.department.value, memo: form.memo.value, is_active: form.is_active.checked,
        group_ids: [...form.querySelectorAll('[name=group]:checked')].map((i) => Number(i.value)),
      };
      try {
        await (c ? api.send('PUT', `/api/settings/contacts/${c.id}`, data) : api.send('POST', '/api/settings/contacts', data));
        closeDrawer();
        contacts(body);
      } catch (err) { form.querySelector('[data-error]').innerHTML = errorBox(err); }
    });
    form.querySelector('[data-delete]')?.addEventListener('click', async () => {
      const ok = await confirmModal({
        title: '수신자 삭제',
        message: `'${c.name}' 수신자를 삭제할까요? (그룹에서도 빠집니다)`,
        danger: true,
        confirmText: '삭제',
      });
      if (!ok) return;
      try {
        await api.send('DELETE', `/api/settings/contacts/${c.id}`);
        closeDrawer();
        contacts(body);
        toast(`'${c.name}' 수신자가 삭제되었습니다.`, { type: 'success' });
      } catch (err) {
        toast(err.message, { type: 'error' });
      }
    });
  };
  body.querySelector('[data-add]').addEventListener('click', () => edit(null));
  body.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => edit(items.find((c) => c.id === Number(b.dataset.edit)))));
}

// ============================================================== 수신 그룹

async function groups(body) {
  const [{ items }, { items: people }] = await Promise.all([api.get('/api/settings/groups'), api.get('/api/settings/contacts')]);
  const byId = Object.fromEntries(people.map((p) => [p.id, p]));
  body.innerHTML = html`
    <section class="card">
      <div class="card-head"><h2 class="card-title">수신 그룹 ${fmtNum(items.length)}개</h2>
        <button class="btn primary sm" data-add>그룹 추가</button></div>
      <div class="card-body flush"><div class="table-wrap"><table class="table">
        <thead><tr><th>그룹 (규칙에 쓰는 이름)</th><th>구성원</th><th class="r">메일 받는 인원</th><th>받는 수준</th><th>사용</th><th></th></tr></thead>
        <tbody>${items.map((g) => html`<tr>
          <td class="nowrap"><b>${g.name}</b>${g.description ? html`<div class="muted" style="font-size:12px">${g.description}</div>` : ''}</td>
          <td>${g.member_ids.length ? g.member_ids.map((id) => html`<span class="dlv">${byId[id]?.name ?? id}</span>`) : html`<span class="muted">없음</span>`}</td>
          <td class="r num ${g.deliverable ? '' : 'tag-bad'}">${fmtNum(g.deliverable)}</td>
          <td class="nowrap">${MIN_LABEL[g.min_severity]}</td>
          <td class="nowrap">${usedBy(g.used_by)}</td>
          <td class="nowrap r"><button class="btn sm" data-edit="${g.id}">수정</button></td>
        </tr>`)}</tbody></table></div></div>
    </section>
    <p class="muted" style="font-size:12.5px">알림 규칙(<a href="#/alerts">알림 › 규칙 편집</a>)의 <code>notify</code> 에 그룹 이름을 씁니다. 예) <code>notify: [운영팀, 보안팀]</code>.
      메일 받는 인원 = 그룹 구성원 중 '알림 받음'이고 이메일이 있는 사람.</p>`;

  const edit = (g) => {
    const drawer = openDrawer({ title: g ? `수신 그룹 수정 — ${g.name}` : '수신 그룹 추가' });
    const members = new Set(g?.member_ids ?? []);
    drawer.innerHTML = html`<form class="auth-form">
      <label>그룹 이름 (규칙의 notify 에 쓰는 이름)<input class="input" name="name" required maxlength="64" value="${g?.name ?? ''}"></label>
      ${g?.used_by?.length ? html`<p class="muted" style="margin:0;font-size:12.5px">규칙 ${g.used_by.join(', ')} 에서 사용 중이라 이름을 바꾸려면 규칙을 먼저 고치세요.</p>` : ''}
      <label>설명<input class="input" name="description" maxlength="200" value="${g?.description ?? ''}"></label>
      ${minSeveritySelect(g?.min_severity)}
      <div class="section-title" style="margin:4px 0 0">구성원</div>
      <input class="input" data-filter placeholder="이름·부서로 찾기">
      <div class="check-list tall">${people.length ? people.map((p) => html`<label data-person="${`${p.name} ${p.department} ${p.email ?? ''}`.toLowerCase()}">
        <input type="checkbox" name="member" value="${p.id}" ${members.has(p.id) ? 'checked' : ''}>
        ${p.name} <span class="muted">${p.department} ${p.email ?? '(이메일 없음)'}</span>${p.is_active ? '' : html` <span class="type-tag">받지 않음</span>`}</label>`)
        : html`<span class="muted">먼저 '수신자' 탭에서 사람을 등록하세요</span>`}</div>
      <div data-error></div>
      <div class="toolbar"><button class="btn primary" type="submit">저장</button>
        ${g ? html`<button class="btn ghost tag-bad" type="button" data-delete>삭제</button>` : ''}</div>
    </form>`;
    const form = drawer.querySelector('form');
    form.querySelector('[data-filter]').addEventListener('input', (e) => {
      const q = e.target.value.trim().toLowerCase();
      form.querySelectorAll('[data-person]').forEach((l) => { l.hidden = q && !l.dataset.person.includes(q); });
    });
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const data = { name: form.name.value, description: form.description.value, min_severity: form.min_severity.value,
        member_ids: [...form.querySelectorAll('[name=member]:checked')].map((i) => Number(i.value)) };
      try {
        await (g ? api.send('PUT', `/api/settings/groups/${g.id}`, data) : api.send('POST', '/api/settings/groups', data));
        closeDrawer();
        groups(body);
      } catch (err) { form.querySelector('[data-error]').innerHTML = errorBox(err); }
    });
    form.querySelector('[data-delete]')?.addEventListener('click', async () => {
      const ok = await confirmModal({
        title: '수신 그룹 삭제',
        message: `그룹 '${g.name}' 을(를) 삭제할까요? (수신자는 지워지지 않습니다)`,
        danger: true,
        confirmText: '삭제',
      });
      if (!ok) return;
      try {
        await api.send('DELETE', `/api/settings/groups/${g.id}`);
        closeDrawer();
        groups(body);
        toast(`'${g.name}' 그룹이 삭제되었습니다.`, { type: 'success' });
      } catch (err) {
        toast(err.message, { type: 'error' });
      }
    });
  };
  body.querySelector('[data-add]').addEventListener('click', () => edit(null));
  body.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => edit(items.find((g) => g.id === Number(b.dataset.edit)))));
}

// ============================================================== 외부 연동

async function channels(body, meta) {
  const [{ items }, tns] = await Promise.all([api.get('/api/settings/channels'), api.get('/api/settings/oracle/tnsnames')]);
  body.innerHTML = html`
    <section class="card" style="margin-bottom:14px">
      <div class="card-head"><h2 class="card-title">외부 연동 ${fmtNum(items.length)}개</h2>
        <div class="toolbar"><button class="btn sm" data-add="webhook">웹훅 추가</button><button class="btn primary sm" data-add="oracle">Oracle DB 추가</button></div></div>
      <div class="card-body flush">${items.length ? html`<div class="table-wrap"><table class="table">
        <thead><tr><th>이름 (규칙에 쓰는 이름)</th><th>종류</th><th>대상</th><th>받는 수준</th><th>사용</th><th>변경</th><th></th></tr></thead>
        <tbody>${items.map((c) => html`<tr class="${c.is_active ? '' : 'muted'}">
          <td class="nowrap"><b>${c.name}</b>${c.is_active ? '' : html` <span class="type-tag">사용 안 함</span>`}
            ${c.description ? html`<div class="muted" style="font-size:12px">${c.description}</div>` : ''}</td>
          <td class="nowrap">${c.type === 'oracle' ? `Oracle · ${meta.oracle_modes[c.config.mode] ?? ''}` : '웹훅'}</td>
          <td class="mono" style="font-size:12px;overflow-wrap:anywhere">${c.error ? html`<span class="tag-bad">${c.error}</span>` : c.target}</td>
          <td class="nowrap">${MIN_LABEL[c.min_severity]}</td>
          <td class="nowrap">${usedBy(c.used_by)}</td>
          <td class="nowrap muted" title="${fmtTime(c.updated_at)}">${fmtRelative(c.updated_at)} · ${c.updated_by || ''}</td>
          <td class="nowrap r"><button class="btn sm" data-edit="${c.id}">${c.type === 'oracle' ? '설정·쿼리' : '수정'}</button></td>
        </tr>`)}</tbody></table></div>` : html`<div class="empty">웹훅(사내 메신저) 또는 Oracle DB 연동을 추가하세요.</div>`}</div>
    </section>
    <section class="card">
      <div class="card-head"><h2 class="card-title">Oracle tnsnames.ora</h2><span class="muted mono" style="font-size:12px">${tns.path}</span></div>
      <div class="card-body">
        <p class="muted" style="margin:0 0 8px;font-size:12.5px">접속 방식 'TNS 이름'에서 쓰는 파일입니다. 기존 Oracle 클라이언트의 tnsnames.ora 내용을 붙여 넣으세요.
          별칭: ${tns.aliases.length ? tns.aliases.join(', ') : '없음'}</p>
        <textarea class="input editor" style="min-height:180px" data-tns spellcheck="false" placeholder="ERP_PROD =\n  (DESCRIPTION =\n    (ADDRESS = (PROTOCOL = TCP)(HOST = db.corp.local)(PORT = 1521))\n    (CONNECT_DATA = (SID = ORCL)))">${tns.text}</textarea>
        <div class="toolbar" style="margin-top:8px"><button class="btn" data-save-tns>저장</button><span data-tns-msg></span></div>
      </div>
    </section>`;

  body.querySelector('[data-save-tns]').addEventListener('click', (e) => run(e.target, body.querySelector('[data-tns-msg]'), async () => {
    const res = await api.send('PUT', '/api/settings/oracle/tnsnames', { text: body.querySelector('[data-tns]').value });
    body.querySelector('[data-tns-msg]').innerHTML = ok(`저장됨 — 별칭 ${res.aliases.join(', ') || '없음'}`);
  }));
  const reload = () => channels(body, meta);
  body.querySelectorAll('[data-add]').forEach((b) => b.addEventListener('click', () =>
    (b.dataset.add === 'oracle' ? editOracle(null, meta, tns.aliases, reload) : editWebhook(null, reload))));
  body.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => {
    const c = items.find((x) => x.id === Number(b.dataset.edit));
    if (c.type === 'oracle') editOracle(c, meta, tns.aliases, reload); else editWebhook(c, reload);
  }));
}

function commonFields(c) {
  return html`
    <label>이름 (규칙의 notify 에 쓰는 이름)<input class="input" name="name" required maxlength="64" value="${c?.name ?? ''}"></label>
    <label>설명<input class="input" name="description" maxlength="200" value="${c?.description ?? ''}"></label>
    <label style="flex-direction:row;align-items:center;gap:8px"><input type="checkbox" name="is_active" ${c?.is_active ?? true ? 'checked' : ''}> 사용</label>
    ${minSeveritySelect(c?.min_severity)}`;
}

async function saveChannel(c, data) {
  if (c) {
    await api.send('PUT', `/api/settings/channels/${c.id}`, data);
    return c.id;
  }
  return (await api.send('POST', '/api/settings/channels', data)).id;
}

async function deleteChannel(c, done) {
  const ok = await confirmModal({
    title: '연동 삭제',
    message: `'${c.name}' 연동을 삭제할까요?`,
    danger: true,
    confirmText: '삭제',
  });
  if (!ok) return;
  try {
    await api.send('DELETE', `/api/settings/channels/${c.id}`);
    closeDrawer();
    done();
    toast(`'${c.name}' 연동이 삭제되었습니다.`, { type: 'success' });
  } catch (err) {
    toast(err.message, { type: 'error' });
  }
}

function editWebhook(c, done) {
  const drawer = openDrawer({ title: c ? `웹훅 — ${c.name}` : '웹훅 추가', subtitle: '사내 메신저 등으로 HTTP POST' });
  drawer.innerHTML = html`<form class="auth-form">
    ${commonFields(c)}
    <label>웹훅 주소<input class="input mono" name="url" ${c ? '' : 'required'} placeholder="${c ? `${c.target}  (${SECRET_HINT})` : 'https://chat.example.com/hooks/…'}"></label>
    <label>보내는 형식<select class="select" name="format">
      <option value="json" ${c?.config.format !== 'text' ? 'selected' : ''}>json — 알림 전체 데이터 (사내 시스템 연동)</option>
      <option value="text" ${c?.config.format === 'text' ? 'selected' : ''}>text — {"text": "..."} (Slack·Mattermost·메신저 호환)</option>
    </select></label>
    <label>추가 헤더 (한 줄에 하나, 예: Authorization: Bearer 토큰)
      <textarea class="input mono" name="headers" rows="3" placeholder="${c?.has_secret ? '저장된 헤더 유지 — 바꿀 때만 입력 (모두 지우려면 - 한 글자)' : ''}"></textarea></label>
    <label>시간 제한(초)<input class="input" name="timeout" type="number" min="1" max="60" value="${c?.config.timeout_sec ?? 10}"></label>
    <div data-error></div>
    <div class="toolbar"><button class="btn primary" type="submit">저장</button>
      ${c ? html`<button class="btn" type="button" data-test>테스트 발송</button><button class="btn ghost tag-bad" type="button" data-delete>삭제</button>` : ''}</div>
  </form>`;
  const form = drawer.querySelector('form');
  const out = form.querySelector('[data-error]');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const raw = form.headers.value.trim();
    let headers;
    if (raw === '-') headers = {};
    else if (raw) headers = Object.fromEntries(raw.split('\n').filter((l) => l.includes(':')).map((l) => [l.slice(0, l.indexOf(':')).trim(), l.slice(l.indexOf(':') + 1).trim()]));
    try {
      await saveChannel(c, { name: form.name.value, type: 'webhook', description: form.description.value,
        is_active: form.is_active.checked, min_severity: form.min_severity.value, url: form.url.value || null, headers,
        config: { format: form.format.value, timeout_sec: Number(form.timeout.value) } });
      closeDrawer();
      done();
    } catch (err) { out.innerHTML = errorBox(err); }
  });
  form.querySelector('[data-test]')?.addEventListener('click', (e) => run(e.target, out, async () => {
    await api.send('POST', `/api/settings/channels/${c.id}/test`);
    out.innerHTML = ok('전송 성공 — 받는 쪽에서 확인하세요 (저장된 설정 기준)');
  }));
  form.querySelector('[data-delete]')?.addEventListener('click', () => deleteChannel(c, done));
}

function editOracle(c, meta, aliases, done) {
  const cfg = c?.config ?? { mode: 'tns', port: 1521, sql: meta.oracle_default_sql };
  const drawer = openDrawer({ title: c ? `Oracle — ${c.name}` : 'Oracle DB 추가', subtitle: '알림이 생기면 사내 Oracle 에 SQL 실행' });
  drawer.innerHTML = html`<form class="auth-form" data-oracle>
    ${commonFields(c)}
    <div class="section-title" style="margin:6px 0 0">접속</div>
    <div class="seg" data-modes>${Object.entries(meta.oracle_modes).map(([k, l]) =>
      html`<button type="button" data-mode="${k}" class="${cfg.mode === k ? 'on' : ''}">${l}</button>`)}</div>
    <div data-mode-fields="tns">
      <label>TNS 이름 (tnsnames.ora 별칭)<input class="input" name="tns_alias" list="tns-aliases" value="${cfg.tns_alias ?? ''}" placeholder="ERP_PROD"></label>
      <datalist id="tns-aliases">${aliases.map((a) => html`<option value="${a}">`)}</datalist>
      <p class="muted" style="margin:4px 0 0;font-size:12px">${aliases.length ? `등록된 별칭: ${aliases.join(', ')}` : '아래 tnsnames.ora 카드에 파일 내용을 먼저 저장하세요'}</p>
    </div>
    <div data-mode-fields="sid service"><div class="form-row">
      <label style="flex:2">호스트<input class="input" name="host" value="${cfg.host ?? ''}" placeholder="db.corp.local"></label>
      <label style="flex:1">포트<input class="input" name="port" type="number" value="${cfg.port ?? 1521}"></label></div></div>
    <div data-mode-fields="sid"><label>SID<input class="input" name="sid" value="${cfg.sid ?? ''}" placeholder="ORCL"></label></div>
    <div data-mode-fields="service"><label>서비스 이름<input class="input" name="service_name" value="${cfg.service_name ?? ''}" placeholder="ORCLPDB1"></label></div>
    <div data-mode-fields="dsn"><label>접속 문자열<textarea class="input mono" name="dsn" rows="3" placeholder="db.corp.local:1521/ORCLPDB1  또는  (DESCRIPTION=...)">${cfg.dsn ?? ''}</textarea></label></div>
    <div class="form-row">
      <label style="flex:1">계정<input class="input" name="user" value="${cfg.user ?? ''}" autocomplete="off"></label>
      <label style="flex:1">비밀번호<input class="input" name="password" type="password" autocomplete="new-password" placeholder="${c?.has_secret ? SECRET_HINT : ''}"></label>
    </div>
    <div class="toolbar"><button class="btn" type="button" data-probe>연결 시험</button><span class="muted" style="font-size:12px">저장 전에 입력한 값으로 접속해 봅니다</span></div>
    <div data-probe-out></div>

    <div class="section-title" style="margin:10px 0 0">알림이 생길 때 실행할 SQL</div>
    <textarea class="input editor mono" name="sql" style="min-height:150px" spellcheck="false">${cfg.sql ?? meta.oracle_default_sql}</textarea>
    <p class="muted" style="margin:0;font-size:12px">바인드 변수: ${meta.oracle_binds.map((b) => html`<code>:${b}</code> `)}
      · 시각은 UTC TIMESTAMP · 프로시저는 <code>BEGIN 프로시저(:rule_name, :host); END;</code> · 기본 테이블 DDL: docs/oracle_alerts.sql</p>
    <div data-error></div>
    <div class="toolbar"><button class="btn primary" type="submit">저장</button>
      ${c ? html`<button class="btn" type="button" data-dry>SQL 시험 실행 (되돌림)</button>
        <button class="btn" type="button" data-commit>테스트 알림 실제 저장</button>
        <button class="btn ghost tag-bad" type="button" data-delete>삭제</button>` : ''}</div>
  </form>
  ${c ? html`<div class="section-title">조회 쿼리 실행 (SELECT 전용 · 읽기 전용 트랜잭션 · 최대 500행 · 실행 기록은 감사 로그에)</div>
    <textarea class="input editor mono" data-query style="min-height:90px" spellcheck="false">SELECT * FROM LOGMON_ALERTS ORDER BY FIRED_AT DESC FETCH FIRST 20 ROWS ONLY</textarea>
    <div class="toolbar" style="margin:8px 0"><button class="btn" data-run>실행</button><span class="muted" data-query-meta style="font-size:12.5px"></span></div>
    <div data-query-out></div>` : ''}`;

  const form = drawer.querySelector('[data-oracle]');
  let mode = cfg.mode || 'tns';
  const showMode = () => {
    form.querySelectorAll('[data-mode]').forEach((b) => b.classList.toggle('on', b.dataset.mode === mode));
    form.querySelectorAll('[data-mode-fields]').forEach((el) => { el.hidden = !el.dataset.modeFields.split(' ').includes(mode); });
  };
  form.querySelectorAll('[data-mode]').forEach((b) => b.addEventListener('click', () => { mode = b.dataset.mode; showMode(); }));
  showMode();

  const config = () => ({
    mode, user: form.user.value, tns_alias: form.tns_alias.value, host: form.host.value, port: Number(form.port.value) || 1521,
    sid: form.sid.value, service_name: form.service_name.value, dsn: form.dsn.value, sql: form.sql.value,
  });
  const out = form.querySelector('[data-error]');

  form.querySelector('[data-probe]').addEventListener('click', (e) => {
    const probeOut = form.querySelector('[data-probe-out]');
    run(e.target, probeOut, async () => {
      const r = await api.send('POST', '/api/settings/oracle/test-connection', {
        config: config(), password: form.password.value || null, channel_id: c?.id ?? null });
      probeOut.innerHTML = ok(`접속 성공 — DB ${r.db_name} · 서비스 ${r.service_name} · 스키마 ${r.schema} · 버전 ${r.version}`);
    });
  });
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await saveChannel(c, { name: form.name.value, type: 'oracle', description: form.description.value,
        is_active: form.is_active.checked, min_severity: form.min_severity.value, password: form.password.value || null, config: config() });
      closeDrawer();
      done();
    } catch (err) { out.innerHTML = errorBox(err); }
  });
  form.querySelector('[data-dry]')?.addEventListener('click', (e) => run(e.target, out, async () => {
    const r = await api.send('POST', `/api/settings/channels/${c.id}/oracle/dry-run`, { commit: false });
    out.innerHTML = ok(`실행 성공 (${r.rowcount}행) — 되돌렸으므로 DB 에는 남지 않습니다. 사용한 바인드: ${r.binds.join(', ')}. 저장된 SQL 기준`);
  }));
  form.querySelector('[data-commit]')?.addEventListener('click', async (e) => {
    const okCommit = await confirmModal({
      title: 'Oracle 테스트 알림 저장',
      message: '테스트 알림 한 건을 실제로 Oracle 에 저장합니다. 계속할까요?',
      confirmText: '저장',
    });
    if (!okCommit) return;
    run(e.target, out, async () => {
      await api.send('POST', `/api/settings/channels/${c.id}/oracle/dry-run`, { commit: true });
      out.innerHTML = ok('테스트 알림을 저장했습니다 (규칙 이름 "테스트 알림", 대상 TEST-PC)');
      toast('테스트 알림을 Oracle에 저장했습니다.', { type: 'success' });
    });
  });
  form.querySelector('[data-delete]')?.addEventListener('click', () => deleteChannel(c, done));

  drawer.querySelector('[data-run]')?.addEventListener('click', (e) => {
    const qOut = drawer.querySelector('[data-query-out]');
    run(e.target, qOut, async () => {
      const r = await api.send('POST', `/api/settings/channels/${c.id}/oracle/query`, { sql: drawer.querySelector('[data-query]').value, max_rows: 200 });
      drawer.querySelector('[data-query-meta]').textContent = `${fmtNum(r.rows.length)}행${r.truncated ? ' (더 있음, 200행까지 표시)' : ''} · ${r.elapsed_ms}ms`;
      qOut.innerHTML = r.columns.length ? html`<div class="table-wrap query-result"><table class="table">
        <thead><tr>${r.columns.map((col) => html`<th>${col}</th>`)}</tr></thead>
        <tbody>${r.rows.map((row) => html`<tr>${row.map((v) => html`<td class="mono" style="font-size:12px">${v === null ? html`<span class="muted">NULL</span>` : String(v).slice(0, 300)}</td>`)}</tr>`)}</tbody>
      </table></div>` : '<div class="empty">결과 없음</div>';
    });
  });
}

// ============================================================== 메일 서버

async function smtp(body) {
  const s = await api.get('/api/settings/smtp');
  const v = s.value || {};
  body.innerHTML = html`
    <section class="card"><div class="card-body">
      <div class="hint-box" style="margin-bottom:14px">현재 적용 중: <b>${s.source === 'db' ? '이 화면의 설정' : '서버 .env (WLM_SMTP_*)'}</b>
        — ${s.effective.host ? `${s.effective.host}:${s.effective.port} (${s.effective.security})` : '메일 서버 없음'}
        ${s.source === 'env' ? html`<br><span class="muted">아래에 호스트를 입력해 저장하면 화면 설정이 우선합니다. 호스트를 비우고 저장하면 다시 .env 를 씁니다.</span>` : ''}</div>
      <form class="auth-form" style="max-width:560px">
        <div class="form-row">
          <label style="flex:2">SMTP 호스트<input class="input" name="host" value="${v.host ?? ''}" placeholder="${s.env.host || 'smtp.corp.local'}"></label>
          <label style="flex:1">포트<input class="input" name="port" type="number" value="${v.port ?? 587}"></label>
        </div>
        <label>보안 연결<select class="select" name="security">
          ${[['starttls', 'STARTTLS (보통 587)'], ['ssl', 'SSL/TLS (보통 465)'], ['none', '없음 (사내 릴레이, 25)']].map(([k, l]) =>
            html`<option value="${k}" ${(v.security ?? 'starttls') === k ? 'selected' : ''}>${l}</option>`)}
        </select></label>
        <div class="form-row">
          <label style="flex:1">계정 (인증 없으면 비움)<input class="input" name="user" value="${v.user ?? ''}" autocomplete="off"></label>
          <label style="flex:1">비밀번호<input class="input" name="password" type="password" autocomplete="new-password" placeholder="${s.has_password ? SECRET_HINT : ''}"></label>
        </div>
        ${s.has_password ? html`<label style="flex-direction:row;align-items:center;gap:8px"><input type="checkbox" name="clear"> 저장된 비밀번호 지우기</label>` : ''}
        <label>보내는 사람<input class="input" name="sender" value="${v.sender ?? ''}" placeholder="${s.env.sender}"></label>
        <div data-error></div>
        <div class="toolbar"><button class="btn primary" type="submit">저장</button>
          ${s.updated_at ? html`<span class="muted" style="font-size:12.5px">마지막 변경 ${fmtTime(s.updated_at)} · ${s.updated_by}</span>` : ''}</div>
      </form>
      <div class="section-title">테스트 메일</div>
      <div class="toolbar"><input class="input" data-to type="email" placeholder="받을 주소" style="width:260px"><button class="btn" data-test>보내기</button></div>
      <div data-test-out style="margin-top:8px"></div>
    </div></section>`;
  const form = body.querySelector('form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api.send('PUT', '/api/settings/smtp', {
        host: form.host.value, port: Number(form.port.value) || 587, security: form.security.value, user: form.user.value,
        sender: form.sender.value, password: form.password.value || null, clear_password: form.clear?.checked ?? false });
      smtp(body);
    } catch (err) { form.querySelector('[data-error]').innerHTML = errorBox(err); }
  });
  body.querySelector('[data-test]').addEventListener('click', (e) => {
    const out = body.querySelector('[data-test-out]');
    run(e.target, out, async () => {
      await api.send('POST', '/api/settings/smtp/test', { to: body.querySelector('[data-to]').value });
      out.innerHTML = ok('보냈습니다 — 받은 편지함(개발 환경은 http://localhost:8025)을 확인하세요');
    });
  });
}

// ============================================================== 로그 보관

const mb = (bytes) => `${(bytes / 1024 / 1024).toLocaleString('ko-KR', { maximumFractionDigits: 1 })} MB`;
const day = (iso) => fmtTime(iso, { seconds: false }).slice(0, 10);

async function retention(body) {
  const s = await api.get('/api/settings/retention');
  const p = s.policy;
  body.innerHTML = html`
    <section class="card" style="margin-bottom:14px"><div class="card-body">
      <div class="section-title" style="margin-top:0">로그 로테이션 정책</div>
      <div class="rotation">
        <div><b>DB</b><span>최근 ${p.db_retention_days}일</span><small>화면에서 바로 검색</small></div>
        <span class="arrow">→</span>
        <div><b>보관 파일</b><span>${p.archiving ? `~ ${p.retention_days}일` : '사용 안 함'}</span><small>압축(.jsonl.gz) + SHA-256</small></div>
        <span class="arrow">→</span>
        <div><b>삭제</b><span>${p.retention_days}일 후</span><small>삭제 기록은 감사 로그</small></div>
      </div>
      <p class="muted" style="font-size:12.5px;margin:10px 0 0">월 단위로 1시간마다 자동 실행됩니다. 기간은 서버 <code>.env</code> 의
        <code>WLM_DB_RETENTION_DAYS</code>, <code>WLM_RETENTION_DAYS</code> 로 정합니다. 보관 파일 위치: <code>${p.archive_dir}</code> (백업 대상)</p>
      <div class="toolbar" style="margin-top:10px"><button class="btn" data-rotate>지금 실행</button>
        <button class="btn" data-verify>보관 파일 무결성 확인</button><span data-msg></span></div>
    </div></section>
    <div class="grid">
      <section class="card" style="grid-column: span 6"><div class="card-head"><h2 class="card-title">DB 에 있는 로그 (월 파티션)</h2></div>
        <div class="card-body flush"><div class="table-wrap"><table class="table">
          <thead><tr><th>파티션</th><th>기간</th><th class="r">건수(추정)</th><th class="r">크기</th><th></th></tr></thead>
          <tbody>${s.partitions.map((x) => html`<tr>
            <td class="nowrap mono" style="font-size:12.5px">${x.name}</td>
            <td class="nowrap">${day(x.from)} ~</td>
            <td class="r num">${fmtNum(x.rows_estimate)}</td>
            <td class="r num">${mb(x.bytes)}</td>
            <td class="nowrap">${x.hold_until ? html`<span class="type-tag" title="복원한 파티션">${day(x.hold_until)}까지 보존</span>` : ''}</td>
          </tr>`)}</tbody></table></div></div></section>
      <section class="card" style="grid-column: span 6"><div class="card-head"><h2 class="card-title">보관 파일</h2></div>
        <div class="card-body flush">${s.archives.length ? html`<div class="table-wrap"><table class="table">
          <thead><tr><th>파일</th><th class="r">건수</th><th class="r">크기</th><th>SHA-256</th><th></th></tr></thead>
          <tbody>${s.archives.map((a) => html`<tr>
            <td class="nowrap mono" style="font-size:12.5px" title="${day(a.from)} ~ ${day(a.to)} · 생성 ${fmtTime(a.created_at)}">${a.file}${a.exists ? '' : html` <span class="tag-bad">파일 없음</span>`}</td>
            <td class="r num">${fmtNum(a.rows)}</td>
            <td class="r num">${mb(a.bytes)}</td>
            <td class="mono muted" style="font-size:11.5px" title="${a.sha256}">${a.sha256.slice(0, 12)}…</td>
            <td class="nowrap r"><button class="btn sm" data-restore="${a.partition}">다시 불러오기</button></td>
          </tr>`)}</tbody></table></div>` : html`<div class="empty">아직 보관 파일이 없습니다 (DB 보관기간이 지난 달이 생기면 자동으로 만들어집니다)</div>`}</div></section>
    </div>`;
  const msg = body.querySelector('[data-msg]');
  body.querySelector('[data-rotate]').addEventListener('click', (e) => run(e.target, msg, async () => {
    await api.send('POST', '/api/settings/retention/rotate');
    retention(body);
  }));
  body.querySelector('[data-verify]').addEventListener('click', (e) => run(e.target, msg, async () => {
    const { items } = await api.send('POST', '/api/settings/retention/verify');
    const bad = items.filter((i) => !i.ok);
    msg.innerHTML = bad.length ? errorBox(new Error(`문제 ${bad.length}건: ${bad.map((b) => `${b.file} (${b.problem})`).join(', ')}`))
      : ok(`보관 파일 ${items.length}개 모두 정상 (SHA-256 일치)`);
  }));
  body.querySelectorAll('[data-restore]').forEach((b) => b.addEventListener('click', async () => {
    const days = await promptModal({
      title: '로그 보관 데이터 복원',
      message: `${b.dataset.restore} 를 DB 로 다시 불러옵니다. 며칠 동안 검색할 수 있게 둘까요?`,
      defaultValue: '14',
      placeholder: '보관 유지 일수 (일)',
      confirmText: '복원',
    });
    if (!days) return;
    run(b, msg, async () => {
      const r = await api.send('POST', '/api/settings/retention/restore', { partition: b.dataset.restore, hold_days: Number(days) });
      retention(body);
      toast(`${fmtNum(r.rows)}건을 불러왔습니다. 이벤트 검색에서 해당 기간을 조회하세요.`, { type: 'success', duration: 4500 });
    });
  }));
}
