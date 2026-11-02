// 오른쪽에서 열리는 상세 패널 + 이벤트 상세 보기.
import * as api from './api.js';
import { can } from './auth.js';
import { eventDoc } from './catalog.js';
import { jsonView } from './jsonview.js';
import { categoryLabel, levelBadge, sourceLabel } from './levels.js';
import { accountKey, addTerm, aliasPath, formatTerm, parseTerms } from './querylang.js';
import { runTest } from './ruletest.js';
import { errorBox, fmtNum, fmtRelative, fmtTime, html, navigate } from './util.js';

let current = null;
// 이벤트 검색·실시간 화면이 열려 있는 동안: { query(): 지금 확정된 문장, apply(text): 문장을 바꿔 바로 검색 }
// 상세 패널의 값에서 지금 검색을 '좁히기'(조건 추가)·'제외'(-조건)할 수 있게 한다 (B-01)
let searchContext = null;
export function setSearchContext(ctx) { searchContext = ctx; }

const INT_KEYS = new Set(['event_id', 'level']);

/** {host: 'WEB-01'} 같은 옛 조건 → 문장 term. 문장으로 쓸 수 없는 원본 경로면 null */
function termOf(filter) {
  const [[key, value]] = Object.entries(filter);
  const term = key.startsWith('f.')
    ? { key: 'f', path: key.slice(2).split('.'), values: [String(value)], neg: false }
    : { key, path: [], values: [INT_KEYS.has(key) ? Number(value) : String(value)], neg: false };
  // 문장으로 쓴 뒤 다시 읽어 '같은 조건'일 때만 (경로에 ':' 가 든 원본 키 등은 문장으로 못 써서 옛 f. 검색만)
  try {
    const parsed = parseTerms(formatTerm(term));
    const p = parsed[0];
    const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
    return parsed.length === 1 && p.key === term.key && same(p.path, term.path) && same(p.values, term.values) ? term : null;
  } catch {
    return null;
  }
}

function actions(filter) {
  const term = termOf(filter);
  const enc = (v) => JSON.stringify(v);
  if (searchContext && term) {
    return html` <a href="#" class="filter-link" data-act="only" data-filter='${enc(filter)}'>이 값만</a>
      <a href="#" class="filter-link" data-act="narrow" data-filter='${enc(filter)}' title="지금 검색 문장에 이 조건을 더합니다">＋ 좁히기</a>
      <a href="#" class="filter-link" data-act="exclude" data-filter='${enc(filter)}' title="지금 검색에서 이 값을 뺍니다">－ 제외</a>`;
  }
  return html` <a href="#" class="filter-link" data-act="only" data-filter='${enc(filter)}'>이 값으로 검색</a>
    ${term ? html`<a href="#" class="filter-link" data-act="without" data-filter='${enc(filter)}'>제외하고 검색</a>` : ''}`;
}

function act(kind, filter) {
  const term = termOf(filter);
  if (kind === 'only' && term?.key === 'account') { searchBy({ query: formatTerm(term) }); return; }   // account 는 주소 파라미터가 없다
  if (kind === 'only' || !term) { searchBy(filter); return; }
  if (kind === 'without') { searchBy({ query: formatTerm({ ...term, neg: true }) }); return; }
  const ctx = searchContext;
  closeDrawer();
  ctx.apply(addTerm(ctx.query(), kind === 'exclude' ? { ...term, neg: true } : term));
}

export function closeDrawer() {
  current?.();
  current = null;
}

/** @returns {HTMLElement} 본문 요소 */
export function openDrawer({ title, subtitle = '', actions = '' }) {
  closeDrawer();
  const root = document.getElementById('drawer-root');
  root.innerHTML = html`
    <div class="drawer-overlay"></div>
    <aside class="drawer" role="dialog" aria-modal="true">
      <div class="drawer-head">
        <div><h2>${title}</h2>${subtitle ? html`<div class="page-sub">${subtitle}</div>` : ''}</div>
        <div class="toolbar">${actions}<button class="btn ghost sm" data-close aria-label="닫기">닫기 ✕</button></div>
      </div>
      <div class="drawer-body"></div>
    </aside>`;
  // 안의 입력 칸이 Esc 를 이미 썼으면(자동완성 닫기·되돌리기) 패널은 닫지 않는다
  const onKey = (ev) => { if (ev.key === 'Escape' && !ev.defaultPrevented) closeDrawer(); };
  document.addEventListener('keydown', onKey);
  root.querySelector('.drawer-overlay').addEventListener('click', closeDrawer);
  root.querySelector('[data-close]').addEventListener('click', closeDrawer);
  current = () => { document.removeEventListener('keydown', onKey); root.innerHTML = ''; };
  return root.querySelector('.drawer-body');
}

function searchBy(params) {
  closeDrawer();
  navigate('events', params);
}

// 앞뒤 로그 (B-61): 같은 PC(·소스)에서 이 로그 바로 앞·뒤. 누를 때만 불러온다 — 사용자·IP 가 보이는 조회라 접속기록에 남고(서버),
// 상세를 열 때마다 이웃까지 읽지 않게. 행을 누르면 그 로그의 상세로
const CONTEXT_PAGE = 10;

function contextLogs(body, ev) {
  const box = body.querySelector('[data-ctx]');
  const state = { same: 'host', before: [], after: [], more: { before: null, after: null }, open: false };
  const seg = body.querySelector('[data-ctx-same]');

  async function page(direction, cursor) {
    return api.get(`/api/events/${ev.id}/context`, { direction, same: state.same, limit: CONTEXT_PAGE, cursor });
  }
  async function load() {
    box.innerHTML = '<div class="skeleton"></div>';
    try {
      const [before, after] = await Promise.all([page('before'), page('after')]);
      Object.assign(state, { before: before.items, after: after.items, open: true,
        more: { before: before.next_cursor, after: after.next_cursor } });
      render();
    } catch (err) {
      box.innerHTML = errorBox(err);
    }
  }
  async function more(direction) {
    try {
      const res = await page(direction, state.more[direction]);
      state[direction] = [...state[direction], ...res.items];
      state.more[direction] = res.next_cursor;
      render();
    } catch (err) {
      box.insertAdjacentHTML('beforeend', errorBox(err));
    }
  }
  function render() {
    const rows = [...[...state.before].reverse(), { ...ev, base: true }, ...state.after];
    const edge = (direction, label, none) => (state.more[direction]
      ? html`<button class="btn sm" type="button" data-ctx-more="${direction}">${label}</button>`
      : html`<span class="muted" style="font-size:12.5px">${none}</span>`);
    box.innerHTML = html`<div style="margin:4px 0 6px">${edge('before', `더 앞 ${CONTEXT_PAGE}건`, '이 앞에는 로그가 없습니다')}</div>
      <div class="table-wrap"><table class="table ctx-table"><tbody>${rows.map((r) => html`<tr class="${r.base ? 'ctx-base' : ''}"
          ${r.base ? '' : html`data-ctx-id="${r.id}" title="이 로그 상세 보기"`}>
        <td class="nowrap num">${fmtTime(r.ts)}</td><td>${levelBadge(r.level)}</td>
        <td class="nowrap ink-2">${sourceLabel(r.source)}${r.event_id != null ? ` · ${r.event_id}` : ''}</td>
        <td class="ctx-msg">${(r.message || '').slice(0, 160)}</td></tr>`)}</tbody></table></div>
      <div style="margin:6px 0 4px">${edge('after', `더 뒤 ${CONTEXT_PAGE}건`, '이 뒤에는 로그가 없습니다')}</div>`;
    box.querySelectorAll('[data-ctx-more]').forEach((b) => b.addEventListener('click', () => more(b.dataset.ctxMore)));
    box.querySelectorAll('[data-ctx-id]').forEach((tr) => tr.addEventListener('click', () => openEvent(Number(tr.dataset.ctxId))));
  }
  body.querySelector('[data-ctx-open]').addEventListener('click', load);
  seg.querySelectorAll('button').forEach((b) => b.addEventListener('click', () => {
    state.same = b.dataset.v;
    seg.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === b));
    if (state.open) load();
  }));
}

// 계정 잠김 원인 (B-68): 같은 사용자의 로그온 실패(4625·4771·4776)를 접속지·PC 마다. 헬프데스크가 4740 → 4771 → 4625 를 손으로 따라가던 것
const LOCKOUT_EVENTS = { 4625: '로그온 실패', 4771: 'Kerberos 사전 인증 실패', 4776: 'NTLM 확인 실패' };

// 규칙 시험 (B-52): 규칙 목록은 고를 때 한 번만 불러온다 (상세를 열 때마다 알림 설정을 읽지 않게)
function ruleTest(body, ev) {
  const select = body.querySelector('[data-rt-rule]');
  let loaded = false;
  select.addEventListener('focus', async () => {
    if (loaded) return;
    loaded = true;
    try {
      const cfg = await api.get('/api/alerts/config');
      const rules = cfg.rules.filter((r) => r.kind === 'count' || r.kind === 'new_terms');
      select.insertAdjacentHTML('beforeend', String(html`${rules.map((r) => html`<option value="${r.name}">${r.name}${r.enabled ? '' : ' (꺼짐)'}</option>`)}`));
    } catch (err) {
      body.querySelector('[data-rt-out]').innerHTML = errorBox(err);
    }
  });
  body.querySelector('[data-rt-run]').addEventListener('click', () => {
    if (!select.value) { select.focus(); return; }
    runTest(body.querySelector('[data-rt-out]'), { name: select.value, event_id: ev.id });
  });
}

async function lockoutCause(box, ev) {
  box.innerHTML = '<div class="skeleton"></div>';
  let res;
  try {
    res = await api.get(`/api/events/${ev.id}/lockout`);
  } catch (err) {
    box.innerHTML = errorBox(err);
    return;
  }
  box.innerHTML = res.items.length ? html`<p class="muted" style="font-size:12.5px;margin:0 0 6px">
      접속지가 많은 순 — 가장 위가 오래된 비밀번호를 계속 넣는 곳일 가능성이 큽니다(휴대폰 메일·매핑 드라이브·예약 작업·서비스 계정 등).</p>
    <div class="table-wrap"><table class="table ctx-table"><thead><tr><th>접속지 IP</th><th>기록한 PC</th><th>무엇</th>
      <th class="r">횟수</th><th>처음</th><th>마지막</th></tr></thead>
      <tbody>${res.items.map((i) => html`<tr><td class="nowrap num">${i.ip ?? html`<span class="muted">(없음)</span>`}</td>
        <td class="nowrap">${i.host}</td><td class="nowrap ink-2">${LOCKOUT_EVENTS[i.event_id] ?? i.event_id}</td>
        <td class="r num"><b>${fmtNum(i.n)}</b></td><td class="nowrap muted">${fmtTime(i.first_ts)}</td>
        <td class="nowrap">${fmtTime(i.last_ts)}</td></tr>`)}</tbody></table></div>`
    : html`<p class="muted">잠김 30분 전~5분 뒤에 ${res.username} 의 로그온 실패가 없습니다 — 도메인 컨트롤러의 감사 정책(Kerberos 인증·자격 증명 확인)이 켜져 있는지 확인하세요.</p>`;
}

/** 이벤트 하나의 상세. ev 에 raw 가 있으면(실시간 화면) 그대로, 아니면 id 로 조회 */
export async function openEvent(evOrId) {
  const body = openDrawer({ title: '이벤트 상세' });
  body.innerHTML = '<div class="skeleton"></div>';
  let ev;
  try {
    ev = typeof evOrId === 'object' && evOrId.raw ? evOrId : await api.get(`/api/events/${typeof evOrId === 'object' ? evOrId.id : evOrId}`);
  } catch (err) {
    body.innerHTML = errorBox(err);
    return;
  }

  const doc = eventDoc(ev.event_id, ev.source);
  const row = (label, value, filter) => html`
    <dt>${label}</dt>
    <dd>${value ?? '–'}${filter ? actions(filter) : ''}</dd>`;

  body.innerHTML = html`
    <div class="toolbar" style="margin-bottom:14px">
      ${levelBadge(ev.level)}
      <span class="muted">·</span>
      <b>${ev.provider || ev.channel || sourceLabel(ev.source)}</b>
      ${ev.event_id != null ? html`<span class="muted">이벤트 ${ev.event_id}${doc ? ` · ${doc}` : ''}</span>` : ''}
    </div>
    <dl class="kv">
      ${row('발생 시각', html`${fmtTime(ev.ts)} <span class="muted">(${fmtRelative(ev.ts)})</span>`)}
      ${row('수집 시각', fmtTime(ev.received_at))}
      ${row('PC', ev.host, { host: ev.host })}
      ${row('분류', categoryLabel(ev.category), ev.category ? { category: ev.category } : null)}
      ${row('소스', sourceLabel(ev.source), { source: ev.source })}
      ${row('채널', ev.channel, ev.channel ? { channel: ev.channel } : null)}
      ${row('공급자', ev.provider, ev.provider ? { provider: ev.provider } : null)}
      ${row(ev.source === 'iis' ? 'HTTP 상태' : '이벤트 ID', ev.event_id, ev.event_id != null ? { event_id: ev.event_id } : null)}
      ${row('수준', levelBadge(ev.level), { level: ev.level })}
      ${ev.username ? row('사용자', ev.username, { user: ev.username }) : ''}
      ${ev.username ? row('계정(표기 통일)', html`<code title="HOSP\\kim·kim@hosp.local·KIM 처럼 표기가 달라도 같은 계정으로 찾습니다">${accountKey(ev.username)}</code>`,
        { account: accountKey(ev.username) }) : ''}
      ${ev.src_ip ? row('접속 IP', ev.src_ip, { ip: ev.src_ip }) : ''}
    </dl>
    ${ev.summary ? html`<div class="section-title">요약</div><p class="summary-line">${ev.summary}</p>` : ''}
    ${ev.decoded?.length ? html`<div class="section-title">코드 풀이</div>
      <dl class="kv">${ev.decoded.map((d) => html`<dt>${d.field}</dt><dd><code>${d.value}</code> <span class="ink-2">${d.meaning}</span></dd>`)}</dl>` : ''}
    ${ev.event_id === 4740 && ev.source === 'winevtlog' && ev.id != null ? html`<div class="section-title"
        style="display:flex;justify-content:space-between;align-items:center">
      <span>계정 잠김 원인 <span class="muted" style="font-weight:400">잠김 30분 전~5분 뒤의 로그온 실패</span></span>
      <button class="btn sm" type="button" data-lockout>찾기</button></div><div data-lockout-out></div>` : ''}
    <div class="section-title">메시지</div>
    <pre class="message-box">${ev.message || '(메시지 없음)'}</pre>
    ${ev.id != null ? html`<div class="section-title" style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
      <span>앞뒤 로그 <span class="muted" style="font-weight:400">같은 PC 에서 이 로그 전후</span></span>
      <span class="toolbar"><span class="seg" data-ctx-same><button data-v="host" class="on">같은 PC</button><button data-v="source">같은 소스만</button></span>
        <button class="btn sm" type="button" data-ctx-open>보기</button></span>
    </div>
    <div data-ctx></div>` : ''}
    ${ev.id != null && can('alerts.manage') ? html`<div class="section-title" style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
      <span>규칙 시험 <span class="muted" style="font-weight:400">이 로그가 규칙 조건에 맞는지 조건마다</span></span>
      <span class="toolbar"><select class="select" data-rt-rule aria-label="시험할 규칙"><option value="">규칙 고르기…</option></select>
        <button class="btn sm" type="button" data-rt-run>시험</button></span></div>
    <div data-rt-out></div>` : ''}
    <div class="section-title" style="display:flex;justify-content:space-between;align-items:center">
      <span>원본 데이터 (에이전트가 보낸 그대로)</span>
      <button class="btn sm" data-copy>JSON 복사</button>
    </div>
    <div class="hint-box" style="margin-bottom:8px">${searchContext ? '값을 클릭하면 그 값으로 검색을 좁히거나 제외할 수 있습니다.' : '값을 클릭하면 그 값을 가진 이벤트만 검색합니다.'}</div>
    <div data-picked></div>
    <div data-json></div>`;

  const bind = (root) => root.querySelectorAll('[data-act]').forEach((a) => a.addEventListener('click', (e) => {
    e.preventDefault();
    act(a.dataset.act, JSON.parse(a.dataset.filter));
  }));
  bind(body);
  jsonView(body.querySelector('[data-json]'), ev.raw, (path, value) => {
    const filter = { [`f.${aliasPath(path)}`]: value };
    if (!searchContext) { searchBy(filter); return; }
    // 검색 화면에서는 고를 수 있게: 이 값만 / 좁히기 / 제외
    const picked = body.querySelector('[data-picked]');
    picked.innerHTML = html`<div class="picked-bar"><code>${aliasPath(path)} = ${value}</code>${actions(filter)}</div>`;
    bind(picked);
  });
  if (ev.id != null) contextLogs(body, ev);
  if (body.querySelector('[data-rt-rule]')) ruleTest(body, ev);
  body.querySelector('[data-lockout]')?.addEventListener('click', () => lockoutCause(body.querySelector('[data-lockout-out]'), ev));
  body.querySelector('[data-copy]').addEventListener('click', async (e) => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(ev.raw, null, 2));
      e.target.textContent = '복사됨';
    } catch {
      e.target.textContent = '복사 실패';
    }
  });
}
