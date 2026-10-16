// 오른쪽에서 열리는 상세 패널 + 이벤트 상세 보기.
import * as api from './api.js';
import { eventDoc } from './catalog.js';
import { jsonView } from './jsonview.js';
import { categoryLabel, levelBadge, sourceLabel } from './levels.js';
import { addTerm, formatTerm, parseTerms } from './querylang.js';
import { errorBox, fmtRelative, fmtTime, html, navigate } from './util.js';

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
      ${ev.src_ip ? row('접속 IP', ev.src_ip, { ip: ev.src_ip }) : ''}
    </dl>
    <div class="section-title">메시지</div>
    <pre class="message-box">${ev.message || '(메시지 없음)'}</pre>
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
    const filter = { [`f.${path}`]: value };
    if (!searchContext) { searchBy(filter); return; }
    // 검색 화면에서는 고를 수 있게: 이 값만 / 좁히기 / 제외
    const picked = body.querySelector('[data-picked]');
    picked.innerHTML = html`<div class="picked-bar"><code>${path} = ${value}</code>${actions(filter)}</div>`;
    bind(picked);
  });
  body.querySelector('[data-copy]').addEventListener('click', async (e) => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(ev.raw, null, 2));
      e.target.textContent = '복사됨';
    } catch {
      e.target.textContent = '복사 실패';
    }
  });
}
