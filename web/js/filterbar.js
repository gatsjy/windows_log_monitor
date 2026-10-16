// 검색/실시간 화면 상단의 필터 막대 (B-01: 검색 문장이 조건의 정본).
// 상태: { since, until, query, ...옛 파라미터 중 문장으로 옮기지 못한 것 }. 드롭다운·수준 칩은 문장을 보여 주고 고치는 창이다:
//   문장 → 컨트롤: 그 키의 포함 조건이 값 하나면 그 값, 아니면 '문장 조건'  /  컨트롤 → 문장: querylang.setKey·setLevels
// 화면에 들어올 때 옛 링크(host=…&q=a|b&f.X=1)는 filterState() 가 문장으로 접는다 (뜻이 똑같이 옮겨지는 것만).
import * as api from './api.js';
import { LEVELS, categoryLabel, levelIcon, sourceLabel } from './levels.js';
import { sinceDate } from './livefilter.js';
import { KEY_LABELS, queryBox } from './querybox.js';
import { foldParams, parseTerms, setKey, setLevels } from './querylang.js';
import { TIME_RANGES, fmtTime, html, qs, toast } from './util.js';

const KNOWN_KEYS = ['since', 'until', 'host', 'source', 'category', 'channel', 'provider', 'user', 'ip', 'level', 'event_id', 'q', 'query'];
const SELECT_KEYS = ['host', 'category', 'channel'];
const SENTENCE = '__sentence__';
const ALL_LEVELS = [1, 2, 3, 4, 5];

function clean(state) {
  return Object.fromEntries(Object.entries(state).filter(([, v]) => v !== undefined && v !== null && v !== ''));
}

export const isFilterKey = (k) => KNOWN_KEYS.includes(k) || k.startsWith('f.');

/** 화면 주소의 파라미터 → 필터 상태 (옛 파라미터를 문장으로 접음). 바뀌었으면 changed */
export function filterState(params, { showTime = true } = {}) {
  const picked = Object.fromEntries(Object.entries(params).filter(([k]) => isFilterKey(k) && (showTime || (k !== 'since' && k !== 'until'))));
  const { query, rest } = foldParams(picked);
  const state = clean({ ...rest, query });
  const changed = JSON.stringify(state) !== JSON.stringify(clean(picked));
  return { state, changed };
}

/** 문장 → 수준 칩에 켤 수준 (포함 조건들의 교집합 − 제외). 수준 조건이 없으면 null (= 전체, 칩 모두 꺼짐) */
function levelsOf(terms) {
  const level = terms.filter((t) => t.key === 'level');
  if (!level.length) return null;
  let allowed = [...ALL_LEVELS];
  for (const t of level.filter((x) => !x.neg)) allowed = allowed.filter((v) => t.values.includes(v));
  const excluded = new Set(level.filter((x) => x.neg).flatMap((x) => x.values));
  return allowed.filter((v) => !excluded.has(v));
}

/** 문장 → 드롭다운 값: '' (조건 없음) | 값 하나 | SENTENCE (여러 값·여러 조건) */
function selectOf(terms, key) {
  const inc = terms.filter((t) => t.key === key && !t.neg);
  const exc = terms.filter((t) => t.key === key && t.neg).reduce((n, t) => n + t.values.length, 0);
  if (!inc.length) return { value: '', excluded: exc };
  if (inc.length === 1 && inc[0].values.length === 1) return { value: inc[0].values[0], excluded: exc };
  return { value: SENTENCE, excluded: exc, count: inc.length };
}

/**
 * @param {HTMLElement} el
 * @param {object} initial  filterState() 의 state
 * @param {{showTime?: boolean, onChange: (state) => void}} opt
 * @returns {Promise<{setState(state), showServerError(err), terms(): any[]|null, destroy()}>}
 */
export async function filterBar(el, initial, { showTime = true, onChange }) {
  let state = clean(initial);
  el.innerHTML = '<div class="card filterbar"><div class="skeleton" style="height:32px;flex:1"></div></div>';

  const [agents, channels, meta] = await Promise.all([
    api.get('/api/agents').catch(() => ({ items: [] })),
    api.get('/api/stats/top', { field: 'channel', since: '7d', limit: 30 }).catch(() => ({ items: [] })),
    api.get('/api/meta').catch(() => ({ sources: [] })),
  ]);
  const agentStatusMap = new Map((agents.items || []).map((a) => [a.host, a.status]));
  const hostLabel = (h) => {
    const st = agentStatusMap.get(h);
    const dot = st === 'online' ? '🟢 ' : st === 'stale' ? '🟡 ' : st === 'offline' ? '⚪ ' : '';
    return dot + h;
  };
  const lists = {
    host: agents.items.map((a) => a.host),
    category: Object.keys(meta.categories || {}),
    channel: channels.items.map((c) => c.value).filter(Boolean),
  };
  const sources = Object.keys(meta.sources || {});

  el.innerHTML = html`<div class="card filterbar">
    <div class="fb-query" data-query></div>
    <div class="fb-controls" data-controls></div>
  </div>`;
  const controls = el.querySelector('[data-controls]');
  let ready = false;   // queryBox 가 만들어지면서 한 번 해석을 부른다 — box 가 생긴 뒤에만 컨트롤을 그린다
  const box = queryBox(el.querySelector('[data-query]'), {
    value: state.query ?? '',
    since: () => state.since,
    slashShortcut: true,
    fieldBudget: () => 10 - Object.keys(state).filter((k) => k.startsWith('f.')).length,
    suggestions: () => ({ host: lists.host, channel: lists.channel, source: sources }),
    onCommit: (text) => commit({ query: text }),
    onAnalyze: () => { if (ready) renderControls(); },
  });
  ready = true;

  function emit() { onChange({ ...state }); }

  function commit(patch) {
    state = clean({ ...state, ...patch });
    renderControls();
    emit();
  }

  /** 컨트롤이 문장을 고친다. 여러 조건·여러 값·제외를 한꺼번에 바꿨으면 되돌리기 토스트 */
  function editSentence(next, label, touched) {
    const before = box.committed;
    box.set(next, { commit: true });
    if (touched.length > 1 || touched.some((t) => t.neg || t.values.length > 1)) {
      toast(`${label} 조건을 바꿨습니다.`, { action: { label: '되돌리기', onClick: () => box.set(before, { commit: true }) }, duration: 6000 });
    }
  }

  function options(key, current, allLabel, label = (v) => v) {
    const values = lists[key];
    const list = current.value && current.value !== SENTENCE && !values.includes(current.value) ? [current.value, ...values] : values;
    const all = current.excluded ? `${allLabel} (제외 ${current.excluded})` : allLabel;
    return html`<option value="" ${current.value === '' ? 'selected' : ''}>${all}</option>
      ${current.value === SENTENCE ? html`<option value="${SENTENCE}" selected>문장 조건 (${current.count}개)</option>` : ''}
      ${list.map((v) => html`<option value="${v}" ${v === current.value ? 'selected' : ''}>${label(v)}</option>`)}`;
  }

  function renderControls() {
    let terms = null;
    try { terms = parseTerms(box.value); } catch { /* 문장이 틀리면 컨트롤을 잠근다 */ }
    const locked = !terms;
    const lockTitle = locked ? '문장 오류를 먼저 고치세요' : '';
    const levels = terms ? levelsOf(terms) : null;
    const custom = state.until || (state.since && !TIME_RANGES.some(([k]) => k === state.since));
    const leftovers = Object.entries(state).filter(([k]) => !['since', 'until', 'query'].includes(k));
    const sel = (key) => (terms ? selectOf(terms, key) : { value: '', excluded: 0 });
    controls.innerHTML = html`
      <div class="fb-group fb-selects">
        ${showTime ? html`<select class="select" data-k="since" aria-label="기간">
          ${custom ? html`<option value="" selected>사용자 지정 구간</option>` : ''}
          ${TIME_RANGES.map(([v, label]) => html`<option value="${v}" ${!custom && state.since === v ? 'selected' : ''}>${label}</option>`)}
        </select>` : ''}
        <select class="select" data-sel="host" aria-label="PC" ${locked ? 'disabled' : ''} title="${lockTitle}">${options('host', sel('host'), '전체 PC', hostLabel)}</select>
        <select class="select" data-sel="category" aria-label="분류" ${locked ? 'disabled' : ''} title="${lockTitle}">${options('category', sel('category'), '전체 분류', categoryLabel)}</select>
        <select class="select" data-sel="channel" aria-label="채널" ${locked ? 'disabled' : ''} title="${lockTitle}">${options('channel', sel('channel'), '전체 채널')}</select>
      </div>
      <div class="fb-group fb-levels" role="group" aria-label="수준">
        ${Object.entries(LEVELS).map(([lv, m]) => {
          const on = Boolean(levels?.includes(Number(lv)));
          return html`<button type="button" class="chip ${on ? 'on' : ''}" data-level="${lv}" aria-pressed="${on}" ${locked ? 'disabled' : ''} title="${lockTitle}">${levelIcon(Number(lv))}${m.label}</button>`;
        })}
        ${levels && !levels.length ? html`<span class="muted fb-hint">수준 조건이 서로 맞지 않습니다</span>` : ''}
      </div>
      <div class="fb-group fb-actions">
        ${showTime ? html`<button type="button" class="btn ghost" data-copy title="지금 보고 있는 구간으로 고정한 링크">링크 복사</button>` : ''}
        <button type="button" class="btn ghost" data-reset>초기화</button>
      </div>
      ${custom && state.until || leftovers.length ? html`<div class="fb-group fb-active">
        ${custom && state.until ? html`<span class="chip on">${fmtTime(state.since, { seconds: false })} – ${fmtTime(state.until, { seconds: false, date: false })}
          <button type="button" class="btn ghost sm x" data-clear-range aria-label="구간 해제">✕</button></span>` : ''}
        ${leftovers.map(([k, v]) => html`<span class="chip on" title="문장으로 옮기지 못한 옛 조건 (서버는 그대로 적용)">${k.startsWith('f.') ? `원본 ${k.slice(2)}` : KEY_LABELS[k === 'q' ? 'msg' : k] ?? k} = ${k === 'source' ? sourceLabel(v) : v}
          <button type="button" class="btn ghost sm x" data-remove="${k}" aria-label="해제">✕</button></span>`)}
      </div>` : ''}`;

    controls.querySelector('[data-k="since"]')?.addEventListener('change', (e) => commit({ since: e.target.value, until: '' }));
    controls.querySelectorAll('select[data-sel]').forEach((s) => s.addEventListener('change', () => {
      const key = s.dataset.sel;
      if (s.value === SENTENCE) return;
      const cur = parseTerms(box.value);
      const touched = cur.filter((t) => t.key === key && (!t.neg || t.values.includes(s.value)));
      editSentence(setKey(box.value, key, s.value), KEY_LABELS[key], touched);
    }));
    controls.querySelectorAll('[data-level]').forEach((b) => b.addEventListener('click', () => {
      const cur = parseTerms(box.value);
      const now = new Set(levelsOf(cur) ?? []);
      const lv = Number(b.dataset.level);
      now.has(lv) ? now.delete(lv) : now.add(lv);
      editSentence(setLevels(box.value, [...now]), '수준', cur.filter((t) => t.key === 'level'));
    }));
    controls.querySelectorAll('[data-remove]').forEach((b) => b.addEventListener('click', () => commit({ [b.dataset.remove]: '' })));
    controls.querySelector('[data-clear-range]')?.addEventListener('click', () => commit({ since: '24h', until: '' }));
    controls.querySelector('[data-reset]').addEventListener('click', () => {
      state = showTime ? { since: '24h' } : {};
      box.set('');
      renderControls();
      emit();
    });
    controls.querySelector('[data-copy]')?.addEventListener('click', async () => {
      // 상대 기간(24h)은 나중에 열면 다른 결과 → 지금 보고 있는 구간으로 고정해서 복사
      const until = state.until ? new Date(state.until) : new Date();
      const since = sinceDate(state.since || '24h');
      const params = { ...state, since: since.toISOString(), until: until.toISOString() };
      const url = `${location.origin}${location.pathname}#/events?${qs(params)}`;
      try {
        await navigator.clipboard.writeText(url);
        toast('지금 보고 있는 구간으로 고정한 링크를 복사했습니다.', { type: 'success' });
      } catch {
        toast('클립보드에 복사하지 못했습니다. 주소창의 주소를 복사하세요.', { type: 'error' });
      }
    });
  }

  renderControls();

  return {
    setState(next) {
      state = clean(next);
      if ((state.query ?? '') !== box.committed) box.set(state.query ?? '');
      renderControls();
    },
    /** 서버가 400 으로 거절: 문장 오류면 입력 칸에 위치를 칠한다 */
    showServerError(err) {
      if (err?.queryError) box.showServerError(err.queryError, state.query ?? '');
    },
    /** 상세 패널의 '좁히기·제외': 문장에 조건 하나를 더해 바로 확정 */
    applySentence(text) { box.set(text, { commit: true }); },
    get query() { return box.committed; },
    destroy() { box.destroy(); },
  };
}
