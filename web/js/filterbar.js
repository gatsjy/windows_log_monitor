// 검색/실시간 화면 상단의 필터 막대.
// 상태는 평범한 객체: { since, until, host, source, channel, level: '1,2', event_id, q, 'f.경로': 값 }
import * as api from './api.js';
import { LEVELS, categoryLabel, levelIcon, sourceLabel } from './levels.js';
import { TIME_RANGES, fmtTime, html } from './util.js';

const KNOWN_KEYS = ['since', 'until', 'host', 'source', 'category', 'channel', 'provider', 'user', 'ip', 'level', 'event_id', 'q'];

function clean(state) {
  return Object.fromEntries(Object.entries(state).filter(([, v]) => v !== undefined && v !== null && v !== ''));
}

/**
 * @param {HTMLElement} el
 * @param {object} initial
 * @param {{showTime?: boolean, onChange: (state) => void}} opt
 */
export async function filterBar(el, initial, { showTime = true, onChange }) {
  let state = clean(initial);
  el.innerHTML = '<div class="card filterbar"><div class="skeleton" style="height:32px;flex:1"></div></div>';

  const [agents, channels, meta] = await Promise.all([
    api.get('/api/agents').catch(() => ({ items: [] })),
    api.get('/api/stats/top', { field: 'channel', since: '7d', limit: 30 }).catch(() => ({ items: [] })),
    api.get('/api/meta').catch(() => ({ sources: [] })),
  ]);
  const hosts = agents.items.map((a) => a.host);
  const channelNames = channels.items.map((c) => c.value).filter(Boolean);

  function update(patch) {
    state = clean({ ...state, ...patch });
    render();
    onChange({ ...state });
  }

  function options(values, current, allLabel, label = (v) => v) {
    const list = current && !values.includes(current) ? [current, ...values] : values;
    return html`<option value="">${allLabel}</option>${list.map((v) =>
      html`<option value="${v}" ${v === current ? 'selected' : ''}>${label(v)}</option>`)}`;
  }

  function render() {
    const levels = new Set((state.level || '').split(',').filter(Boolean));
    const custom = state.until || (state.since && !TIME_RANGES.some(([k]) => k === state.since));
    const fieldChips = Object.entries(state).filter(([k]) => k.startsWith('f.'));
    el.innerHTML = html`<div class="card filterbar">
      ${showTime ? html`<select class="select" data-k="since" aria-label="기간">
        ${custom ? html`<option value="" selected>사용자 지정 구간</option>` : ''}
        ${TIME_RANGES.map(([v, label]) => html`<option value="${v}" ${!custom && state.since === v ? 'selected' : ''}>${label}</option>`)}
      </select>` : ''}
      <select class="select" data-k="host" aria-label="PC">${options(hosts, state.host, '전체 PC')}</select>
      <select class="select" data-k="category" aria-label="분류">${options(Object.keys(meta.categories || {}), state.category, '전체 분류', categoryLabel)}</select>
      <select class="select" data-k="channel" aria-label="채널">${options(channelNames, state.channel, '전체 채널')}</select>
      <span class="divider"></span>
      ${Object.entries(LEVELS).map(([lv, m]) => html`
        <button type="button" class="chip ${levels.has(lv) ? 'on' : ''}" data-level="${lv}" aria-pressed="${levels.has(lv)}">${levelIcon(Number(lv))}${m.label}</button>`)}
      <span class="divider"></span>
      <input class="input" style="width:150px" data-text="event_id" placeholder="이벤트 ID (4625,4740)" value="${state.event_id ?? ''}">
      <input class="input grow" data-text="q" placeholder="메시지 검색 (Enter, 여러 단어는 a|b)" value="${state.q ?? ''}">
      ${custom && state.until ? html`<span class="chip on">${fmtTime(state.since, { seconds: false })} – ${fmtTime(state.until, { seconds: false, date: false })}
        <button type="button" class="btn ghost sm x" data-clear-range aria-label="구간 해제">✕</button></span>` : ''}
      ${[['provider', '공급자'], ['source', '소스'], ['user', '사용자'], ['ip', 'IP']].filter(([k]) => state[k]).map(([k, label]) =>
        html`<span class="chip on">${label}: ${k === 'source' ? sourceLabel(state[k]) : state[k]}<button type="button" class="btn ghost sm x" data-remove="${k}" aria-label="해제">✕</button></span>`)}
      ${fieldChips.map(([k, v]) => html`<span class="chip on" title="원본 필드 조건">${k.slice(2)} = ${v}
        <button type="button" class="btn ghost sm x" data-remove="${k}" aria-label="해제">✕</button></span>`)}
      <button type="button" class="btn ghost" data-reset>초기화</button>
    </div>`;

    el.querySelectorAll('select[data-k]').forEach((s) => s.addEventListener('change', () => {
      const patch = { [s.dataset.k]: s.value };
      if (s.dataset.k === 'since') patch.until = '';
      update(patch);
    }));
    el.querySelectorAll('[data-level]').forEach((b) => b.addEventListener('click', () => {
      const next = new Set(levels);
      next.has(b.dataset.level) ? next.delete(b.dataset.level) : next.add(b.dataset.level);
      update({ level: [...next].sort().join(',') });
    }));
    el.querySelectorAll('[data-text]').forEach((input) => {
      const commit = () => { if ((state[input.dataset.text] ?? '') !== input.value.trim()) update({ [input.dataset.text]: input.value.trim() }); };
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') commit(); });
      input.addEventListener('change', commit);
    });
    el.querySelectorAll('[data-remove]').forEach((b) => b.addEventListener('click', () => update({ [b.dataset.remove]: '' })));
    el.querySelector('[data-clear-range]')?.addEventListener('click', () => update({ since: '24h', until: '' }));
    el.querySelector('[data-reset]').addEventListener('click', () => {
      state = showTime ? { since: '24h' } : {};
      render();
      onChange({ ...state });
    });
  }

  render();
}

export const isFilterKey = (k) => KNOWN_KEYS.includes(k) || k.startsWith('f.');
