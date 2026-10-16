// 이벤트 검색 화면: 필터(검색 문장) → 시간대 분포 → 결과 표 (더 보기).
// 옛 링크(host=…&q=a|b)로 들어오면 문장으로 접어 주소를 바꾼다 (filterState). 같은 주소 = 같은 조건.
import * as api from '../api.js';
import { columnChart, legend, seriesColors, seriesLabel } from '../charts.js';
import { setSearchContext } from '../drawer.js';
import { EVENT_HEAD, bindRows, eventRow } from '../eventtable.js';
import { filterBar, filterState } from '../filterbar.js';
import { parseTerms } from '../querylang.js';
import { errorBox, fmtNum, html, replaceParams, tzOffset } from '../util.js';

export async function mount(root, params) {
  const initial = filterState({ since: '24h', ...params }, { showTime: true });
  let state = initial.state;
  if (initial.changed) replaceParams('events', state);
  let bar = null;
  let items = [];
  let cursor = null;
  let token = 0;

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">이벤트 검색</h1>
        <p class="page-sub">조건을 고르면 바로 검색됩니다. 막대를 누르면 그 시간대만, 행을 누르면 원본 데이터를 봅니다.</p></div>
      <div class="toolbar"><span class="muted num" data-count></span></div>
    </div>
    <div data-filter></div>
    <section class="card" style="margin-bottom:14px"><div class="card-body" data-hist><div class="skeleton" style="height:150px"></div></div></section>
    <section class="card">
      <div class="table-wrap"><table class="table ev-table"><thead>${EVENT_HEAD}</thead><tbody data-rows></tbody></table></div>
      <div data-foot style="padding:12px;text-align:center"></div>
    </section>`;

  const rowsEl = root.querySelector('[data-rows]');
  const footEl = root.querySelector('[data-foot]');
  bindRows(rowsEl, (k) => items[Number(k)]);

  function renderFoot() {
    footEl.innerHTML = cursor
      ? html`<button class="btn" data-more>더 보기</button>`
      : html`<span class="muted">${items.length ? '마지막 결과입니다' : '조건에 맞는 이벤트가 없습니다'}</span>`;
    footEl.querySelector('[data-more]')?.addEventListener('click', loadMore);
  }

  async function loadMore() {
    const my = token;
    const page = await api.get('/api/events', { ...state, limit: 100, cursor });
    if (my !== token) return;
    const start = items.length;
    items = items.concat(page.items);
    cursor = page.next_cursor;
    rowsEl.insertAdjacentHTML('beforeend', String(html`${page.items.map((ev, i) => eventRow(ev, start + i))}`));
    renderFoot();
  }

  async function load() {
    const my = ++token;
    rowsEl.innerHTML = '';
    // 문장이 틀렸으면 서버에 묻지 않는다 (입력 칸이 틀린 곳을 보여 준다) — 옛 링크·손으로 고친 주소로 들어온 경우
    try { parseTerms(state.query ?? ''); } catch {
      footEl.innerHTML = html`<span class="muted">검색 문장을 고치면 결과가 보입니다.</span>`;
      root.querySelector('[data-count]').textContent = '';
      return;
    }
    footEl.innerHTML = '<div class="skeleton" style="height:120px"></div>';
    try {
      const [series, count, page] = await Promise.all([
        api.get('/api/stats/timeseries', { ...state, group: 'level', buckets: 60, tz_offset: tzOffset() }),
        api.get('/api/stats/count', state),
        api.get('/api/events', { ...state, limit: 100 }),
      ]);
      if (my !== token) return;
      root.querySelector('[data-count]').textContent = `${fmtNum(count.current)}건`;

      const colors = seriesColors('level', series.series.map((s) => s.key));
      const ser = series.series.map((s) => ({ key: s.key, label: seriesLabel('level', s.key), color: colors[s.key], values: s.values, total: s.total }));
      const hist = root.querySelector('[data-hist]');
      hist.innerHTML = html`${legend(ser)}<div data-chart></div>`;
      columnChart(hist.querySelector('[data-chart]'), {
        buckets: series.buckets, intervalSec: series.interval_sec, series: [...ser].reverse(), height: 150,
        onSelect: (range) => { state = { ...state, ...range }; replaceParams('events', state); bar?.setState(state); load(); },
      });

      items = page.items;
      cursor = page.next_cursor;
      rowsEl.innerHTML = items.length
        ? html`${items.map((ev, i) => eventRow(ev, i))}`
        : html`<tr><td colspan="6" class="empty" style="padding:48px 16px;">조건에 일치하는 이벤트가 없습니다. 상단 필터를 조정해보세요.</td></tr>`;
      renderFoot();
    } catch (err) {
      if (my !== token) return;
      footEl.innerHTML = errorBox(err);
      bar?.showServerError(err);   // 문장 오류면 입력 칸에서 틀린 곳을 칠한다
    }
  }

  filterBar(root.querySelector('[data-filter]'), state, {
    onChange: (next) => { state = next; replaceParams('events', state); load(); },
  }).then((b) => { bar = b; });
  // 상세 패널의 '좁히기·제외'가 이 화면의 문장을 고치게
  setSearchContext({ query: () => bar?.query ?? state.query ?? '', apply: (text) => bar?.applySentence(text) });
  load();
  return () => { token++; bar?.destroy(); setSearchContext(null); };
}
