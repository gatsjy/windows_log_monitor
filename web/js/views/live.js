// 실시간 로그: 서버가 받는 즉시 SSE(/api/live)로 밀어주는 이벤트를 위에서부터 쌓는다.
// 조건(검색 문장)은 서버가 거른다(filters.matches). 조건을 바꾸면 이미 보이는 행도 같은 규칙(querylang.compileQuery)으로 다시 거른다.
import * as api from '../api.js';
import { setSearchContext } from '../drawer.js';
import { EVENT_HEAD, bindRows, eventRow } from '../eventtable.js';
import { filterBar, filterState } from '../filterbar.js';
import { compileQuery } from '../querylang.js';
import { fmtNum, html, qs, replaceParams } from '../util.js';

const MAX_ROWS = 300;

export async function mount(root, params) {
  const initial = filterState(params, { showTime: false });
  let state = initial.state;
  if (initial.changed) replaceParams('live', state);
  let bar = null;
  let source = null;
  let paused = false;
  let pending = [];
  let seq = 0;
  let total = 0;
  const events = new Map(); // key → event (상세 보기용)
  const arrivals = [];      // [time, count] — 분당 수신량 계산

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">실시간 로그</h1>
        <p class="page-sub">에이전트가 보내는 로그가 도착하는 즉시 표시됩니다. 행을 누르면 원본 데이터를 봅니다.</p></div>
      <div class="toolbar">
        <span class="live-badge" data-status><span class="pulse off"></span>연결 중…</span>
        <span class="live-badge num" data-rate>0건/분</span>
        <button class="btn" data-pause>일시정지</button>
        <button class="btn ghost" data-clear>지우기</button>
      </div>
    </div>
    <div data-filter></div>
    <section class="card">
      <div class="table-wrap"><table class="table ev-table"><thead>${EVENT_HEAD}</thead><tbody data-rows></tbody></table></div>
      <div class="empty" data-empty>새 로그를 기다리는 중…</div>
    </section>`;

  const rowsEl = root.querySelector('[data-rows]');
  const emptyEl = root.querySelector('[data-empty]');
  const statusEl = root.querySelector('[data-status]');
  const rateEl = root.querySelector('[data-rate]');
  const pauseBtn = root.querySelector('[data-pause]');
  bindRows(rowsEl, (k) => events.get(k));

  function setStatus(kind, text) {
    statusEl.innerHTML = html`<span class="pulse ${kind}"></span>${text}`;
  }

  function addRows(batch) {
    const ordered = [...batch].sort((a, b) => a.ts.localeCompare(b.ts));
    let rows = '';
    for (const ev of ordered) {
      const key = String(++seq);
      events.set(key, ev);
      rows = String(eventRow(ev, key, { flash: true })) + rows;
    }
    rowsEl.insertAdjacentHTML('afterbegin', rows);
    while (rowsEl.children.length > MAX_ROWS) {
      events.delete(rowsEl.lastElementChild.dataset.k);
      rowsEl.lastElementChild.remove();
    }
    emptyEl.hidden = rowsEl.children.length > 0;
  }

  function updateRate() {
    const now = Date.now();
    while (arrivals.length && arrivals[0][0] < now - 60_000) arrivals.shift();
    const perMin = arrivals.reduce((a, [, n]) => a + n, 0);
    rateEl.textContent = `${fmtNum(perMin)}건/분 · 누적 ${fmtNum(total)}`;
  }

  function connect() {
    source?.close();
    setStatus('off', '연결 중…');
    const mine = new EventSource(`/api/live?${qs(state)}`);
    source = mine;
    source.onopen = () => setStatus('', paused ? '일시정지' : '수신 중');
    source.onerror = async () => {
      if (mine.readyState !== EventSource.CLOSED) { setStatus('bad', '재연결 중…'); return; }
      // 400 등으로 끊김(EventSource 는 본문을 못 읽는다) → 해석 API 로 문장 오류 위치를 받아 보여 준다
      try {
        await api.get('/api/search/parse', state);
        setStatus('bad', '연결이 끊겼습니다 — 새로고침하세요');
      } catch (err) {
        setStatus('bad', err.queryError ? '검색 조건 오류' : '연결이 끊겼습니다');
        bar?.showServerError(err);
      }
    };
    source.addEventListener('events', (e) => {
      const batch = JSON.parse(e.data);
      total += batch.length;
      arrivals.push([Date.now(), batch.length]);
      updateRate();
      if (paused) {
        pending = pending.concat(batch).slice(-MAX_ROWS);
        pauseBtn.textContent = `재개 (${fmtNum(pending.length)}건 대기)`;
        return;
      }
      addRows(batch);
    });
  }

  pauseBtn.addEventListener('click', () => {
    paused = !paused;
    pauseBtn.textContent = paused ? '재개' : '일시정지';
    setStatus(paused ? 'off' : '', paused ? '일시정지' : '수신 중');
    if (!paused && pending.length) { addRows(pending); pending = []; }
  });
  root.querySelector('[data-clear]').addEventListener('click', () => {
    rowsEl.innerHTML = '';
    events.clear();
    emptyEl.hidden = false;
  });

  // 조건이 바뀌면 이미 보이는 행·대기 중인 행도 새 조건으로 거른다 (서버와 같은 규칙)
  function refilter() {
    const keep = compileQuery(state);
    for (const tr of [...rowsEl.children]) {
      if (!keep(events.get(tr.dataset.k))) { events.delete(tr.dataset.k); tr.remove(); }
    }
    pending = pending.filter(keep);
    emptyEl.hidden = rowsEl.children.length > 0;
  }

  filterBar(root.querySelector('[data-filter]'), state, {
    showTime: false,
    onChange: (next) => { state = next; replaceParams('live', state); refilter(); connect(); },
  }).then((b) => { bar = b; });
  setSearchContext({ query: () => bar?.query ?? state.query ?? '', apply: (text) => bar?.applySentence(text) });
  connect();
  const timer = setInterval(updateRate, 5000);

  return () => { source?.close(); clearInterval(timer); bar?.destroy(); setSearchContext(null); };
}
