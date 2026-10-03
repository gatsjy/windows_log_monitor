// 실시간 로그: 서버가 받는 즉시 SSE(/api/live)로 밀어주는 이벤트를 위에서부터 쌓는다.
import { EVENT_HEAD, bindRows, eventRow } from '../eventtable.js';
import { filterBar, isFilterKey } from '../filterbar.js';
import { fmtNum, html, qs, replaceParams } from '../util.js';

const MAX_ROWS = 300;

export async function mount(root, params) {
  let state = Object.fromEntries(Object.entries(params).filter(([k]) => isFilterKey(k) && k !== 'since' && k !== 'until'));
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
      <div class="table-wrap"><table class="table"><thead>${EVENT_HEAD}</thead><tbody data-rows></tbody></table></div>
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
    source = new EventSource(`/api/live?${qs(state)}`);
    source.onopen = () => setStatus('', paused ? '일시정지' : '수신 중');
    source.onerror = () => setStatus('bad', '재연결 중…');
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

  filterBar(root.querySelector('[data-filter]'), state, {
    showTime: false,
    onChange: (next) => { state = next; replaceParams('live', state); connect(); },
  });
  connect();
  const timer = setInterval(updateRate, 5000);

  return () => { source?.close(); clearInterval(timer); };
}
