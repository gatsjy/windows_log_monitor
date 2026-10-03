// 숫자 카드.
//   metric: "count"(기본) | "agents" | "rate"
//   query:  이벤트 조건 (count 일 때)
//   up_is_good: true 면 증가를 초록, false 면 빨강, 생략하면 중립
//   color:  스파크라인 색 (예: "var(--critical)")
// 실시간: count 는 새 이벤트가 오면 숫자·스파크라인이 바로 올라가고, rate 는 브라우저가 받은 속도로 갱신된다.
import * as api from '../api.js';
import { sparkline } from '../charts.js';
import { bump } from '../livefilter.js';
import { statusBadge } from '../levels.js';
import { fmtCompact, fmtNum, html, navigate, rangeLabel, tzOffset } from '../util.js';

function deltaHtml(current, previous, upIsGood, since) {
  if (previous == null) return '';
  const diff = current - previous;
  let text;
  if (previous === 0) text = current === 0 ? '변화 없음' : '신규';
  else text = `${diff >= 0 ? '▲' : '▼'} ${Math.abs((diff / previous) * 100).toFixed(diff === 0 ? 0 : 1)}%`;
  let tone = 'flat';
  if (diff !== 0 && upIsGood != null) tone = (diff > 0) === upIsGood ? 'good' : 'bad';
  return html`<span class="delta ${tone}">${text}</span><span>이전 ${rangeLabel(since).replace('최근 ', '')} 대비 (${fmtNum(previous)})</span>`;
}

export default {
  label: '숫자 카드',
  async render(body, cfg, ctx) {
    const metric = cfg.metric || 'count';
    body._live = null;

    if (metric === 'agents') {
      const { agents } = await api.get('/api/stats/summary');
      body.innerHTML = html`<div class="stat clickable" data-go>
        <div class="stat-value">${agents.online}<small>/ ${agents.total}대</small></div>
        <div class="stat-meta">${statusBadge('online')}
          ${agents.stale ? html`<span>·</span>${statusBadge('stale')} ${agents.stale}` : ''}
          ${agents.offline ? html`<span>·</span>${statusBadge('offline')} ${agents.offline}` : ''}</div></div>`;
      body.querySelector('[data-go]').addEventListener('click', () => navigate('agents'));
      return;
    }

    if (metric === 'rate') {
      const s = await api.get('/api/stats/summary');
      body.innerHTML = html`<div class="stat">
        <div class="stat-value"><span data-value>${fmtCompact(Math.round(s.ingest_per_min))}</span><small>건/분</small></div>
        <div class="stat-meta">최근 1분 수신 · 5분 평균 ${fmtNum(Math.round(s.ingest_per_min_5m))}건/분</div></div>`;
      body._live = { rate: true };
      return;
    }

    const q = ctx.query(cfg);
    const [count, series] = await Promise.all([
      api.get('/api/stats/count', { ...q, compare: true }),
      api.get('/api/stats/timeseries', { ...q, group: 'none', buckets: 24, tz_offset: tzOffset() }),
    ]);
    const values = series.series[0]?.values ?? series.buckets.map(() => 0);
    const color = cfg.color || 'var(--s1)';
    body.innerHTML = html`<div class="stat clickable" data-go title="클릭: 이벤트 검색">
      <div class="stat-value"><span data-value>${fmtNum(count.current)}</span><small>건</small></div>
      <div class="stat-meta">${deltaHtml(count.current, count.previous, cfg.up_is_good, q.since)}</div>
      <div class="spark">${sparkline(values, color)}</div></div>`;
    body.querySelector('[data-go]').addEventListener('click', () => ctx.drill(cfg.query || {}));
    body._live = { count: count.current, values, color };
  },

  live(body, cfg, ctx, events) {
    const st = body._live;
    if (!st) return;
    if (st.rate) {
      body.querySelector('[data-value]').textContent = fmtCompact(Math.round(ctx.ratePerMin()));
      return;
    }
    if (!events.length) return;
    st.count += events.length;
    st.values[st.values.length - 1] += events.length;
    body.querySelector('[data-value]').textContent = fmtNum(st.count);
    body.querySelector('.spark').innerHTML = sparkline(st.values, st.color);
    bump(body.querySelector('.stat-value'));
  },
};
