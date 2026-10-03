// 시간대별 누적 막대.
//   group: "level"(기본) | "channel" | "host" | "source" | "provider" | "event_id" | "none" | "f.<원본경로>"
//   buckets: 막대 개수 목표 (기본 48), height: 높이 px (기본 200)
// 실시간: 새 이벤트가 오면 해당 구간 막대가 바로 자란다. 새 구간이 시작되거나 새 계열이 나타나면 전체 다시 조회.
import * as api from '../api.js';
import { columnChart, legend, seriesColors, seriesLabel } from '../charts.js';
import { fieldValue } from '../livefilter.js';
import { html, tzOffset } from '../util.js';

function draw(body, cfg, ctx, st) {
  const series = st.series.map((s) => ({ ...s, label: seriesLabel(st.group, s.key), color: st.colors[s.key] }));
  body.innerHTML = html`${legend(series)}<div data-chart></div>`;
  // 수준별일 때는 심각/오류가 위에 오도록 쌓는다 (서버는 1→5 순서)
  const stack = st.group === 'level' ? [...series].reverse() : series;
  columnChart(body.querySelector('[data-chart]'), {
    buckets: st.buckets,
    intervalSec: st.intervalSec,
    series: stack,
    height: cfg.height || 200,
    onSelect: (range) => ctx.drill({ ...(cfg.query || {}), ...range }),
  });
}

export default {
  label: '시계열 막대',
  async render(body, cfg, ctx) {
    const group = cfg.group || 'level';
    const data = await api.get('/api/stats/timeseries', {
      ...ctx.query(cfg), group, buckets: cfg.buckets || 48, tz_offset: tzOffset(),
    });
    const st = {
      group,
      buckets: data.buckets,
      intervalSec: data.interval_sec,
      series: data.series.map((s) => ({ key: s.key, values: [...s.values], total: s.total })),
      colors: seriesColors(group, data.series.map((s) => s.key)),
    };
    body._live = st;
    draw(body, cfg, ctx, st);
  },

  live(body, cfg, ctx, events) {
    const st = body._live;
    if (!st || !events.length || !st.buckets.length) return;
    const t0 = new Date(st.buckets[0]).getTime();
    const step = st.intervalSec * 1000;
    const now = Date.now();
    for (const ev of events) {
      const t = new Date(ev.ts).getTime();
      if (t > now + 60_000) continue; // PC 시계가 앞선 이벤트는 무시 (다음 동기화 때 반영)
      const i = Math.floor((t - t0) / step);
      if (i < 0) continue;
      if (i >= st.buckets.length) { ctx.resync(body); return; } // 새 구간 시작
      const key = fieldValue(st.group, ev) ?? '';
      const target = st.series.find((s) => s.key === key) || st.series.find((s) => s.key === '__other__');
      if (!target) { ctx.resync(body); return; } // 처음 보는 계열 → 색/순서를 서버 기준으로 다시
      target.values[i] += 1;
      target.total += 1;
    }
    draw(body, cfg, ctx, st);
  },
};
