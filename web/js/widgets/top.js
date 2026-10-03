// 상위 N 개 값 (가로 막대 목록). 막대를 누르면 그 값으로 이벤트 검색.
//   field: "host"(기본) | "channel" | "provider" | "source" | "event_id" | "level" | "f.<원본경로>"
//   limit: 개수 (기본 8), color: 막대 색 (기본 var(--s1))
// 실시간: 새 이벤트의 값만큼 막대가 늘고 순위가 바로 바뀐다.
import * as api from '../api.js';
import { barList } from '../charts.js';
import { eventDoc } from '../catalog.js';
import { fieldValue } from '../livefilter.js';
import { categoryLabel, levelBadge, levelColor, sourceLabel } from '../levels.js';

const COLUMNS = new Set(['host', 'channel', 'provider', 'source', 'event_id', 'level', 'category', 'user', 'ip']);
// 서버(repository.TOP_SKIP_EMPTY)와 같이: 사용자·IP 는 값 없는 이벤트를 세지 않는다
const SKIP_EMPTY = new Set(['user', 'ip']);

function draw(body, cfg, ctx, st) {
  const field = st.field;
  const rows = st.items.slice(0, st.limit).map((it) => ({
    value: it.n,
    raw: it.value,
    label: it.value == null ? '(없음)'
      : field === 'level' ? levelBadge(Number(it.value))
        : field === 'source' ? sourceLabel(it.value)
          : field === 'category' ? categoryLabel(it.value) : it.value,
    sub: field === 'event_id' ? eventDoc(it.value, (cfg.query || {}).source || ((cfg.query || {}).category === 'iis' ? 'iis' : null)) : '',
    color: field === 'level' ? levelColor(Number(it.value)) : cfg.color || 'var(--s1)',
  }));
  barList(body, rows, (row) => {
    if (row.raw == null) return;
    const key = COLUMNS.has(field) ? field : `f.${field.replace(/^f\./, '')}`;
    ctx.drill({ ...(cfg.query || {}), [key]: row.raw });
  });
}

export default {
  label: '상위 값 목록',
  async render(body, cfg, ctx) {
    const field = cfg.field || 'host';
    const limit = cfg.limit || 8;
    // 실시간으로 순위가 바뀔 수 있게 화면 개수보다 넉넉히 받아 둔다
    const data = await api.get('/api/stats/top', { ...ctx.query(cfg), field, limit: limit * 3 });
    const st = { field, limit, items: data.items.map((it) => ({ value: it.value, n: it.n })) };
    body._live = st;
    draw(body, cfg, ctx, st);
  },

  live(body, cfg, ctx, events) {
    const st = body._live;
    if (!st || !events.length) return;
    const field = st.field.startsWith('f.') || COLUMNS.has(st.field) ? st.field : `f.${st.field}`;
    for (const ev of events) {
      const value = fieldValue(field, ev);
      if (value == null && SKIP_EMPTY.has(field)) continue;
      const item = st.items.find((it) => it.value === value);
      if (item) item.n += 1;
      else st.items.push({ value, n: 1 });
    }
    st.items.sort((a, b) => b.n - a.n);
    draw(body, cfg, ctx, st);
  },
};
