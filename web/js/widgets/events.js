// 최근 이벤트 표.  limit: 행 수 (기본 10)
// 실시간: 조건에 맞는 새 이벤트가 맨 위에 끼어든다.
import * as api from '../api.js';
import { eventTable } from '../eventtable.js';

function draw(body, st, fresh = 0) {
  eventTable(body, st.items, { emptyText: '이 기간에 해당 이벤트가 없습니다' });
  body.querySelectorAll('tbody tr').forEach((tr, i) => { if (i < fresh) tr.classList.add('flash'); });
}

export default {
  label: '최근 이벤트 표',
  flush: true,
  async render(body, cfg, ctx) {
    const limit = cfg.limit || 10;
    const data = await api.get('/api/events', { ...ctx.query(cfg), limit });
    body._live = { limit, items: data.items };
    draw(body, body._live);
  },

  live(body, cfg, ctx, events) {
    const st = body._live;
    if (!st || !events.length) return;
    const fresh = [...events].sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, st.limit);
    st.items = [...fresh, ...st.items].slice(0, st.limit);
    draw(body, st, fresh.length);
  },
};
