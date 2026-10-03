// 최근 알림 목록.  limit: 개수 (기본 5). 누르면 알림 상세.
// 실시간 스트림 대상이 아니라서 대시보드 동기화 주기(refresh_sec)마다 갱신된다.
import * as api from '../api.js';
import { deliveryChips, openAlert } from '../alertdetail.js';
import { severityBadge } from '../levels.js';
import { fmtNum, fmtRelative, html } from '../util.js';

export default {
  label: '최근 알림',
  flush: true,
  async render(body, cfg, ctx) {
    const { items } = await api.get('/api/alerts', { since: ctx.query(cfg).since, limit: cfg.limit || 5 });
    if (!items.length) {
      body.innerHTML = html`<div class="empty">이 기간에 발생한 알림이 없습니다 ✓</div>`;
      return;
    }
    body.innerHTML = html`<div class="table-wrap"><table class="table"><tbody>${items.map((a) => html`
      <tr class="clickable" data-id="${a.id}">
        <td class="nowrap muted" style="width:1%">${fmtRelative(a.fired_at)}</td>
        <td class="nowrap" style="width:1%">${severityBadge(a.severity)}</td>
        <td class="nowrap"><b>${a.rule}</b>${a.group_key ? html` <span class="muted">· ${a.group_key}</span>` : ''}
          ${a.event_count ? html` <span class="muted num">(${fmtNum(a.event_count)}건)</span>` : ''}</td>
        <td class="r dlv-cell">${deliveryChips(a.deliveries)}</td>
      </tr>`)}</tbody></table></div>`;
    body.querySelectorAll('[data-id]').forEach((tr) => tr.addEventListener('click', () => openAlert(tr.dataset.id)));
  },
};
