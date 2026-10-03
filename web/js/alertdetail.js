// 알림 공용 표시: 전송 상태 칩, 조건 요약 문구, 알림 상세 패널.
import * as api from './api.js';
import { openDrawer } from './drawer.js';
import { EVENT_HEAD, bindRows, eventRow } from './eventtable.js';
import { categoryLabel, levelLabel, severityBadge, sourceLabel } from './levels.js';
import { errorBox, fmtDuration, fmtNum, fmtRelative, fmtTime, html } from './util.js';

const DELIVERY = {
  sent: ['✓', '전송됨'],
  pending: ['…', '전송 중'],
  failed: ['!', '실패 · 재시도 예정'],
  gave_up: ['✕', '실패 · 재시도 중단'],
  skipped: ['–', '건너뜀 (받을 최소 수준 미달)'],
};

export function deliveryChips(deliveries = []) {
  if (!deliveries.length) return html`<span class="muted">대상 없음</span>`;
  return html`${deliveries.map((d) => {
    const [mark, label] = DELIVERY[d.status] ?? ['?', d.status];
    return html`<span class="dlv ${d.status}" title="${label}${d.last_error ? `: ${d.last_error}` : ''}">${mark} ${d.notifier}</span>`;
  })}`;
}

const GROUP_LABELS = {
  host: 'PC', channel: '채널', provider: '공급자', source: '소스', event_id: '이벤트 ID', level: '수준',
  category: '분류', user: '사용자', ip: '출발지 IP', none: '',
};

function matchText(match = {}) {
  const parts = Object.entries(match).map(([k, v]) => {
    if (k === 'level') return `수준 ${v.split(',').map((x) => levelLabel(Number(x))).join('·')}`;
    if (k === 'event_id') return `이벤트 ${v}`;
    if (k === 'channel') return `채널 ${v}`;
    if (k === 'host') return `PC ${v}`;
    if (k === 'source') return v.split(',').map(sourceLabel).join('·');
    if (k === 'category') return v.split(',').map(categoryLabel).join('·');
    if (k === 'user') return `사용자 ${v}`;
    if (k === 'ip') return `IP ${v}`;
    if (k === 'provider') return `공급자 ${v}`;
    if (k === 'q') return `"${v}" 포함`;
    return `${k.replace(/^f\./, '')} = ${v}`;
  });
  return parts.join(', ') || '모든 이벤트';
}

/** 규칙 조건을 한 줄로: "수준 오류 · 10분 동안 5건 이상 · PC별 · 재알림 1시간" */
export function ruleSummary(r) {
  if (r.kind === 'agent_silent') {
    return `${r.hosts.length ? r.hosts.join(', ') : '모든 PC'} · ${fmtDuration(r.silent_for_sec)} 이상 수신 없음`;
  }
  const group = r.group_by === 'none' ? '전체 합산' : `${GROUP_LABELS[r.group_by] ?? r.group_by.replace(/^f\./, '')}별`;
  return `${matchText(r.match)} · ${fmtDuration(r.window_sec)} 동안 ${fmtNum(r.threshold)}건 이상 · ${group} · 재알림 ${fmtDuration(r.cooldown_sec)}`;
}

/** 서버가 만든 링크(http://주소/#/events?...)를 현재 화면 기준 해시로 */
export function linkHash(link) {
  const i = (link || '').indexOf('#');
  return i >= 0 ? link.slice(i) : '';
}

export async function openAlert(id) {
  const body = openDrawer({ title: '알림 상세' });
  body.innerHTML = '<div class="skeleton"></div>';
  let alert;
  try {
    alert = await api.get(`/api/alerts/${id}`);
  } catch (err) {
    body.innerHTML = errorBox(err);
    return;
  }
  const p = alert.payload || {};
  const samples = p.samples || [];
  const hash = linkHash(p.link);
  body.innerHTML = html`
    <div class="toolbar" style="margin-bottom:6px">${severityBadge(alert.severity)}<b>${alert.rule}</b>
      ${alert.group_key ? html`<span class="muted">· ${alert.group_key}</span>` : ''}</div>
    <p class="ink-2" style="margin:0 0 14px">${p.kind === 'agent_silent'
      ? `${alert.group_key} 에서 ${fmtDuration(p.window_sec)} 이상 로그/하트비트가 들어오지 않았습니다.`
      : `최근 ${fmtDuration(p.window_sec)} 동안 조건에 맞는 이벤트 ${fmtNum(alert.event_count)}건 (기준 ${fmtNum(p.threshold)}건 이상)`}</p>
    ${p.description ? html`<div class="hint-box" style="margin-bottom:14px">${p.description}</div>` : ''}
    ${p.tags?.length ? html`<div style="margin:-6px 0 12px">${p.tags.map((t) => html`<span class="type-tag" style="margin-right:4px">${t}</span>`)}</div>` : ''}
    <dl class="kv">
      <dt>발생 시각</dt><dd>${fmtTime(alert.fired_at)} <span class="muted">(${fmtRelative(alert.fired_at)})</span></dd>
      ${alert.first_event_at ? html`<dt>이벤트 시각</dt><dd>${fmtTime(alert.first_event_at)} ~ ${fmtTime(alert.last_event_at, { date: false })}</dd>` : ''}
      ${p.kind === 'agent_silent' ? html`<dt>마지막 수신</dt><dd>${fmtTime(alert.last_event_at)}</dd>` : ''}
      <dt>알림 번호</dt><dd class="num">#${alert.id}</dd>
    </dl>
    ${hash ? html`<a class="btn" href="${hash}">${p.kind === 'agent_silent' ? '수집 PC 화면 열기' : '이 알림의 이벤트 검색'} →</a>` : ''}
    <div class="section-title">전송 상태</div>
    <div class="table-wrap"><table class="table">
      <thead><tr><th>알림 대상</th><th>상태</th><th class="r">시도</th><th>전송 시각</th><th>마지막 오류</th></tr></thead>
      <tbody>${alert.deliveries.map((d) => html`<tr>
        <td class="nowrap"><b>${d.notifier}</b></td>
        <td class="nowrap">${deliveryChips([d])}</td>
        <td class="r num">${d.attempts}</td>
        <td class="nowrap muted">${d.sent_at ? fmtTime(d.sent_at) : '–'}</td>
        <td class="ink-2" style="overflow-wrap:anywhere">${d.last_error || ''}</td>
      </tr>`)}</tbody></table></div>
    ${samples.length ? html`
      <div class="section-title">알림에 포함된 최근 이벤트</div>
      <div class="table-wrap"><table class="table"><thead>${EVENT_HEAD}</thead>
        <tbody data-samples>${samples.map((s, i) => eventRow(s, i))}</tbody></table></div>` : ''}`;
  const tbody = body.querySelector('[data-samples]');
  if (tbody) bindRows(tbody, (k) => samples[Number(k)]?.id && { id: samples[Number(k)].id });
  body.querySelector('a.btn')?.addEventListener('click', () => document.querySelector('.drawer-overlay')?.click());
}
