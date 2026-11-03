// 알림 공용 표시: 전송 상태 칩, 처리 상태 칩, 조건 요약 문구, 알림 상세 패널(처리·메모·무음).
import * as api from './api.js';
import { can } from './auth.js';
import { openDrawer, openEvent } from './drawer.js';
import { EVENT_HEAD, bindRows, eventRow } from './eventtable.js';
import { categoryLabel, levelLabel, severityBadge, sourceLabel } from './levels.js';
import { describe } from './querybox.js';
import { formatTerm, parseTerms } from './querylang.js';
import { ENTITY_LABELS, entityHash, errorBox, fmtDuration, fmtNum, fmtRelative, fmtTime, html, qs } from './util.js';

const DELIVERY = {
  sent: ['✓', '전송됨'],
  pending: ['…', '전송 대기'],   // 전송기가 곧 보낸다 (ADR-045). 잡고 보내는 중이면 claimed_at
  failed: ['!', '실패 · 재시도 예정'],
  gave_up: ['✕', '실패 · 재시도 중단'],
  skipped: ['–', '건너뜀'], // 사유(받을 최소 수준 미달, 무음)는 last_error 에
};

// 처리 상태 (server: alerts.status) — 확인은 알림을 볼 수 있으면 누구나, 해결·다시 열기·무음은 alerts.handle
export const ALERT_STATUS = { open: '처리 안 됨', acked: '확인함', resolved: '해결됨' };
const NOTE_ACTIONS = { note: '메모', ack: '확인', resolve: '해결', reopen: '다시 열기', auto_resolve: '자동 해결', escalate: '다시 알림', ack_timeout: '확인 시간 초과' };
// 에스컬레이션 (B-43): 전송 행의 action 'escalate:<초>:<acked|resolved>'
const isEscalation = (d) => (d.action || '').startsWith('escalate:') || (d.action || '').startsWith('acktimeout:');
// 종료 분류 (B-44) — 해결할 때 필수. auto 는 엔진의 자동 해소 (server: alerts/message.RESOLUTION_LABELS)
export const RESOLUTIONS = {
  tp_malicious: ['정탐 — 의심 행위', '정탐'], tp_expected: ['정탐 — 예상된 관리 작업', '정탐(예상)'],
  fp_rule: ['오탐 — 규칙 문제', '오탐'], fp_data: ['오탐 — 데이터 문제', '오탐(데이터)'], undetermined: ['판단 불가', '판단 불가'],
  auto: ['자동 해소', '자동'],
};
/** 해결 양식의 종료 분류 칸 (고르기 전에는 비어 있음 — 기본값으로 대충 닫지 않게) */
export function resolutionSelect(attr = 'data-resolution') {
  return html`<select class="select" ${attr === 'data-resolution' ? html`data-resolution` : html`data-bulk-resolution`} aria-label="종료 분류">
    <option value="">종료 분류 고르기…</option>
    ${Object.entries(RESOLUTIONS).filter(([k]) => k !== 'auto').map(([k, [label]]) => html`<option value="${k}">${label}</option>`)}</select>`;
}
export const SILENCE_DURATIONS = [[3600, '1시간'], [4 * 3600, '4시간'], [86400, '하루'], [3 * 86400, '사흘']];

export function statusChip(a) {
  const auto = a.status === 'resolved' && a.auto_resolved;   // 조건이 풀려 엔진이 해결 (B-35 2단계)
  const who = auto ? '조건이 풀려 자동으로' : a.status === 'resolved' ? a.resolved_by : a.status === 'acked' ? a.acked_by : '';
  const kind = a.status === 'resolved' && !auto && RESOLUTIONS[a.resolution] ? ` · ${RESOLUTIONS[a.resolution][1]}` : '';
  return html`<span class="ast ${a.status}" title="${who ? `${who} · ${fmtTime(a.status === 'resolved' ? a.resolved_at : a.acked_at)}${RESOLUTIONS[a.resolution] ? ` · ${RESOLUTIONS[a.resolution][0]}` : ''}` : ''}">${ALERT_STATUS[a.status] ?? a.status}${auto ? ' (자동)' : ''}${kind}</span>${
    a.silence_id ? html` <span class="ast silenced" title="무음 #${a.silence_id} — 보내지 않음">무음</span>` : ''}${
    a.observed ? html` <span class="ast silenced" title="관찰 모드 규칙 — 기록만 하고 보내지 않음">관찰</span>` : ''}`;
}

/** 무음 범위 문구: "로그온 실패 · PC-01" / "모든 규칙 · 모든 대상" */
export function silenceScope(s) {
  return `${s.rule ?? '모든 규칙'} · ${s.group_key == null ? '모든 대상' : s.group_key || '(대상 없음)'}`;
}

/** 같은 규칙·대상의 앞 알림과의 관계, 이 알림 뒤 이어진 이벤트, 지연 수신 (B-35). 서버 message.py 의 문구와 같은 뜻 */
function lifecycle(alert, p) {
  const lines = [];
  if (p.recurred) lines.push(`해결된 알림(#${p.previous_id}) 뒤 새로 발생했습니다 — 재알림 간격과 상관없이 알렸습니다`);
  else if (p.previous_id) lines.push(`지난 알림(#${p.previous_id}, ${fmtTime(p.previous_fired_at)}) 이후 이 대상에서 ${fmtNum(p.since_previous || 0)}건`);
  const f = alert.followup;
  if (f?.n) lines.push(`이 알림 뒤 같은 조건으로 ${fmtNum(f.n)}건 더 들어왔습니다 · 마지막 ${fmtRelative(f.last_at)}`);
  if (p.kind === 'count' && p.first_event_at && p.window_sec) {
    const lag = (new Date(p.fired_at) - new Date(p.first_event_at)) / 1000;
    if (lag > Math.max(2 * p.window_sec, p.window_sec + 3600)) {
      lines.push(`지연 수신분 포함 — 발생 시각 ${fmtTime(p.first_event_at)} ~ ${fmtTime(p.last_event_at)} (밀린 로그를 한꺼번에 받았거나 PC 시계가 틀렸을 수 있습니다)`);
    }
  }
  return lines.length ? html`<div class="hint-box" style="margin:-6px 0 14px;font-size:12.5px">${lines.map((l) => html`<div>${l}</div>`)}</div>` : '';
}

export function deliveryChips(deliveries = []) {
  if (!deliveries.length) return html`<span class="muted">대상 없음</span>`;
  return html`${deliveries.map((d) => {
    const [mark, label] = d.claimed_at ? ['↗', '보내는 중'] : DELIVERY[d.status] ?? ['?', d.status];
    const held = d.status === 'pending' && !d.claimed_at && d.next_attempt_at && new Date(d.next_attempt_at) > Date.now();
    const next = d.status === 'failed' && d.next_attempt_at ? ` · 다음 시도 ${fmtTime(d.next_attempt_at, { date: false })}`
      : held ? ` · 같은 규칙 알림을 모아 ${fmtTime(d.next_attempt_at, { date: false })}에 보냄` : d.batch_size > 1 ? ` · ${d.batch_size}건을 묶어 한 통으로` : '';
    const what = d.action === 'resolve' ? '해소 통지 ' : isEscalation(d) ? '다시 알림(에스컬레이션) ' : '';   // 해소 통지 (B-35 2단계)
    return html`<span class="dlv ${d.status}" title="${what}${label}${next}${d.last_error ? `: ${d.last_error}` : ''}">${mark} ${d.notifier}${d.action === 'resolve' ? ' · 해소' : isEscalation(d) ? ' · 다시' : ''}</span>`;
  })}`;
}

export const GROUP_LABELS = {
  host: 'PC', channel: '채널', provider: '공급자', source: '소스', event_id: '이벤트 ID', level: '수준',
  category: '분류', user: '사용자', account: '계정', ip: '출발지 IP', none: '',
};

export function matchText(match = {}) {
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
    if (k === 'saved') return `저장한 검색 '${v}'`;
    if (k === 'query') {
      try { return describe(parseTerms(v)); } catch { return `문장: ${v}`; }
    }
    return `${k.replace(/^f\./, '')} = ${v}`;
  });
  return parts.join(', ') || '모든 이벤트';
}

// 상관 알림 (B-67 2단계): 볼 개체 → 'PC·계정·IP'
const ENTITY_WORDS = { host: 'PC', account: '계정', ip: 'IP' };
export const entityText = (kinds = []) => kinds.map((k) => ENTITY_WORDS[k] ?? k).join('·');

/** 규칙 조건을 한 줄로: "수준 오류 · 10분 동안 5건 이상 · PC별 · 재알림 1시간" */
export function ruleSummary(r) {
  if (r.kind === 'correlation') {
    return `같은 ${entityText(r.entities)}에서 ${fmtDuration(r.window_sec)} 안에 다른 규칙 알림의 서로 다른 전술 ${fmtNum(r.min_tactics)}개 이상 · 재알림 ${fmtDuration(r.cooldown_sec)}`;
  }
  if (r.kind === 'agent_silent') {
    return `${r.hosts.length ? r.hosts.join(', ') : '모든 PC'} · ${fmtDuration(r.silent_for_sec)} 이상 수신 없음`;
  }
  if (r.kind === 'stream_silent') {
    return `${r.hosts.length ? r.hosts.join(', ') : '모든 PC'} · ${r.channels.length ? r.channels.join(', ') : '모든 채널'} · 늘 오던 채널이 끊김`;
  }
  if (r.kind === 'new_terms') {
    const what = r.fields.map((k) => GROUP_LABELS[k] ?? k.replace(/^f\./, '')).join(' + ');
    return `${matchText(r.match)} · 처음 보는 ${what} (최근 ${fmtDuration(r.history_sec)} 동안 없던 값) · 배우는 기간 ${fmtDuration(r.learn_sec)}`;
  }
  const group = r.group_by === 'none' ? '전체 합산' : `${GROUP_LABELS[r.group_by] ?? r.group_by.replace(/^f\./, '')}별`;
  const distinct = r.distinct?.field ? ` · 서로 다른 ${GROUP_LABELS[r.distinct.field] ?? r.distinct.field.replace(/^f\./, '')} ${fmtNum(r.distinct.min)}개 이상` : '';
  return `${matchText(r.match)} · ${fmtDuration(r.window_sec)} 동안 ${fmtNum(r.threshold)}건 이상${distinct} · ${group} · 재알림 ${fmtDuration(r.cooldown_sec)}`;
}

const termName = (k) => GROUP_LABELS[k] ?? k.replace(/^f\./, '');

/** 처음 보는 값 알림(B-47)의 한 줄 — 하나면 그 값, 몰려왔으면 몇 개 */
function termsText(t) {
  const days = t.history_days ? `최근 ${fmtNum(t.history_days)}일 동안` : '이전에';
  if (t.items) return `${days} 없던 ${(t.fields ?? []).map(termName).join(' + ')} ${fmtNum(t.count)}개가 한 주기에 몰려와 한 통으로 묶었습니다 — 서브넷·계정 일괄 변경인지 확인하세요.`;
  const again = t.prev_last_seen ? ` (마지막으로 본 때 ${fmtTime(t.prev_last_seen)} — 오랜만에 다시 보임)` : '';
  return `${days} 보지 못한 ${(t.fields ?? []).map(termName).join(' + ')} 조합이 나타났습니다${again}.`;
}

/** 상관 알림 (B-67 2단계): 전술 흐름(전술 → 그 전술로 센 규칙)과 묶은 알림 목록 — 누르면 그 알림 상세 */
function correlationBlock(c) {
  const steps = c.tactics ?? [];
  const items = c.alerts ?? [];
  return html`<ol class="tactic-steps">${steps.map((s) => html`<li><b>${s.name}</b> <span class="muted">${s.rule}</span></li>`)}</ol>
    ${items.length ? html`<ul class="rel-list" data-chain style="margin-bottom:14px">${items.map((a) => html`<li data-alert="${a.id}" title="이 알림 상세">
      <div class="rel-head">${severityBadge(a.severity)}<b>${a.rule}</b>${a.group_key ? html`<span class="muted">· ${a.group_key}</span>` : ''}</div>
      <div class="rel-meta"><span class="num muted">${fmtTime(a.fired_at)}</span>${(a.tactics ?? []).map((t) => html`<span class="type-tag">${t}</span>`)}</div>
    </li>`)}</ul>` : ''}
    ${(c.count ?? items.length) > items.length ? html`<p class="muted" style="margin:-8px 0 14px;font-size:12.5px">… 외 ${fmtNum(c.count - items.length)}건 — 개체 칩을 눌러 개체 페이지에서 모두 보세요</p>` : ''}`;
}

function termsBlock(t) {
  const fields = t.fields ?? [];
  if (t.items) {
    return html`<div class="table-wrap" style="margin:-6px 0 14px"><table class="table no-stack"><thead><tr>${fields.map((k) => html`<th>${termName(k)}</th>`)}<th>처음 본 시각</th></tr></thead>
      <tbody>${t.items.map((i) => html`<tr>${i.values.map((v) => html`<td>${v}</td>`)}<td class="nowrap">${i.first_ts ? fmtTime(i.first_ts) : '–'}</td></tr>`)}</tbody></table></div>
      ${t.count > t.items.length ? html`<p class="muted" style="margin:-8px 0 14px;font-size:12.5px">… 외 ${fmtNum(t.count - t.items.length)}개 (이벤트 검색에서 확인)</p>` : ''}`;
  }
  return html`<dl class="kv" style="margin:-6px 0 14px">${fields.map((k, i) => html`<dt>${termName(k)}</dt><dd><b>${t.values?.[i] ?? ''}</b></dd>`)}
    ${t.first_ts ? html`<dt>처음 본 시각</dt><dd>${fmtTime(t.first_ts)}</dd>` : ''}${t.host ? html`<dt>PC</dt><dd>${t.host}</dd>` : ''}</dl>`;
}

/** 서버가 만든 링크(http://주소/#/events?...)를 현재 화면 기준 해시로 */
// 알림의 개체 (B-67): 서버 종류(account) → 개체 페이지 종류(user)
const ENTITY_KIND = { host: 'host', account: 'user', ip: 'ip' };

/** 개체 칩 — 누르면 개체 페이지. entities = {host: [...], account: [...], ip: [...]} */
export function entityChips(entities = {}) {
  return html`${Object.entries(ENTITY_KIND).flatMap(([k, page]) => (entities[k] || []).map((v) => html`<a class="type-tag entity-chip"
    href="${entityHash(page, v)}" title="${ENTITY_LABELS[page]} ${v} 의 알림·로그">${ENTITY_LABELS[page]} ${v}</a> `))}`;
}

/** 알림 짧은 표 (개체 페이지, B-67) — 행을 누르면 그 알림 상세(bindAlertRows) */
export function alertRows(items) {
  return html`<div class="table-wrap"><table class="table"><thead><tr><th>발생 시각</th><th>심각도</th><th>규칙</th><th>대상</th>
    <th>처리 상태</th></tr></thead>
    <tbody>${items.map((a) => html`<tr class="clickable" data-alert="${a.id}">
      <td class="nowrap num">${fmtTime(a.fired_at)}</td><td class="nowrap">${severityBadge(a.severity)}</td><td>${a.rule}</td>
      <td class="ink-2" style="overflow-wrap:anywhere">${a.group_key || '–'}${a.terms_host ? html` <span class="muted">· PC ${a.terms_host}</span>` : ''}</td>
      <td class="nowrap">${statusChip(a)}</td></tr>`)}</tbody></table></div>`;
}

/** alertRows·관련 알림 목록의 행을 누르면 그 알림 상세 (칩 링크는 그대로 개체 페이지로) */
export function bindAlertRows(el, onChange) {
  el.addEventListener('click', (ev) => {
    if (ev.target.closest('a')) return;
    const row = ev.target.closest('[data-alert]');
    if (row) openAlert(Number(row.dataset.alert), { onChange });
  });
}

// 겹친 개체: 종류마다 두 개까지는 칩, 넘으면 '계정 7개'(값은 title) — 좁은 패널에서 칩이 줄줄이 늘어서지 않게
function sharedSummary(a) {
  return html`${Object.entries(ENTITY_KIND).map(([k, page]) => {
    const values = a[`shared_${k}`] || [];
    if (values.length <= 2) return entityChips({ [k]: values });
    return html`<span class="type-tag" title="${values.join(', ')}">${ENTITY_LABELS[page]} ${fmtNum(values.length)}개</span> `;
  })}`;
}

function relatedList(items) {
  return html`<ul class="rel-list">${items.map((a) => html`<li data-alert="${a.id}" title="이 알림 상세">
    <div class="rel-head">${severityBadge(a.severity)}<b>${a.rule}</b>${a.group_key ? html`<span class="muted">· ${a.group_key}</span>` : ''}
      <span class="rel-status">${statusChip(a)}</span></div>
    <div class="rel-meta"><span class="num muted">${fmtTime(a.fired_at)}</span><span class="muted">겹친 개체</span>${sharedSummary(a)}</div>
  </li>`)}</ul>`;
}

/** 관련 알림 (B-67): 앞뒤 1시간 안에 같은 PC·계정·IP 가 걸린 다른 알림 — 규칙마다 흩어진 한 흐름을 한 곳에서 */
async function relatedSection(box, alert, onChange) {
  let res;
  try {
    res = await api.get(`/api/alerts/${alert.id}/related`);
  } catch (err) {
    box.innerHTML = errorBox(err);
    return;
  }
  const e = res.entities;
  if (!e.host.length && !e.account.length && !e.ip.length) {
    box.innerHTML = html`<p class="muted" style="font-size:13px">이 알림에는 PC·계정·IP 가 없어 관련 알림을 찾지 않습니다.</p>`;
    return;
  }
  box.innerHTML = res.items.length ? html`${relatedList(res.items)}
    ${res.truncated ? html`<p class="muted" style="font-size:12.5px">가깝게 이어진 ${fmtNum(res.items.length)}건만 보입니다(계정·IP 가 겹친 것, 겹친 값이 많은 것, 시각이 가까운 것부터) — 개체 칩을 눌러 개체 페이지에서 모두 보세요.</p>` : ''}`
    : html`<p class="muted" style="font-size:13px">앞뒤 ${fmtDuration(res.window_sec)} 안에 같은 PC·계정·IP 가 걸린 다른 알림이 없습니다.</p>`;
  bindAlertRows(box, onChange);
}

export function linkHash(link) {
  const i = (link || '').indexOf('#');
  return i >= 0 ? link.slice(i) : '';
}

/**
 * 알림 상세 패널. 처리(확인·해결·다시 열기), 메모, 무음을 여기서 한다.
 * onChange: 처리 상태가 바뀌면 부르는 함수 (목록 새로고침용)
 */
export async function openAlert(id, { onChange } = {}) {
  const body = openDrawer({ title: '알림 상세' });
  body.innerHTML = '<div class="skeleton"></div>';
  const reload = async () => {
    try {
      render(await api.get(`/api/alerts/${id}`));
    } catch (err) {
      body.innerHTML = errorBox(err);
    }
  };

  // 늘 예상되는 대상(백업 계정·업체 IP)이면 규칙 예외로 (B-46) — 묶음 기준 값으로 조건을 미리 채워 예외 탭을 연다
  function exceptionLink(alert, p) {
    if (!can('alerts.manage') || p.kind !== 'count' || !p.group_by || p.group_by === 'none' || !alert.group_key) return '';
    if (p.group_by === 'account') return '';   // account: 예외는 받지 않는다(다른 표기로 비켜 감, B-54) — 표기를 user: 로 직접 쓴다
    const term = p.group_by.startsWith('f.')
      ? formatTerm({ key: 'f', path: p.group_by.slice(2).split('.'), values: [alert.group_key], neg: false })
      : formatTerm({ key: p.group_by, values: [alert.group_key], neg: false, path: [] });
    const href = `#/alerts/exceptions?rule=${encodeURIComponent(alert.rule)}&term=${encodeURIComponent(term)}`;
    return html`<a class="btn ghost" href="${href}" title="이 대상은 이 규칙에서 늘 빼기 (사유·만료와 함께)">예외로…</a>`;
  }

  function render(alert) {
    const p = alert.payload || {};
    const samples = p.samples || [];
    const hash = linkHash(p.link);
    const handler = can('alerts.handle');
    const related = alert.related_unresolved || 0; // 같은 규칙·대상의 해결 안 된 다른 알림 수
    // 설정 변경 알림(ADR-043): 설명 첫 줄이 요약, 나머지 줄이 변경 목록. 무음으로 막을 수 없어 무음 단추가 없다
    const config = p.kind === 'config';
    // 내장 알림(설정 변경·알림 기능 문제, ADR-043·045): 설명 첫 줄이 요약, 나머지가 내용. 알림 기능 문제는 무음으로 막을 수 있다
    const builtin = config || p.kind === 'system';
    const [configSummary, ...configLines] = builtin ? (p.description || '').split('\n') : [];
    const entities = !!(alert.entity_hosts?.length || alert.entity_accounts?.length || alert.entity_ips?.length);
    body.innerHTML = html`
      <div class="toolbar" style="margin-bottom:6px">${severityBadge(alert.severity)}<b>${alert.rule}</b>
        ${alert.group_key ? html`<span class="muted">· ${alert.group_key}</span>` : ''}</div>
      <p class="ink-2" style="margin:0 0 14px">${builtin ? configSummary : p.kind === 'agent_silent'
        ? `${alert.group_key} 에서 ${fmtDuration(p.window_sec)} 이상 로그/하트비트가 들어오지 않았습니다.`
        : p.kind === 'stream_silent'
          ? `${alert.group_key} 로그가 ${fmtDuration(p.window_sec)} 넘게 들어오지 않습니다 — PC 는 살아 있습니다${p.stream?.per_day ? ` (평소 하루 ${fmtNum(p.stream.per_day)}건)` : ''}. 감사 정책·에이전트 설정을 확인하세요.`
        : p.kind === 'new_terms'
          ? termsText(p.terms ?? {})
        : p.kind === 'correlation'
          ? `${alert.group_key} 에서 최근 ${fmtDuration(p.window_sec)} 동안 다른 규칙들의 알림이 서로 다른 공격 단계(전술) ${fmtNum(p.correlation?.tactics?.length ?? 0)}개로 이어졌습니다 (기준 ${fmtNum(p.threshold)}개 이상) — 한 사고로 보고 함께 조사하세요.`
        : p.distinct_field
          ? `최근 ${fmtDuration(p.window_sec)} 동안 서로 다른 ${GROUP_LABELS[p.distinct_field] ?? p.distinct_field.replace(/^f\./, '')} ${fmtNum(p.distinct_count)}개 (기준 ${fmtNum(p.distinct_min)}개 이상) · 이벤트 ${fmtNum(alert.event_count)}건`
          : `최근 ${fmtDuration(p.window_sec)} 동안 조건에 맞는 이벤트 ${fmtNum(alert.event_count)}건 (기준 ${fmtNum(p.threshold)}건 이상)`}</p>
      ${lifecycle(alert, p)}
      ${p.kind === 'new_terms' ? termsBlock(p.terms ?? {}) : ''}
      ${p.kind === 'correlation' ? correlationBlock(p.correlation ?? {}) : ''}
      ${p.distinct_values?.length ? html`<p class="muted" style="margin:-8px 0 14px;font-size:12.5px">${p.distinct_values.join(', ')}${p.distinct_count > p.distinct_values.length ? ` … 외 ${fmtNum(p.distinct_count - p.distinct_values.length)}` : ''}</p>` : ''}

      <div class="handle-box">
        <div class="handle-state">${statusChip(alert)}
          <span class="muted">${alert.status === 'resolved' && alert.auto_resolved ? `${fmtRelative(alert.resolved_at)} 조건이 풀려 자동으로 해결`
            : alert.status === 'resolved' ? `${alert.resolved_by} 님이 ${fmtRelative(alert.resolved_at)} 해결`
            : alert.status === 'acked' ? `${alert.acked_by} 님이 ${fmtRelative(alert.acked_at)} 확인` : '아직 아무도 확인하지 않았습니다'}</span></div>
        <div class="toolbar">
          ${alert.status === 'open' ? html`<button class="btn" data-act="ack" title="보고 있다는 기록을 남깁니다">확인</button>` : ''}
          ${handler && alert.status !== 'resolved' ? html`<button class="btn primary" data-form="resolve">해결…</button>` : ''}
          ${handler && alert.status !== 'open' ? html`<button class="btn" data-form="reopen" title="처리 안 됨으로 되돌립니다">다시 열기…</button>` : ''}
          ${handler && !config ? html`<button class="btn ghost" data-form="silence" title="점검·작업 중 이 알림을 잠시 보내지 않습니다">무음…</button>` : ''}
          ${exceptionLink(alert, p)}
        </div>
        <div data-formbox></div>
      </div>
      ${alert.silence ? html`<div class="hint-box" style="margin-bottom:14px">무음 #${alert.silence.id} 중에 발생해 보내지 않았습니다 —
        ${alert.silence.hidden ? '다른 대상에 건 무음' : html`${alert.silence.reason} (${alert.silence.created_by},`} ${fmtTime(alert.silence.starts_at)} ~ ${fmtTime(alert.silence.ends_at)}${alert.silence.hidden ? '' : ')'}</div>` : ''}

      ${builtin ? (configLines.length ? html`<div class="hint-box" style="margin-bottom:14px;white-space:pre-line">${configLines.join('\n')}</div>` : '')
        : p.description ? html`<div class="hint-box" style="margin-bottom:14px">${p.description}</div>` : ''}
      ${p.tags?.length ? html`<div style="margin:-6px 0 12px">${p.tags.map((t) => html`<span class="type-tag" style="margin-right:4px">${t}</span>`)}</div>` : ''}
      ${p.routes?.length ? html`<div class="muted" style="margin:-6px 0 12px;font-size:12.5px">받는 곳 경로: ${p.routes.join(' → ')}</div>` : ''}
      <dl class="kv">
        <dt>발생 시각</dt><dd>${fmtTime(alert.fired_at)} <span class="muted">(${fmtRelative(alert.fired_at)})</span></dd>
        ${alert.first_event_at ? html`<dt>이벤트 시각</dt><dd>${fmtTime(alert.first_event_at)} ~ ${fmtTime(alert.last_event_at, { date: false })}</dd>` : ''}
        ${p.kind === 'agent_silent' || p.kind === 'stream_silent' ? html`<dt>마지막 수신</dt><dd>${fmtTime(alert.last_event_at)}</dd>` : ''}
        <dt>알림 번호</dt><dd class="num">#${alert.id}</dd>
        ${entities ? html`<dt>개체</dt><dd><div class="entity-chips">${entityChips({ host: alert.entity_hosts, account: alert.entity_accounts, ip: alert.entity_ips })}</div></dd>` : ''}
      </dl>
      ${p.kind === 'system' ? html`<a class="btn" data-link href="#/alerts/targets">알림 상태·알림 대상 보기 →</a>`
        : config ? (can('audit.view') ? html`<a class="btn" data-link href="#/audit?action=alerts.config.">감사로그에서 설정 변경 보기 →</a>` : '')
        : hash ? html`<a class="btn" data-link href="${hash}">${p.kind === 'agent_silent' || p.kind === 'stream_silent' ? '수집 PC 화면 열기' : '이 알림의 이벤트 검색'} →</a>` : ''}

      ${!builtin ? html`<div class="section-title">관련 알림 <span class="muted" style="font-weight:400">앞뒤 1시간 · 같은 PC·계정·IP</span></div>
        <div data-related><div class="skeleton" style="height:60px"></div></div>` : ''}

      ${!builtin && p.kind === 'count' ? html`<div class="section-title" style="display:flex;justify-content:space-between;align-items:center">
        <span>조사 순서 <span class="muted" style="font-weight:400">플레이북 — 무엇부터 볼지</span></span>
        <button class="btn sm" type="button" data-pb-open>열기</button></div><div data-pb></div>` : ''}

      <div class="section-title">처리 기록</div>
      <ol class="timeline">
        <li><span class="tl-act fired">발생</span><span class="muted">${fmtTime(alert.fired_at)}</span></li>
        ${alert.notes.map((n) => html`<li>
          <span class="tl-act ${n.action}">${NOTE_ACTIONS[n.action] ?? n.action}</span>${n.action === 'resolve' && RESOLUTIONS[n.resolution]
            ? html`<span class="muted">${RESOLUTIONS[n.resolution][0]}</span> ` : ''}<b>${n.author}</b>
          <span class="muted">${fmtTime(n.at)}</span>
          ${n.text ? html`<div class="tl-text">${n.text}</div>` : ''}</li>`)}
      </ol>
      <div class="note-form">
        <textarea class="input" rows="2" maxlength="2000" data-note placeholder="조사·조치 내용을 남깁니다 (저장 후 고칠 수 없음)" aria-label="메모"></textarea>
        <button class="btn sm" data-addnote>메모 남기기</button>
      </div>
      <div data-msg></div>

      <div class="section-title">전송 상태</div>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>알림 대상</th><th>상태</th><th class="r">시도</th><th>전송 시각</th><th>마지막 오류</th></tr></thead>
        <tbody>${alert.deliveries.map((d) => html`<tr>
          <td class="nowrap"><b>${d.notifier}</b>${d.action === 'resolve' ? html` <span class="muted">해소 통지</span>`
            : isEscalation(d) ? html` <span class="muted">다시 알림 (${d.action.startsWith('acktimeout:') ? `확인한 뒤 ${fmtDuration(Number(d.action.split(':')[1]))} 미해결`
              : `${fmtDuration(Number(d.action.split(':')[1]))} ${d.action.endsWith(':acked') ? '미확인' : '미해결'}`})</span>` : ''}</td>
          <td class="nowrap">${deliveryChips([d])}</td>
          <td class="r num">${d.attempts}</td>
          <td class="nowrap muted">${d.sent_at ? fmtTime(d.sent_at) : '–'}${d.batch_size > 1 ? html` <span title="같은 규칙 알림을 한 통으로 (B-41)">· ${d.batch_size}건 묶음</span>` : ''}</td>
          <td class="ink-2" style="overflow-wrap:anywhere">${d.last_error || ''}</td>
        </tr>`)}</tbody></table></div>
      ${samples.length ? html`
        <div class="section-title">알림에 포함된 최근 이벤트</div>
        <div class="table-wrap"><table class="table ev-table"><thead>${EVENT_HEAD}</thead>
          <tbody data-samples>${samples.map((s, i) => eventRow(s, i))}</tbody></table></div>` : ''}`;

    const chain = body.querySelector('[data-chain]');
    if (chain) bindAlertRows(chain, onChange);   // 묶은 알림을 열면 이 패널은 그 알림으로 바뀐다
    const relBox = body.querySelector('[data-related]');
    if (relBox) relatedSection(relBox, alert, onChange);   // 관련 알림을 열면 이 패널은 그 알림으로 바뀐다 — 목록만 새로
    body.querySelector('[data-pb-open]')?.addEventListener('click', (e) => {
      e.target.disabled = true;
      playbookSection(body.querySelector('[data-pb]'), alert, async () => { onChange?.(); await reload(); });
    });
    const tbody = body.querySelector('[data-samples]');
    if (tbody) bindRows(tbody, (k) => samples[Number(k)]?.id && { id: samples[Number(k)].id });
    body.querySelector('[data-link]')?.addEventListener('click', () => document.querySelector('.drawer-overlay')?.click());
    const msg = body.querySelector('[data-msg]');
    const formbox = body.querySelector('[data-formbox]');

    async function act(action, ids, note = '', withRelated = false, resolution = null) {
      await api.send('POST', '/api/alerts/handle', { ids, action, note, with_related: withRelated, resolution });
      onChange?.();
      await reload();
    }

    body.querySelector('[data-act="ack"]')?.addEventListener('click', async (e) => {
      e.target.disabled = true;
      try { await act('ack', [alert.id]); } catch (err) { e.target.disabled = false; msg.innerHTML = errorBox(err); }
    });

    body.querySelectorAll('[data-form]').forEach((b) => b.addEventListener('click', () => {
      const kind = b.dataset.form;
      if (formbox.dataset.kind === kind) { formbox.innerHTML = ''; formbox.dataset.kind = ''; return; }
      formbox.dataset.kind = kind;
      if (kind === 'silence') silenceForm(formbox, alert, () => onChange?.()); // 이미 발생한 알림은 그대로라 다시 그리지 않는다
      else handleForm(formbox, kind, related, async (note, withRelated, resolution) => act(kind, [alert.id], note, withRelated, resolution));
    }));

    body.querySelector('[data-addnote]').addEventListener('click', async (e) => {
      const text = body.querySelector('[data-note]').value.trim();
      if (!text) { body.querySelector('[data-note]').focus(); return; }
      e.target.disabled = true;
      try {
        await api.send('POST', `/api/alerts/${alert.id}/notes`, { text });
        onChange?.();
        await reload();
      } catch (err) {
        e.target.disabled = false;
        msg.innerHTML = errorBox(err);
      }
    });
  }

  await reload();
}

/** 조사 플레이북 (B-66): 질문마다 알림 값으로 채운 검색의 건수·상위 값·최근 로그, 답을 처리 기록 메모로 */
async function playbookSection(box, alert, noted) {
  box.innerHTML = '<div class="skeleton" style="height:80px"></div>';
  let pb;
  try {
    pb = await api.get(`/api/alerts/${alert.id}/playbook`);
  } catch (err) {
    box.innerHTML = errorBox(err);
    return;
  }
  if (!pb.available) {
    box.innerHTML = html`<p class="muted" style="font-size:13px">이 규칙의 플레이북이 없습니다 — 규칙 번호로 <code>config/playbooks/&lt;번호&gt;.yaml</code> 을 만들면 여기에 나옵니다.</p>`;
    return;
  }
  if (pb.error) { box.innerHTML = errorBox(new Error(pb.error)); return; }
  const link = (s) => `#/events?${qs({ since: s.since, until: s.until, query: s.query })}`;
  box.innerHTML = html`<ol class="pb-steps">${pb.steps.map((s, i) => html`<li>
      <div><b>${s.question}</b></div>
      ${s.why ? html`<div class="muted pb-why">${s.why}</div>` : ''}
      ${s.missing ? html`<div class="muted pb-why">이 알림에 ${s.missing.join('·')} 값이 없어 건너뜁니다.</div>`
        : s.error ? html`<div class="tag-bad pb-why">${s.error}</div>` : html`
        <div class="pb-run"><code>${s.query}</code> <span class="num"><b>${fmtNum(s.count)}</b>건</span>
          <a href="${link(s)}" data-pb-link>검색에서 보기 →</a></div>
        ${s.top.length ? html`<div class="pb-top">${s.top.map((t) => html`<span class="type-tag">${t.value ?? '(없음)'} <b class="num">${fmtNum(t.n)}</b></span>`)}</div>` : ''}
        ${s.events.length ? html`<ul class="pb-events">${s.events.map((e) => html`<li data-pb-ev="${e.id}" title="이 로그 상세">
          <span class="num muted">${fmtTime(e.ts)}</span> ${e.host}${e.username ? ` · ${e.username}` : ''}${e.src_ip ? ` · ${e.src_ip}` : ''}
          <span class="ink-2">${e.message}</span></li>`)}</ul>` : ''}`}
      <div class="pb-answer"><input class="input" data-pb-answer="${i}" maxlength="500" placeholder="답 (예: 내부 PC 한 대, 백업 계정)">
        <button class="btn sm" type="button" data-pb-note="${i}">메모로 남기기</button></div>
    </li>`)}</ol>
    ${pb.false_positive ? html`<div class="hint-box" style="white-space:pre-line;margin-top:8px"><b>오탐 판단 기준</b>
${pb.false_positive}</div>` : ''}`;
  box.querySelectorAll('[data-pb-link]').forEach((a) => a.addEventListener('click', () => document.querySelector('.drawer-overlay')?.click()));
  box.querySelectorAll('[data-pb-ev]').forEach((li) => li.addEventListener('click', () => openEvent(Number(li.dataset.pbEv))));
  box.querySelectorAll('[data-pb-note]').forEach((b) => b.addEventListener('click', async () => {
    const i = Number(b.dataset.pbNote);
    const answer = box.querySelector(`[data-pb-answer="${i}"]`).value.trim();
    if (!answer) { box.querySelector(`[data-pb-answer="${i}"]`).focus(); return; }
    b.disabled = true;
    try {
      await api.send('POST', `/api/alerts/${alert.id}/notes`, { text: `[조사] ${pb.steps[i].question} — ${answer}` });
      await noted();
    } catch (err) {
      b.disabled = false;
      box.insertAdjacentHTML('beforeend', String(errorBox(err)));
    }
  }));
}

/** 해결 / 다시 열기 양식: 조치 내용(선택) + (해결) 같은 규칙·대상의 해결 안 된 다른 알림도 함께 */
function handleForm(box, kind, related, submit) {
  const resolve = kind === 'resolve';
  box.innerHTML = html`<div class="inline-form">
    ${resolve ? html`<label class="field"><span>종료 분류 <small class="muted">(필수 — 규칙별 오탐률에 쓰임)</small></span>${resolutionSelect()}</label>` : ''}
    <label class="field"><span>${resolve ? '조치 내용' : '다시 여는 이유'} <small class="muted">(선택, 처리 기록에 남음)</small></span>
      <textarea class="input" rows="2" maxlength="2000" data-text placeholder="${resolve ? '예: 계정 잠금 해제, 사용자 비밀번호 초기화' : '예: 같은 증상 재발'}"></textarea></label>
    ${resolve && related ? html`<label class="check-row"><input type="checkbox" data-related checked>
      같은 규칙·대상의 해결 안 된 다른 알림 ${fmtNum(related)}건도 함께 해결</label>` : ''}
    <div class="toolbar"><button class="btn ${resolve ? 'primary' : ''}" data-ok>${resolve ? '해결로 표시' : '다시 열기'}</button>
      <button class="btn ghost" data-cancel>취소</button></div>
    <div data-err></div></div>`;
  (box.querySelector('[data-resolution]') || box.querySelector('[data-text]')).focus();
  box.querySelector('[data-cancel]').addEventListener('click', () => { box.innerHTML = ''; box.dataset.kind = ''; });
  box.querySelector('[data-ok]').addEventListener('click', async (e) => {
    const resolution = box.querySelector('[data-resolution]')?.value || null;
    if (resolve && !resolution) {
      box.querySelector('[data-err]').innerHTML = errorBox(new Error('종료 분류를 고르세요 (정탐·오탐·판단 불가)'));
      box.querySelector('[data-resolution]').focus();
      return;
    }
    e.target.disabled = true;
    try {
      await submit(box.querySelector('[data-text]').value.trim(), !!box.querySelector('[data-related]')?.checked, resolution);
    } catch (err) {
      e.target.disabled = false;
      box.querySelector('[data-err]').innerHTML = errorBox(err);
    }
  });
}

/** 무음 양식 (알림 상세에서): 이 규칙·이 대상 / 이 규칙 전체, 기간, 사유 */
function silenceForm(box, alert, done) {
  const hasKey = alert.group_key !== '';
  // 처음 보는 값(B-47)은 대상 이름이 값 조합 — 그 PC 의 점검이면 PC 로 거는 것을 먼저(PC 범위 사용자는 PC 로만 걸 수 있다)
  const pc = alert.terms_host || '';
  box.innerHTML = html`<div class="inline-form">
    <p class="muted" style="margin:0;font-size:12.5px">무음 동안에도 알림은 이력에 남고, 보내기만 하지 않습니다. 끝난 뒤에도 새 로그가 들어오면 바로 다시 알립니다.</p>
    <div class="field"><span>범위</span><div class="seg" data-scope>
      ${pc ? html`<button type="button" data-v="pc" class="on">이 규칙 · PC ${pc}</button>` : ''}
      ${hasKey ? html`<button type="button" data-v="one" class="${pc ? '' : 'on'}">이 규칙 · ${alert.group_key}</button>` : ''}
      <button type="button" data-v="rule" class="${hasKey || pc ? '' : 'on'}">이 규칙 전체</button></div></div>
    <div class="field"><span>기간 (지금부터)</span><div class="seg" data-dur>${SILENCE_DURATIONS.map(([sec, label], i) => html`
      <button type="button" data-v="${sec}" class="${i === 0 ? 'on' : ''}">${label}</button>`)}</div></div>
    <label class="field"><span>사유 <em>*</em></span><input class="input" data-reason maxlength="500" placeholder="예: 정기 패치 작업 (변경 요청 CR-1234)"></label>
    <div class="toolbar"><button class="btn primary" data-ok>무음 걸기</button><button class="btn ghost" data-cancel>취소</button></div>
    <div data-err></div></div>`;
  box.querySelectorAll('.seg').forEach((seg) => seg.querySelectorAll('button').forEach((b) => b.addEventListener('click', () => {
    seg.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === b));
  })));
  box.querySelector('[data-reason]').focus();
  box.querySelector('[data-cancel]').addEventListener('click', () => { box.innerHTML = ''; box.dataset.kind = ''; });
  box.querySelector('[data-ok]').addEventListener('click', async (e) => {
    const reason = box.querySelector('[data-reason]').value.trim();
    if (!reason) { box.querySelector('[data-reason]').focus(); return; }
    const scope = box.querySelector('[data-scope] .on').dataset.v;
    e.target.disabled = true;
    try {
      await api.send('POST', '/api/alerts/silences', {
        rule: alert.rule, group_key: scope === 'pc' ? pc : scope === 'one' ? alert.group_key : null, reason,
        ...(scope === 'pc' ? { target: 'pc' } : {}),
        duration_sec: Number(box.querySelector('[data-dur] .on').dataset.v),
      });
      box.innerHTML = html`<div class="hint-box">✓ 무음을 걸었습니다. 알림 화면의 '무음' 탭에서 보거나 해제합니다.</div>`;
      box.dataset.kind = '';
      done();
    } catch (err) {
      e.target.disabled = false;
      box.querySelector('[data-err]').innerHTML = errorBox(err);
    }
  });
}
