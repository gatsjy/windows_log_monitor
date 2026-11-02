// 알림 규칙 편집기 (오른쪽 패널). 입력 양식으로 규칙 한 개를 만들고, Snort 식 한 줄 규칙 문장과
// 우리말 요약을 실시간으로 보여 준다. 저장하면 서버가 config/alerts.yaml 의 그 규칙 블록만 바꾼다.
import * as api from './api.js';
import { GROUP_LABELS, matchText } from './alertdetail.js';
import { closeDrawer, openDrawer } from './drawer.js';
import { CATEGORY_LABELS, LEVELS, SEVERITIES, categoryLabel, levelIcon, severityBadge } from './levels.js';
import { queryBox } from './querybox.js';
import { runTest } from './ruletest.js';
import { confirmModal, errorBox, fmtNum, html, raw, toast } from './util.js';

const UNITS = [['s', '초', 1], ['m', '분', 60], ['h', '시간', 3600], ['d', '일', 86400]];
const GROUP_BY = [['host', 'PC'], ['ip', '출발지 IP'], ['user', '사용자'], ['category', '분류'], ['event_id', '이벤트 ID'],
  ['channel', '채널'], ['none', '전체 합산']];
const TRACK = { host: 'by_host', ip: 'by_src', user: 'by_user', category: 'by_category', event_id: 'by_event', channel: 'by_channel', none: 'none' };
// 서로 다른 값 수 (ADR-041): 묶음마다 이 필드의 서로 다른 값이 N개 이상일 때만 — 패스워드 스프레이, 한 계정의 여러 PC 접속
const DISTINCT = [['user', '사용자'], ['host', 'PC'], ['ip', '출발지 IP'], ['event_id', '이벤트 ID']];
export const distinctText = (d) => (d?.field ? `서로 다른 ${GROUP_LABELS[d.field] ?? d.field.replace(/^f\./, '')} ${fmtNum(d.min)}개 이상` : '');
const SEV_ORDER = ['critical', 'error', 'warning', 'info'];
// 처음 보는 값 (B-47): 볼 값. 계정은 표기 통일(account) — 공격자가 정하는 이름(4625·IIS·sshd)이면 사용자(그대로)를 권한다
const TERM_FIELDS = [['account', '계정(표기 통일)'], ['user', '사용자(그대로)'], ['ip', '출발지 IP'], ['host', 'PC'], ['event_id', '이벤트 ID'],
  ['channel', '채널'], ['provider', '공급자']];
const termLabel = (k) => TERM_FIELDS.find(([x]) => x === k)?.[1] ?? k.replace(/^f\./, '원본 ');
const MATCH_FIELDS = ['category', 'level', 'event_id', 'host', 'user', 'ip', 'source', 'channel', 'provider', 'q', 'query', 'saved'];

function splitUnit(sec) {
  const [key] = [...UNITS].reverse().find(([, , size]) => sec % size === 0 && sec >= size) || UNITS[0];
  const size = UNITS.find(([k]) => k === key)[2];
  return { n: sec / size, unit: key };
}
const unitSize = (key) => UNITS.find(([k]) => k === key)[2];
const quote = (s) => `"${String(s).replace(/"/g, '\\"')}"`;
const list = (v) => String(v || '').split(',').map((x) => x.trim()).filter(Boolean);
// 해결 방식 (B-35 2단계): 비어 있으면 종류의 기본값 — 끊김 규칙(PC·채널)은 auto, 건수 규칙은 manual (서버 rules.py SILENT_KINDS 와 같음)
const SILENT = new Set(['agent_silent', 'stream_silent']);
const resolveOf = (r) => r.resolve || (SILENT.has(r.kind) ? 'auto' : 'manual');
const defaultResolve = (r) => (SILENT.has(r.kind) ? 'auto' : 'manual');

/** 편집 중인 값 → Snort 식 한 줄 규칙 (보기 전용) */
export function signature(r) {
  const parts = [`msg:${quote(r.name || '(이름 없음)')}`];
  if (r.kind === 'stream_silent') {
    parts.push('stream:silent');
    parts.push(`hosts:${r.hosts.length ? r.hosts.join(',') : 'any'}`);
    parts.push(`channels:${r.channels.length ? quote(r.channels.join(',')) : 'any'}`);
  } else if (r.kind === 'agent_silent') {
    parts.push(`heartbeat:silent ${r.silent_for_sec}s`);
    parts.push(`hosts:${r.hosts.length ? r.hosts.join(',') : 'any'}`);
  } else if (r.kind === 'new_terms') {
    Object.entries(r.match).forEach(([k, v]) => { if (v) parts.push(k.startsWith('f.') ? `field:${k.slice(2)}=${quote(v)}` : `${k}:${quote(v)}`); });
    parts.push(`new_terms:track ${r.terms.join('+') || '?'}, history ${r.history_sec}s, learn ${r.learn_sec}s`);
  } else {
    Object.entries(r.match).forEach(([k, v]) => {
      if (!v) return;
      // 검색 문장은 query:"…" (Snort 의 msg: 와 겹치지 않게)
      parts.push(k.startsWith('f.') ? `field:${k.slice(2)}=${quote(v)}` : k === 'q' ? `content:${quote(v)}`
        : k === 'query' || k === 'saved' ? `${k}:${quote(v)}` : `${k}:${v}`);
    });
    parts.push(`threshold:type both, track ${TRACK[r.group_by] || `by_${r.group_by.replace(/^f\./, '')}`}, count ${r.threshold}, seconds ${r.window_sec}`);
    if (r.distinct?.field) parts.push(`distinct:${TRACK[r.distinct.field] || `by_${r.distinct.field.replace(/^f\./, '')}`} ${r.distinct.min}`);
    parts.push(`cooldown:${r.cooldown_sec}`);
  }
  if (resolveOf(r) !== defaultResolve(r)) parts.push(`resolve:${resolveOf(r)}`);
  if (r.mode === 'observe' && !SILENT.has(r.kind)) parts.push('mode:observe');
  if (r.notify.length) parts.push(`notify:${quote(r.notify.join(','))}`);
  r.tags.forEach((t) => parts.push(`reference:${t}`));
  if (r.group) parts.push(`classtype:${quote(r.group)}`);
  parts.push(`sid:${r.sid || 'auto'}`);
  return `${r.enabled ? 'alert' : '# alert'} ${r.severity} (${parts.join('; ')};)`;
}

/** 편집 중인 값 → 우리말 한 문장 */
export function sentence(r) {
  const sev = SEVERITIES[r.severity]?.label ?? r.severity;
  const to = r.notify.length ? `'${r.notify.join("', '")}'에` : '(받는 곳 없음)';
  if (r.kind === 'agent_silent') {
    return `${r.hosts.length ? r.hosts.join(', ') : '모든 PC'}에서 ${fmtSec(r.silent_for_sec)} 이상 로그가 오지 않으면 ${to} [${sev}] 알림.`
      + (resolveOf(r) === 'auto' ? ' 다시 들어오면 자동으로 해결하고 해소 통지.' : '');
  }
  if (r.kind === 'stream_silent') {
    return `${r.hosts.length ? r.hosts.join(', ') : '모든 PC'}에서 늘 오던 ${r.channels.length ? r.channels.join(', ') : '채널'} 로그가 평소보다 오래 끊기면`
      + ` (PC 는 살아 있는데) ${to} [${sev}] 알림.` + (resolveOf(r) === 'auto' ? ' 다시 들어오면 자동으로 해결하고 해소 통지.' : '');
  }
  if (r.kind === 'new_terms') {
    const what = r.terms.length ? r.terms.map(termLabel).join(' + ') : '(볼 값 없음)';
    return `${matchText(r.match)} 로그에서 ${what} 조합이 최근 ${fmtSec(r.history_sec)} 동안 처음 보이면 ${to} [${sev}] 알림. `
      + `처음 ${fmtSec(r.learn_sec)}은 배우기만 합니다(지난 로그가 있으면 거슬러 배움). 한 번에 ${fmtNum(r.burst)}개 넘게 새로 보이면 한 통으로, `
      + `값 조합은 ${fmtNum(r.max_terms)}개까지 둡니다.` + (r.mode === 'observe' ? ' 지금은 관찰 모드 — 기록만 하고 보내지 않음.' : '');
  }
  const by = r.group_by === 'none' ? '전체를 합산해서' : `${GROUP_LABELS[r.group_by] ?? r.group_by.replace(/^f\./, '')}마다 따로 세어`;
  const distinct = r.distinct?.field ? `이고 ${distinctText(r.distinct)}` : '';
  const observe = r.mode === 'observe' ? ' 지금은 관찰 모드 — 기록만 하고 보내지 않음.' : '';
  return `${matchText(r.match)} 로그가 ${fmtSec(r.window_sec)} 동안 ${fmtNum(r.threshold)}건 이상${distinct}이면, ${by} ${to} [${sev}] 알림. `
    + `같은 대상은 ${fmtSec(r.cooldown_sec)} 동안 다시 알리지 않음.`
    + (resolveOf(r) === 'auto' ? ` ${fmtSec(r.window_sec)} 동안 기준 아래로 내려가면 자동으로 해결하고 해소 통지.` : '') + observe;
}
function fmtSec(sec) {
  const { n, unit } = splitUnit(sec);
  return `${n}${UNITS.find(([k]) => k === unit)[1]}`;
}

function unitInput(name, sec) {
  const { n, unit } = splitUnit(sec);
  return html`<span class="unit-input"><input class="input num" type="number" min="1" data-num="${name}" value="${n}">
    <select class="select" data-unit="${name}">${UNITS.map(([k, l]) => html`<option value="${k}" ${k === unit ? 'selected' : ''}>${l}</option>`)}</select></span>`;
}

/**
 * @param {{rule?: object, config: object, onSaved: () => void, defaults?: {group?: string}}} opt
 *   rule = /api/alerts/config 의 규칙 항목 (없으면 새 규칙), config = 같은 응답 (그룹·알림 대상 목록)
 */
export async function openRuleEditor({ rule, config, onSaved, defaults = {} }) {
  const isNew = !rule;
  const r = {
    name: rule?.name ?? '', sid: rule?.sid ?? null, group: rule?.group ?? defaults.group ?? '', description: rule?.description ?? '',
    kind: rule?.kind ?? 'count', enabled: rule?.enabled ?? true, severity: rule?.severity ?? 'warning',
    match: { ...(rule?.match ?? {}) }, group_by: rule?.group_by ?? 'host',
    window_sec: rule?.window_sec ?? 300, threshold: rule?.threshold ?? 5, cooldown_sec: rule?.cooldown_sec ?? 1800,
    silent_for_sec: rule?.silent_for_sec ?? 600, hosts: [...(rule?.hosts ?? [])], channels: [...(rule?.channels ?? [])],
    notify: [...(rule?.notify ?? (config.notifiers[0] ? [config.notifiers[0].name] : []))], tags: [...(rule?.tags ?? [])],
    distinct: rule?.distinct ? { ...rule.distinct } : null,
    resolve: rule?.resolve ?? '',
    mode: rule?.mode ?? 'active',
    // 처음 보는 값 (B-47) — 'fields' 는 아래 원본 필드 조건이 쓰는 이름이라 terms 로
    terms: [...(rule?.fields?.length ? rule.fields : ['account', 'ip'])], history_sec: rule?.history_sec ?? 30 * 86400,
    learn_sec: rule?.learn_sec ?? 14 * 86400, max_terms: rule?.max_terms ?? 50000, burst: rule?.burst ?? 20,
  };
  // 로그 하나로 시험 (B-52): 조건을 바꾸면 폼을 다시 그리므로 입력·결과를 여기 둔다 — 바꾼 조건으로 같은 로그를 다시 시험하게
  const test = { id: '', sample: '', open: false, out: '' };
  const body = openDrawer({ title: isNew ? '새 알림 규칙' : '알림 규칙 수정', subtitle: isNew ? '규칙 번호(SID)는 저장할 때 자동으로 붙습니다' : `SID ${r.sid ?? '–'} · ${r.group || '기타'}` });
  body.innerHTML = '<div class="skeleton"></div>';
  const [meta, fields, searches] = await Promise.all([
    api.get('/api/meta').catch(() => ({ categories: CATEGORY_LABELS })),
    api.get('/api/fields').catch(() => ({ items: [] })),
    api.get('/api/searches').catch(() => ({ items: [] })),
  ]);
  // 저장한 검색(B-64) — 고른 것이 목록에 없으면(지워졌거나 남의 비공개 검색) 이름만 남겨 둔다
  const savedNames = searches.items.map((x) => x.name);
  if (r.match.saved && !savedNames.includes(r.match.saved)) savedNames.unshift(r.match.saved);
  const categories = Object.keys(meta.categories || CATEGORY_LABELS);
  const groups = [...new Set(config.rules.map((x) => x.group).filter(Boolean))];
  const fieldPaths = [...new Set(fields.items.map((f) => f.path))].slice(0, 300);
  // 원본 필드 조건은 [경로, 값] 배열로 따로 둔다 (아직 경로를 안 적은 빈 행도 보여 줘야 하므로)
  r.fields = Object.entries(r.match).filter(([k]) => k.startsWith('f.')).map(([k, v]) => [k.slice(2), v]);
  Object.keys(r.match).filter((k) => k.startsWith('f.')).forEach((k) => delete r.match[k]);
  const fullMatch = () => ({
    ...r.match,
    ...Object.fromEntries(r.fields.filter(([k, v]) => k.trim() && String(v).trim()).map(([k, v]) => [`f.${k.trim().replace(/^f\./, '')}`, String(v).trim()])),
  });
  const view = () => ({ ...r, match: fullMatch() });

  function render() {
    const cats = new Set(list(r.match.category));
    const lvls = new Set(list(r.match.level));
    body.innerHTML = html`
      <div class="rule-preview">
        <div class="sig" data-sig></div>
        <p class="rule-sentence" data-sentence></p>
      </div>

      <section class="form-section">
        <h3>기본 정보</h3>
        <label class="field"><span>규칙 이름 <em>*</em></span><input class="input" data-k="name" value="${r.name}" placeholder="예: 원격 데스크톱 무차별 대입" maxlength="120"></label>
        <div class="form-row">
          <label class="field"><span>규칙 묶음</span><input class="input" data-k="group" list="rule-groups" value="${r.group}" placeholder="예: 계정·인증 공격">
            <datalist id="rule-groups">${groups.map((g) => html`<option value="${g}">`)}</datalist></label>
          <label class="field" style="max-width:160px"><span>규칙 번호 (SID)</span><input class="input num" data-k="sid" value="${r.sid ?? ''}" placeholder="자동" inputmode="numeric"></label>
        </div>
        <label class="field"><span>설명</span><input class="input" data-k="description" value="${r.description}" placeholder="무엇을 잡는 규칙인지 (알림 메일에 함께 나감)"></label>
        <div class="field"><span>심각도</span>
          <div class="seg" data-sev>${SEV_ORDER.map((k) => html`<button type="button" data-v="${k}" class="${r.severity === k ? 'on' : ''}">${severityBadge(k)}</button>`)}</div></div>
        <label class="switch-row"><button type="button" class="switch ${r.enabled ? 'on' : ''}" role="switch" aria-checked="${r.enabled}" data-enabled></button>규칙 사용</label>
      </section>

      <section class="form-section">
        <h3>무엇을 감지하나요</h3>
        <div class="seg" data-kind>
          <button type="button" data-v="count" class="${r.kind === 'count' ? 'on' : ''}">로그 건수</button>
          <button type="button" data-v="agent_silent" class="${r.kind === 'agent_silent' ? 'on' : ''}">PC 수신 끊김</button>
          <button type="button" data-v="stream_silent" class="${r.kind === 'stream_silent' ? 'on' : ''}">채널 끊김</button>
          <button type="button" data-v="new_terms" class="${r.kind === 'new_terms' ? 'on' : ''}">처음 보는 값</button>
        </div>
      </section>

      ${r.kind === 'stream_silent' ? html`
      <section class="form-section">
        <h3>어떤 PC의 어떤 채널이</h3>
        <label class="field"><span>대상 PC (쉼표로 구분, 비우면 모든 PC)</span><input class="input" data-hosts value="${r.hosts.join(', ')}" placeholder="DC-01, FILE-01"></label>
        <label class="field"><span>볼 채널 (쉼표로 구분, 비우면 모든 채널 — 채널이 없는 로그는 소스 이름)</span><input class="input" data-channels value="${r.channels.join(', ')}" placeholder="Security, Microsoft-Windows-PowerShell/Operational"></label>
        <p class="hint-box">지난 7일 중 5일 이상 오던 채널이 평소 간격의 10배(최소 6시간) 넘게 조용하면 알립니다. PC 자체가 끊긴 것은 'PC 수신 끊김'이 따로 알립니다.
          GPO 변경으로 DC 의 Security 수집만 멈춘 경우 같은 조용한 실패를 잡습니다.</p>
      </section>` : ''}

      ${r.kind === 'stream_silent' ? '' : r.kind === 'agent_silent' ? html`
      <section class="form-section">
        <h3>어떤 PC가 얼마나 조용하면</h3>
        <label class="field"><span>대상 PC (쉼표로 구분, 비우면 모든 PC)</span><input class="input" data-hosts value="${r.hosts.join(', ')}" placeholder="WEB-01, DB-01"></label>
        <div class="field"><span>끊김 판정</span><div class="sentence-row">${unitInput('silent_for_sec', r.silent_for_sec)}<span>이상 로그·하트비트가 없으면</span></div></div>
        ${r.hosts.length ? '' : html`<p class="hint-box">비워 두면 퇴근 시 꺼지는 PC까지 알림이 갑니다. 서버만 적는 것을 권장합니다.</p>`}
      </section>` : html`
      <section class="form-section">
        <h3>어떤 로그를</h3>
        <div class="field"><span>분류</span><div class="chips">${categories.map((c) => html`
          <button type="button" class="chip ${cats.has(c) ? 'on' : ''}" data-cat="${c}">${categoryLabel(c)}</button>`)}</div></div>
        <div class="field"><span>수준</span><div class="chips">${Object.entries(LEVELS).map(([lv, m]) => html`
          <button type="button" class="chip ${lvls.has(lv) ? 'on' : ''}" data-lvl="${lv}">${levelIcon(Number(lv))}${m.label}</button>`)}</div></div>
        <div class="form-row">
          <label class="field"><span>이벤트 ID</span><input class="input" data-m="event_id" value="${r.match.event_id ?? ''}" placeholder="4625,4771"></label>
          <label class="field"><span>PC</span><input class="input" data-m="host" value="${r.match.host ?? ''}" placeholder="WEB-01,WEB-02"></label>
        </div>
        <div class="form-row">
          <label class="field"><span>사용자</span><input class="input" data-m="user" value="${r.match.user ?? ''}" placeholder="administrator"></label>
          <label class="field"><span>출발지 IP</span><input class="input" data-m="ip" value="${r.match.ip ?? ''}" placeholder="203.0.113.5"></label>
        </div>
        <label class="field"><span>메시지에 포함 (여러 단어는 <code>a|b</code> = 둘 중 하나)</span><input class="input" data-m="q" value="${r.match.q ?? ''}" placeholder="Failed password|Invalid user"></label>
        <label class="field"><span>저장한 검색 (선택 — 그 문장도 함께 만족, 검색 화면에서 고치면 다음 평가부터 반영)</span>
          <select class="select" data-m="saved"><option value="">없음</option>
            ${savedNames.map((n) => html`<option value="${n}" ${n === r.match.saved ? 'selected' : ''}>${n}</option>`)}</select></label>
        <div class="field"><span>검색 문장 (선택 — 위 조건과 모두 만족, 이벤트 검색과 같은 문법)</span><div data-rule-query></div></div>
        <div class="field"><span>원본 필드 조건</span>
          <datalist id="field-paths">${fieldPaths.map((p) => html`<option value="${p}">`)}</datalist>
          <div class="cond-list">${r.fields.map(([k, v], i) => html`<div class="cond-row">
            <input class="input" data-fk="${i}" list="field-paths" value="${k}" placeholder="EventData.LogonType">
            <span class="muted">=</span><input class="input" data-fv="${i}" value="${v}" placeholder="10">
            <button type="button" class="btn ghost sm" data-fdel="${i}" aria-label="조건 삭제">✕</button></div>`)}
            <button type="button" class="btn sm" data-fadd>+ 조건 추가</button></div></div>
        ${['source', 'channel', 'provider'].some((k) => r.match[k]) ? html`<p class="muted" style="font-size:12.5px;margin:0">
          그 밖의 조건: ${['source', 'channel', 'provider'].filter((k) => r.match[k]).map((k) => `${k}=${r.match[k]}`).join(', ')}</p>` : ''}
      </section>

      ${r.kind === 'new_terms' ? html`<section class="form-section">
        <h3>어떤 값이 처음이면</h3>
        <div class="field"><span>볼 값 (1~3개 — 이 조합이 처음이면 알림)</span><div class="chips">${TERM_FIELDS.map(([k, l]) => html`
          <button type="button" class="chip ${r.terms.includes(k) ? 'on' : ''}" data-term="${k}">${l}</button>`)}
          ${r.terms.filter((k) => k.startsWith('f.')).map((k) => html`<button type="button" class="chip on" data-term="${k}">${termLabel(k)} ✕</button>`)}</div>
          <div class="sentence-row" style="margin-top:6px"><input class="input" data-term-path list="field-paths" placeholder="원본 필드 (예: EventData.ServiceName)" style="max-width:280px">
            <button type="button" class="btn sm" data-term-add>+ 원본 필드</button></div></div>
        ${r.terms.includes('account') && /\b(4625|4771|18456)\b/.test(`${r.match.event_id ?? ''} ${r.match.query ?? ''}`) ? html`<p class="hint-box">로그온 실패의 계정은 공격자가 정합니다 — 표기 통일(계정)은 다른 표기로 비켜 가거나 값을 넘치게 할 수 있어 '사용자(그대로)'를 권합니다.</p>` : ''}
        <div class="sentence-row"><span>최근</span>${unitInput('history_sec', r.history_sec)}<span>동안 안 보였으면 새 값 (다시 보이면 또 알림)</span></div>
        <div class="sentence-row"><span>처음</span>${unitInput('learn_sec', r.learn_sec)}<span>은 배우기만 (지난 로그로 거슬러 배움)</span></div>
        <div class="sentence-row"><span>한 번에</span><input class="input num" type="number" min="1" max="100" data-k="burst" value="${r.burst}" style="width:80px">
          <span>개 넘게 새로 보이면 한 통으로 · 값 조합은</span><input class="input num" type="number" min="100" max="500000" data-k="max_terms" value="${r.max_terms}" style="width:110px"><span>개까지</span></div>
      </section>` : html`<section class="form-section">
        <h3>얼마나 자주면</h3>
        <div class="sentence-row">${unitInput('window_sec', r.window_sec)}<span>동안</span>
          <input class="input num" type="number" min="1" data-k="threshold" value="${r.threshold}" style="width:90px"><span>건 이상이면 알림</span></div>
        <div class="sentence-row"><select class="select" data-k="group_by">${GROUP_BY.map(([k, l]) => html`<option value="${k}" ${r.group_by === k ? 'selected' : ''}>${l}</option>`)}
          ${GROUP_BY.some(([k]) => k === r.group_by) ? '' : html`<option value="${r.group_by}" selected>${r.group_by}</option>`}</select>
          <span>${r.group_by === 'none' ? '(모든 로그를 합쳐서 셈)' : '마다 따로 세고 따로 알림'}</span></div>
        <div class="sentence-row"><span>그중 서로 다른</span>
          <select class="select" data-dfield><option value="">(따지지 않음)</option>${DISTINCT.filter(([k]) => k !== r.group_by).map(([k, l]) => html`<option value="${k}" ${r.distinct?.field === k ? 'selected' : ''}>${l}</option>`)}</select>
          ${r.distinct?.field ? html`<input class="input num" type="number" min="2" data-dmin value="${r.distinct.min}" style="width:80px"><span>개 이상일 때만</span>`
            : html`<span class="muted" style="font-size:12.5px">예) 한 IP 에서 서로 다른 계정 10개 = 패스워드 스프레이</span>`}</div>
        <div class="sentence-row"><span>같은 대상은</span>${unitInput('cooldown_sec', r.cooldown_sec)}<span>동안 다시 알리지 않음</span></div>
      </section>`}`}

      <section class="form-section">
        <h3>끝나면</h3>
        <div class="sentence-row"><select class="select" data-resolve aria-label="해결 방식">
          <option value="manual" ${resolveOf(r) === 'manual' ? 'selected' : ''}>담당자가 확인하고 해결</option>
          <option value="auto" ${resolveOf(r) === 'auto' ? 'selected' : ''} ${(r.kind === 'count' && r.distinct?.field) || r.kind === 'new_terms' ? 'disabled' : ''}>${SILENT.has(r.kind) ? '다시 들어오면' : '조건이 풀리면'} 자동으로 해결하고 해소 통지</option>
        </select></div>
        <p class="muted" style="font-size:12.5px;margin:6px 0 0">${SILENT.has(r.kind) ? '다시 들어오면 끝난 것이 분명합니다. 알림을 받은 곳에만 해소 통지를 보냅니다.'
          : r.distinct?.field ? '서로 다른 값 수 규칙은 보안 규칙이라 담당자가 해결합니다.'
          : '오류 다발처럼 건수가 오르내리는 운영 규칙에만 권합니다. 한 번 나는 이벤트(서비스 종료 등)는 조용해져도 고쳐진 것이 아니고, 보안 규칙은 담당자가 검토해야 합니다.'}</p>
      </section>

      <section class="form-section">
        <h3>누구에게</h3>
        ${SILENT.has(r.kind) ? '' : html`<div class="sentence-row"><select class="select" data-mode aria-label="알림 보내기">
          <option value="active" ${r.mode !== 'observe' ? 'selected' : ''}>바로 보냄</option>
          <option value="observe" ${r.mode === 'observe' ? 'selected' : ''}>관찰 — 알림을 기록만 하고 보내지 않음</option>
        </select></div>
        <p class="muted" style="font-size:12.5px;margin:6px 0 10px">새 규칙은 관찰로 며칠 두고 알림 이력('관찰' 표시)에서 오탐을 본 뒤 규칙 목록의 '관찰 끝내기'로 켜는 것을 권합니다. 관찰로 돌리는 것은 탐지 약화로 다른 관리자에게 알립니다.</p>`}
        ${config.notifiers.length ? html`<div class="check-list">${config.notifiers.map((n) => html`
          <label><input type="checkbox" data-notify="${n.name}" ${r.notify.includes(n.name) ? 'checked' : ''}>${n.name}
            <span class="muted" style="font-size:12px">${n.type === 'email' ? '메일' : n.type}</span></label>`)}</div>`
          : html`<p class="hint-box">알림 대상이 없습니다. 환경설정에서 수신 그룹이나 외부 연동을 먼저 만드세요.</p>`}
        <label class="field"><span>태그 (쉼표로 구분 — MITRE 기법, ISMS 항목)</span><input class="input" data-tags value="${r.tags.join(', ')}" placeholder="MITRE T1110, ISMS 2.11.3"></label>
      </section>

      <section class="form-section">
        <h3>미리보기</h3>
        <p class="muted" style="margin:0 0 8px;font-size:13px">최근 24시간 로그에 이 규칙을 적용했다면 알림이 몇 번 울렸을지 계산합니다 (근사치).</p>
        <button type="button" class="btn" data-preview>최근 24시간으로 시험</button>
        <div data-preview-out style="margin-top:10px"></div>
      </section>

      ${SILENT.has(r.kind) ? '' : html`<section class="form-section">
        <h3>로그 하나로 시험</h3>
        <p class="muted" style="margin:0 0 8px;font-size:13px">이 로그가 조건에 맞는지 조건마다 보여 줍니다 — '왜 안 걸렸나'. 건수·기간은 보지 않습니다.</p>
        <div class="toolbar" style="flex-wrap:wrap"><input class="input" data-test-id inputmode="numeric" placeholder="이벤트 번호" style="max-width:160px" value="${test.id}">
          <button type="button" class="btn" data-test-run>시험</button></div>
        <details style="margin-top:8px" ${test.open ? 'open' : ''}><summary class="muted">원본 붙여넣기 (에이전트가 보낸 JSON 한 건 — 이벤트 상세의 'JSON 복사')</summary>
          <textarea class="input" data-test-sample rows="6" style="width:100%;margin-top:6px;font-family:var(--mono, monospace)" placeholder='{"log_source": "winevtlog", "EventID": 4625, "Channel": "Security", ...}'>${test.sample}</textarea></details>
        <div data-test-out style="margin-top:10px">${test.out}</div>
      </section>`}

      <div data-msg></div>
      <div class="form-actions">
        ${isNew ? '' : html`<button type="button" class="btn ghost danger" data-delete>규칙 삭제</button>`}
        <span style="flex:1"></span>
        <button type="button" class="btn" data-cancel>취소</button>
        <button type="button" class="btn primary" data-save>${isNew ? '규칙 추가' : '저장'}</button>
      </div>`;
    bind();
    mountQuery();
    refresh();
  }

  // 검색 문장 칸: 틀린 동안에는 저장·미리보기를 막는다 (서버도 ConfigError 로 거절하지만 위치를 먼저 보여 준다)
  let queryValid = true;
  let saving = false;   // 저장 요청 중에는 문장을 고쳐도 단추를 다시 켜지 않는다
  function mountQuery() {
    const el = body.querySelector('[data-rule-query]');
    if (!el) return;
    queryBox(el, {
      value: r.match.query ?? '',
      label: '규칙 검색 문장',
      staleNote: false,
      placeholder: '예) -user:svc_backup "잘못된 암호"',
      fieldBudget: () => 10 - r.fields.filter(([k, v]) => k.trim() && String(v).trim()).length,
      onCommit: () => {},
      onAnalyze: (terms, text) => {
        queryValid = Boolean(terms);
        setMatch('query', (text ?? '').trim());
        body.querySelectorAll('[data-save], [data-preview]').forEach((b) => {
          b.disabled = !queryValid || (saving && b.hasAttribute('data-save'));
          b.title = queryValid ? '' : '검색 문장의 오류를 먼저 고치세요';
        });
        if (body.querySelector('[data-sig]')) refresh();
      },
    });
  }

  function refresh() {
    body.querySelector('[data-sig]').textContent = signature(view());
    body.querySelector('[data-sentence]').textContent = sentence(view());
  }

  function setMatch(key, value) {
    if (value) r.match[key] = value; else delete r.match[key];
  }

  function bind() {
    body.querySelectorAll('[data-k]').forEach((el) => el.addEventListener('input', () => {
      const k = el.dataset.k;
      r[k] = ['threshold', 'burst', 'max_terms'].includes(k) ? Math.max(1, Number(el.value) || 1)
        : k === 'sid' ? (el.value.trim() ? Number(el.value) : null) : el.value;
      if (k === 'group_by') render(); else refresh();
    }));
    body.querySelector('[data-dfield]')?.addEventListener('change', (e) => {
      r.distinct = e.target.value ? { field: e.target.value, min: r.distinct?.min ?? 10 } : null;
      if (r.distinct && r.resolve === 'auto') r.resolve = '';   // 서로 다른 값 수 규칙은 자동 해결할 수 없다
      render();
    });
    body.querySelector('[data-resolve]').addEventListener('change', (e) => { r.resolve = e.target.value; refresh(); });
    body.querySelector('[data-mode]')?.addEventListener('change', (e) => { r.mode = e.target.value; refresh(); });
    body.querySelector('[data-test-id]')?.addEventListener('input', (e) => { test.id = e.target.value; });
    body.querySelector('[data-test-sample]')?.addEventListener('input', (e) => { test.sample = e.target.value; });
    body.querySelector('[data-test-sample]')?.closest('details').addEventListener('toggle', (e) => { test.open = e.target.open; });
    body.querySelector('[data-test-run]')?.addEventListener('click', async () => {
      const out = body.querySelector('[data-test-out]');
      const text = body.querySelector('[data-test-sample]').value.trim();
      const id = Number(body.querySelector('[data-test-id]').value.trim());
      let sample = null;
      if (text) {
        try { sample = JSON.parse(text); } catch { out.innerHTML = errorBox(new Error('원본이 JSON 이 아닙니다')); return; }
      } else if (!Number.isInteger(id) || id <= 0) {
        out.innerHTML = errorBox(new Error('이벤트 번호를 넣거나 원본을 붙여 넣으세요'));
        return;
      }
      await runTest(out, sample ? { rule: payload(), sample } : { rule: payload(), event_id: id });
      test.out = raw(out.innerHTML);
    });
    body.querySelector('[data-dmin]')?.addEventListener('input', (e) => {
      r.distinct.min = Math.max(2, Number(e.target.value) || 2);
      refresh();
    });
    body.querySelectorAll('[data-num], [data-unit]').forEach((el) => el.addEventListener('input', () => {
      const name = el.dataset.num || el.dataset.unit;
      const n = Math.max(1, Number(body.querySelector(`[data-num="${name}"]`).value) || 1);
      r[name] = n * unitSize(body.querySelector(`[data-unit="${name}"]`).value);
      refresh();
    }));
    body.querySelectorAll('[data-m]').forEach((el) => el.addEventListener('input', () => { setMatch(el.dataset.m, el.value.trim()); refresh(); }));
    body.querySelectorAll('[data-sev] button').forEach((b) => b.addEventListener('click', () => {
      r.severity = b.dataset.v;
      body.querySelectorAll('[data-sev] button').forEach((x) => x.classList.toggle('on', x === b));
      refresh();
    }));
    body.querySelectorAll('[data-kind] button').forEach((b) => b.addEventListener('click', () => {
      r.kind = b.dataset.v;
      if (r.kind === 'new_terms' && r.resolve === 'auto') r.resolve = '';   // 처음 보는 값은 사람이 해결
      render();
    }));
    body.querySelectorAll('[data-term]').forEach((b) => b.addEventListener('click', () => {
      const k = b.dataset.term;
      r.terms = r.terms.includes(k) ? r.terms.filter((x) => x !== k) : r.terms.length < 3 ? [...r.terms, k] : r.terms;
      render();
    }));
    body.querySelector('[data-term-add]')?.addEventListener('click', () => {
      const path = body.querySelector('[data-term-path]').value.trim().replace(/^f\./, '');
      if (path && r.terms.length < 3 && !r.terms.includes(`f.${path}`)) { r.terms = [...r.terms, `f.${path}`]; render(); }
    });
    body.querySelector('[data-enabled]').addEventListener('click', (e) => {
      r.enabled = !r.enabled;
      e.currentTarget.classList.toggle('on', r.enabled);
      e.currentTarget.setAttribute('aria-checked', String(r.enabled));
      refresh();
    });
    const toggleList = (attr, key) => body.querySelectorAll(`[${attr}]`).forEach((b) => b.addEventListener('click', () => {
      const set = new Set(list(r.match[key]));
      const v = b.getAttribute(attr);
      set.has(v) ? set.delete(v) : set.add(v);
      b.classList.toggle('on', set.has(v));
      setMatch(key, [...set].sort().join(','));
      refresh();
    }));
    toggleList('data-cat', 'category');
    toggleList('data-lvl', 'level');
    // 원본 필드 조건
    body.querySelectorAll('[data-fk]').forEach((el) => el.addEventListener('input', () => { r.fields[el.dataset.fk][0] = el.value; refresh(); }));
    body.querySelectorAll('[data-fv]').forEach((el) => el.addEventListener('input', () => { r.fields[el.dataset.fv][1] = el.value; refresh(); }));
    body.querySelectorAll('[data-fdel]').forEach((b) => b.addEventListener('click', () => { r.fields.splice(Number(b.dataset.fdel), 1); render(); }));
    body.querySelector('[data-fadd]')?.addEventListener('click', () => {
      r.fields.push(['', '']);
      render();
      body.querySelector(`[data-fk="${r.fields.length - 1}"]`)?.focus();
    });
    body.querySelector('[data-hosts]')?.addEventListener('input', (e) => { r.hosts = list(e.target.value); refresh(); });
    body.querySelector('[data-channels]')?.addEventListener('input', (e) => { r.channels = list(e.target.value); refresh(); });
    body.querySelector('[data-tags]').addEventListener('input', (e) => { r.tags = list(e.target.value); refresh(); });
    body.querySelectorAll('[data-notify]').forEach((c) => c.addEventListener('change', () => {
      r.notify = [...body.querySelectorAll('[data-notify]:checked')].map((x) => x.dataset.notify);
      refresh();
    }));
    body.querySelector('[data-cancel]').addEventListener('click', closeDrawer);
    body.querySelector('[data-save]').addEventListener('click', save);
    body.querySelector('[data-delete]')?.addEventListener('click', remove);
    body.querySelector('[data-preview]').addEventListener('click', preview);
  }

  function payload() {
    const { fields, terms, ...rest } = view();
    return r.kind === 'new_terms' ? { ...rest, fields: terms } : rest;
  }

  async function preview() {
    const out = body.querySelector('[data-preview-out]');
    out.innerHTML = '<div class="skeleton" style="height:60px"></div>';
    try {
      const p = await api.send('POST', '/api/alerts/rules/preview', { rule: payload() });
      if (p.kind === 'stream_silent') {
        out.innerHTML = p.silent.length
          ? html`<div class="hint-box">지금 기준으로 <b>${p.silent.length}개</b> 채널이 끊김 상태입니다: ${p.silent.slice(0, 20).map((s) => `${s.host} ${s.channel}`).join(', ')}</div>`
          : html`<div class="hint-box">지금 끊김 상태인 채널이 없습니다.</div>`;
        return;
      }
      if (p.kind === 'new_terms') {
        out.innerHTML = html`
          <div class="preview-stats">
            <div><b class="num">${fmtNum(p.new)}</b><span>최근 ${p.hours}시간에 처음 보인 조합</span></div>
            <div><b class="num">${fmtNum(p.total)}</b><span>앞 ${p.lookback_days}일 포함 조합 수 (상한 ${fmtNum(p.max_terms)})</span></div>
          </div>
          ${p.items.length ? html`<div class="table-wrap"><table class="table no-stack">
            <thead><tr>${p.fields.map((k) => html`<th>${termLabel(k)}</th>`)}<th>처음</th><th class="r">건수</th></tr></thead>
            <tbody>${p.items.map((i) => html`<tr>${i.values.map((v) => html`<td>${v}</td>`)}<td class="nowrap">${String(i.first).slice(5, 16).replace('T', ' ')}</td><td class="r num">${fmtNum(i.n)}</td></tr>`)}</tbody>
          </table></div>` : ''}
          ${p.new > p.burst ? html`<p class="hint-box" style="margin-top:8px">하루 ${fmtNum(p.new)}개는 많습니다 — 한 번에 ${fmtNum(p.burst)}개가 넘으면 한 통으로 묶입니다. 조건을 좁히거나 값을 줄여 보세요.</p>` : ''}
          ${p.total > p.max_terms * 0.8 ? html`<p class="hint-box" style="margin-top:8px">조합이 상한에 가깝습니다 — 상한을 넘으면 새 값을 두지 못하고 규칙 오류로 알립니다.</p>` : ''}
          <p class="muted" style="font-size:12.5px;margin:8px 0 0">앞 ${p.lookback_days}일로 배웠다고 치고 센 근사치입니다. 실제로는 처음 ${fmtSec(r.learn_sec)} 동안 배우기만 합니다.</p>`;
        return;
      }
      if (p.kind === 'agent_silent') {
        out.innerHTML = p.silent.length
          ? html`<div class="hint-box">지금 기준으로 <b>${p.silent.length}대</b>가 끊김 상태입니다: ${p.silent.map((s) => s.host).join(', ')}</div>`
          : html`<div class="hint-box">지금 끊김 상태인 PC가 없습니다.</div>`;
        return;
      }
      out.innerHTML = html`
        <div class="preview-stats">
          <div><b class="num">${fmtNum(p.matched)}</b><span>조건에 맞는 로그</span></div>
          <div><b class="num">${fmtNum(p.fires)}</b><span>예상 알림 횟수</span></div>
          <div><b class="num">${fmtNum(p.targets)}</b><span>알림 대상(묶음 값)</span></div>
        </div>
        ${p.groups.length ? html`<div class="table-wrap"><table class="table no-stack">
          <thead><tr><th>${GROUP_BY.find(([k]) => k === r.group_by)?.[1] ?? r.group_by}</th><th class="r">알림</th><th class="r">${p.distinct ? '구간 최대 서로 다른 수' : '구간 최대 건수'}</th></tr></thead>
          <tbody>${p.groups.map((g) => html`<tr><td>${g.key || '(전체)'}</td><td class="r num">${fmtNum(g.fires)}</td><td class="r num">${fmtNum(g.max)}</td></tr>`)}</tbody>
        </table></div>` : ''}
        ${p.fires > 50 ? html`<p class="hint-box" style="margin-top:8px">하루 ${fmtNum(p.fires)}번은 많습니다. 건수를 올리거나 기간·조건을 좁혀 보세요.</p>` : ''}
        ${p.matched === 0 ? html`<p class="muted" style="font-size:12.5px;margin:8px 0 0">최근 24시간에는 맞는 로그가 없었습니다. 조건 이름·값을 확인하세요.</p>` : ''}`;
    } catch (err) {
      out.innerHTML = errorBox(err);
    }
  }

  async function save() {
    const msg = body.querySelector('[data-msg]');
    const btn = body.querySelector('[data-save]');
    if (!queryValid) return;
    saving = true;
    btn.disabled = true;
    try {
      const res = await api.send('PUT', '/api/alerts/rules', { original: isNew ? null : rule.name, rule: payload() });
      msg.innerHTML = html`<div class="hint-box">✓ 저장됨 (SID ${res.sid}) — 다음 평가부터 바로 적용됩니다</div>`;
      setTimeout(() => { closeDrawer(); onSaved?.(); }, 600);
    } catch (err) {
      msg.innerHTML = errorBox(err);
      saving = false;
      btn.disabled = !queryValid;
    }
  }

  async function remove() {
    const ok = await confirmModal({
      title: '규칙 삭제',
      message: `'${rule.name}' 규칙을 삭제할까요?\n되돌리려면 다시 만들어야 합니다. (끄기만 하려면 '규칙 사용'을 끄세요)`,
      danger: true,
      confirmText: '삭제',
    });
    if (!ok) return;
    try {
      await api.send('DELETE', `/api/alerts/rules/${encodeURIComponent(rule.name)}`);
      closeDrawer();
      onSaved?.();
      toast(`'${rule.name}' 규칙이 삭제되었습니다.`, { type: 'success' });
    } catch (err) {
      body.querySelector('[data-msg]').innerHTML = errorBox(err);
      toast(err.message, { type: 'error' });
    }
  }

  render();
}
