// 규칙 시험기 (B-52): 로그 하나가 규칙 조건에 맞는지 조건마다 기대·실제·참거짓 — '왜 안 걸렸나'.
// 서버(EventFilter.explain)가 엔진과 같은 조건(저장한 검색·걸린 예외 포함)으로 판단하고, 화면은 표로 그리기만 한다.
// 건수·기간·묶음은 보지 않는다(그것은 '미리보기').
import * as api from './api.js';
import { categoryLabel, levelLabel } from './levels.js';
import { KEY_LABELS } from './querybox.js';
import { errorBox, html } from './util.js';

const NONE = '(값 없음)';

function label(key) {
  if (key === 'scope') return '조회 범위';
  if (key === 'never') return '조건끼리';
  if (key === 'q') return KEY_LABELS.msg;
  if (key.startsWith('f.')) return `원본 ${key.slice(2)}`;
  return KEY_LABELS[key] ?? key;
}

function shown(key, value) {
  if (value === null || value === undefined || value === '') return NONE;
  if (key === 'level') return `${levelLabel(Number(value))} (${value})`;
  if (key === 'category') return categoryLabel(value);
  return String(value);
}

function expected(c) {
  const list = (vs) => vs.map((v) => shown(c.key, v)).join(', ');
  switch (c.op) {
    case 'in': return c.expected.length > 1 ? `다음 중 하나: ${list(c.expected)}` : list(c.expected);
    case 'eq': return `= ${c.expected[0]}`;
    case 'not_in': return `아님: ${list(c.expected)}`;
    case 'msg_any': return `${c.expected.map((v) => `'${v}'`).join(' 또는 ')} 포함`;
    case 'msg_not': return `${c.expected.map((v) => `'${v}'`).join(', ')} 없음`;
    case 'never': return '같은 키의 포함 조건이 겹치지 않아 어떤 로그도 맞지 않음';
    case 'scope': return c.expected.map((s) => [s.categories.join('·'), s.hosts.join('·')].filter(Boolean).join(' / ') || '전체').join(' 또는 ');
    default: return JSON.stringify(c.expected);
  }
}

function actual(c) {
  if (c.op === 'scope') return `${categoryLabel(c.actual.category)} / ${c.actual.host ?? NONE}`;
  if (c.op === 'never') return '';
  if (c.op === 'not_in' && (c.actual === null || c.actual === undefined)) return `${NONE} — 값이 없으면 빼지 않음`;
  return shown(c.key, c.actual);
}

/** 서버 결과 → 판정 줄 + 조건 표 */
export function renderTest(res) {
  const failed = res.checks.filter((c) => !c.ok);
  return html`
    <div class="hint-box ${res.matched ? '' : 'warn'}">${res.matched
      ? html`✓ 이 로그는 <b>${res.rule}</b> 조건에 맞습니다${res.checks.length ? '' : ' (조건 없음 — 모든 로그)'}. 건수·기간을 채우면 알림이 납니다.`
      : html`✕ 이 로그는 <b>${res.rule}</b> 조건에 맞지 않습니다 — 조건 ${res.checks.length}개 중 ${failed.length}개가 맞지 않음.`}
      ${res.ingest_error ? html`<div class="tag-bad">정규화 오류: ${res.ingest_error}</div>` : ''}</div>
    ${res.checks.length ? html`<div class="table-wrap"><table class="table ctx-table rule-test">
      <thead><tr><th>조건</th><th>기대</th><th>이 로그</th><th></th></tr></thead>
      <tbody>${res.checks.map((c) => html`<tr class="${c.ok ? '' : 'rule-test-fail'}">
        <td class="nowrap">${label(c.key)}${c.exception ? html`<div class="muted" style="font-size:12px">규칙 예외 '${c.exception}'</div>` : ''}</td>
        <td>${expected(c)}</td>
        <td class="ctx-msg">${actual(c)}</td>
        <td class="nowrap ${c.ok ? 'tag-good' : 'tag-bad'}">${c.ok ? '✓ 맞음' : '✕ 아님'}</td></tr>`)}</tbody></table></div>` : ''}`;
}

/**
 * @param {HTMLElement} out  결과를 그릴 곳
 * @param {{rule?: object, name?: string, event_id?: number, sample?: object}} body
 */
export async function runTest(out, body) {
  out.innerHTML = '<div class="skeleton" style="height:60px"></div>';
  try {
    out.innerHTML = renderTest(await api.send('POST', '/api/alerts/rules/test', body));
  } catch (err) {
    out.innerHTML = errorBox(err);
  }
}
