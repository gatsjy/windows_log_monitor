// 공용 유틸: 안전한 HTML 템플릿, 숫자/시간 포맷, 라우팅 헬퍼.

/** html`` 결과물. 문자열로 쓰면 그대로 HTML 이 된다 (innerHTML = html`...`). */
export class SafeHTML {
  constructor(s) { this.s = s; }
  toString() { return this.s; }
}

/** 이미 안전하다고 확인된 문자열을 이스케이프 없이 넣을 때 */
export const raw = (s) => new SafeHTML(String(s ?? ''));

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ESC[c]);

function part(v) {
  if (v == null || v === false) return '';
  if (v instanceof SafeHTML) return v.s;
  if (Array.isArray(v)) return v.map(part).join('');
  return esc(v);
}

/** 템플릿 안의 값은 자동 이스케이프된다. 중첩 html`` 은 그대로 들어간다. */
export function html(strings, ...values) {
  let out = strings[0];
  values.forEach((v, i) => { out += part(v) + strings[i + 1]; });
  return new SafeHTML(out);
}

// ------------------------------------------------------------- numbers
const nf = new Intl.NumberFormat('ko-KR');
const compact = new Intl.NumberFormat('ko-KR', { notation: 'compact', maximumFractionDigits: 1 });

export const fmtNum = (n) => (n == null ? '–' : nf.format(n));
/** 1만 이상은 '1.2만' 처럼 줄여서 */
export const fmtCompact = (n) => (n == null ? '–' : Math.abs(n) < 10000 ? nf.format(n) : compact.format(n));

// --------------------------------------------------------------- times
const pad = (n) => String(n).padStart(2, '0');

/** 브라우저 시간대 기준 'YYYY-MM-DD HH:mm:ss' */
export function fmtTime(value, { seconds = true, date = true } = {}) {
  if (!value) return '–';
  const d = value instanceof Date ? value : new Date(value);
  const day = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}${seconds ? ':' + pad(d.getSeconds()) : ''}`;
  return date ? `${day} ${time}` : time;
}

export function fmtRelative(value) {
  if (!value) return '–';
  const s = (Date.now() - new Date(value).getTime()) / 1000;
  if (s < 0) return '방금';
  if (s < 10) return '방금';
  if (s < 60) return `${Math.floor(s)}초 전`;
  if (s < 3600) return `${Math.floor(s / 60)}분 전`;
  if (s < 86400) return `${Math.floor(s / 3600)}시간 전`;
  return `${Math.floor(s / 86400)}일 전`;
}

export function fmtDuration(sec) {
  if (sec < 60) return `${sec}초`;
  if (sec < 3600) return `${Math.round(sec / 60)}분`;
  if (sec < 86400) return `${Math.round(sec / 3600)}시간`;
  return `${Math.round(sec / 86400)}일`;
}

export const TIME_RANGES = [
  ['15m', '최근 15분'], ['1h', '최근 1시간'], ['6h', '최근 6시간'], ['24h', '최근 24시간'],
  ['7d', '최근 7일'], ['30d', '최근 30일'], ['90d', '최근 90일'],
];
export const rangeLabel = (v) => (TIME_RANGES.find(([k]) => k === v) || [, v])[1];

// -------------------------------------------------------------- misc
export function debounce(fn, ms = 300) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

/** 빈 값을 뺀 쿼리 문자열 */
export function qs(params = {}) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    sp.set(k, Array.isArray(v) ? v.join(',') : v);
  }
  return sp.toString();
}

/** 다른 화면으로 이동: navigate('events', { host: 'WEB-01' }) */
export function navigate(view, params = {}) {
  const q = qs(params);
  location.hash = `#/${view}${q ? '?' + q : ''}`;
}

/** 현재 화면에 머물면서 주소창의 파라미터만 바꾼다 (화면 재마운트 없음) */
export function replaceParams(view, params = {}) {
  const q = qs(params);
  history.replaceState(null, '', `#/${view}${q ? '?' + q : ''}`);
}

export const tzOffset = () => -new Date().getTimezoneOffset();

/** localStorage 는 사생활 보호 모드 등에서 실패할 수 있다 */
export const store = {
  get(key, fallback = null) { try { const v = localStorage.getItem(key); return v == null ? fallback : JSON.parse(v); } catch { return fallback; } },
  set(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* 무시 */ } },
};

export function errorBox(err) {
  return html`<div class="error-box">${err?.message || String(err)}</div>`;
}

export { alertModal, confirmModal, promptModal, toast } from './dialog.js';
