// 실시간 갱신용: 서버 filters.py 의 matches() 와 같은 규칙으로 이벤트가 위젯 조건에 맞는지 판단.
// (규칙을 바꾸면 server/app/filters.py 와 함께 고칠 것)

const LIST_KEYS = new Set(['host', 'channel', 'provider', 'source', 'category', 'user', 'ip']);
// 조건 이름 → 이벤트(API 응답) 필드 이름
const FIELD_OF = { user: 'username', ip: 'src_ip' };
const INT_KEYS = new Set(['level', 'event_id']);
const UNIT_SEC = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };

const split = (v) => String(v).split(',').map((s) => s.trim()).filter(Boolean);

/** 원본 JSON 에서 점 경로 값. 배열은 숫자 인덱스 */
export function getPath(obj, path) {
  let cur = obj;
  for (const part of path.split('.')) {
    if (cur == null) return undefined;
    if (Array.isArray(cur)) cur = /^\d+$/.test(part) ? cur[Number(part)] : undefined;
    else if (typeof cur === 'object') cur = cur[part];
    else return undefined;
  }
  return cur;
}

/** PostgreSQL `raw #>> path` 와 같은 문자열 표현 */
export function rawText(v) {
  if (typeof v === 'string') return v;
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  return JSON.stringify(v);
}

/** '24h' 같은 상대 시간 → Date */
export function sinceDate(since) {
  if (!since) return null;
  const m = /^(\d+)\s*([smhdw])$/.exec(since);
  if (!m) return new Date(since);
  return new Date(Date.now() - Number(m[1]) * UNIT_SEC[m[2]] * 1000);
}

/** 그룹/상위값 키: 서버 timeseries/top 의 key 와 같은 문자열 */
export function fieldValue(field, ev) {
  if (field === 'none') return '';
  if (FIELD_OF[field]) field = FIELD_OF[field];
  if (field.startsWith('f.')) {
    const v = getPath(ev.raw, field.slice(2));
    return v == null ? null : rawText(v);
  }
  const v = ev[field];
  return v == null ? null : String(v);
}

/** query = 위젯 조건 ({since, host, level, ...}) */
export function matchesQuery(query, ev) {
  for (const [key, value] of Object.entries(query)) {
    if (value === '' || value == null || key === 'since' || key === 'until') continue;
    if (LIST_KEYS.has(key)) {
      if (!split(value).includes(ev[FIELD_OF[key] ?? key] ?? '')) return false;
    } else if (INT_KEYS.has(key)) {
      if (!split(value).map(Number).includes(ev[key])) return false;
    } else if (key === 'q') {
      const message = (ev.message || '').toLowerCase();
      const terms = String(value).split('|').map((t) => t.trim().toLowerCase()).filter(Boolean);
      if (terms.length && !terms.some((t) => message.includes(t))) return false;
    } else if (key.startsWith('f.')) {
      const cur = getPath(ev.raw, key.slice(2));
      if (cur == null || rawText(cur) !== String(value)) return false;
    }
  }
  if (query.until) return false; // 고정 구간은 실시간 대상 아님
  const since = sinceDate(query.since);
  return !since || new Date(ev.ts) >= since;
}

/** 요소에 잠깐 강조 애니메이션 (클래스를 뗐다 붙여서 재시작) */
export function bump(el, cls = 'bump') {
  if (!el) return;
  el.classList.remove(cls);
  void el.offsetWidth;
  el.classList.add(cls);
}
