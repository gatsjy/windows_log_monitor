// 실시간 갱신용: 서버 filters.py 의 matches() 와 같은 규칙으로 이벤트가 위젯 조건에 맞는지 판단.
// 조건 해석·매칭은 querylang.js (서버 querylang.py·filters.py 와 같은 알고리즘, 케이스 표로 함께 시험).
import { compileQuery, rawText as queryRawText, walkRaw } from './querylang.js';

const FIELD_OF = { user: 'username', ip: 'src_ip' };
const UNIT_SEC = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };
const CACHE_MAX = 100;
const compiled = new Map();   // JSON(조건) → 술어. 위젯마다 이벤트 묶음이 올 때 문장을 다시 해석하지 않게

/** 원본 JSON 에서 점 경로 값 (서버 _field_expr 처럼 빈 단계는 버림). 배열은 숫자 위치 */
export const getPath = (obj, path) => walkRaw(obj, path.split('.').filter(Boolean));

/** PostgreSQL `raw #>> path` 와 같은 문자열 표현 (배열·객체는 ', ' · ': ' 구분자) */
export const rawText = queryRawText;

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

function predicate(query) {
  const key = JSON.stringify(query);
  let fn = compiled.get(key);
  if (!fn) {
    fn = compileQuery(query);
    if (compiled.size >= CACHE_MAX) compiled.delete(compiled.keys().next().value);
    compiled.set(key, fn);
  }
  return fn;
}

/** query = 위젯 조건 ({since, host, level, q, 'f.경로', query(검색 문장), ...}) */
export function matchesQuery(query, ev) {
  if (query.until) return false; // 고정 구간은 실시간 대상 아님
  const since = sinceDate(query.since);
  if (since && new Date(ev.ts) < since) return false;
  return predicate(query)(ev);
}

/** 요소에 잠깐 강조 애니메이션 (클래스를 뗐다 붙여서 재시작) */
export function bump(el, cls = 'bump') {
  if (!el) return;
  el.classList.remove(cls);
  void el.offsetWidth;
  el.classList.add(cls);
}
