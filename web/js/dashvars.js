// 대시보드 변수 (B-07 2단계): JSON 의 variables + 주소 #/dashboard/<이름>?var-<name>=값 → 위젯마다 검색 문장에 조건 하나를 AND.
// 문자열 치환이 아니라 문장 편집(addTerm)이라 서버 SQL·실시간 매처가 같은 문장을 본다(ADR-033). 값은 formatValue 로 감싸 한 값으로만
// 들어간다 — 'a,b' 나 'x -user:y' 가 다른 조건이 되지 않게. import·DOM 없음 (node 로 시험).
import { addTerm, formatValue, parseTerms } from './querylang.js';

export const VAR_KEYS = ['host', 'user', 'ip', 'channel', 'provider', 'source', 'category', 'event_id', 'level'];
export const MAX_VARS = 5;

/** 변수 정의 → 지금 값 { name: '값' } (주소의 var-<name>, 없으면 default, 비면 조건 없음) */
export function varValues(variables = [], params = {}) {
  return Object.fromEntries(variables.map((v) => [v.name, String(params[`var-${v.name}`] ?? v.default ?? '').trim()]));
}

/** 변수 하나 → 검색 조건 하나 (term). 값이 그 키에 맞지 않으면(예: event_id:abc) 오류 */
export function varTerm(variable, value) {
  const [term, ...rest] = parseTerms(`${variable.key}:${formatValue(value)}`);
  if (!term || rest.length) throw new Error(`변수 ${variable.name} 의 값이 조건 하나가 아닙니다`);
  return term;
}

/** 위젯의 조건 객체(cfg.query 와 since 를 합친 것)에 변수 값들을 문장으로 더한 새 객체. 잘못된 값은 errors 에 */
export function applyVars(query, variables = [], values = {}) {
  let text = query.query ?? '';
  const errors = [];
  for (const v of variables) {
    const value = values[v.name];
    if (!value) continue;
    try {
      text = addTerm(text, varTerm(v, value));
    } catch (err) {
      errors.push(`${v.label || v.name}: ${err.message}`);
    }
  }
  return { query: text ? { ...query, query: text } : query, errors };
}
