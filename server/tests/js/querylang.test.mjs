// 검색 문장(B-01) 화면 쪽 시험 — 서버와 같은 케이스 표(server/tests/querylang_cases.json)로 web/js/querylang.js 를 본다.
// npm 없이 Node 내장 시험 도구만 쓴다:  node --test 'server/tests/js/*.test.mjs'
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { CATEGORY_LABELS, LEVELS } from '../../../web/js/levels.js';
import { fieldValue, getPath, matchesQuery } from '../../../web/js/livefilter.js';
import {
  CATEGORIES, LEVEL_NAMES, QueryError, addTerm, compileQuery, cpToUtf16, foldParams, formatQuery, parseTerms, rawText,
  setKey, setLevels, termJson, tokenAt, utf16ToCp,
} from '../../../web/js/querylang.js';

const CASES = JSON.parse(readFileSync(new URL('../querylang_cases.json', import.meta.url), 'utf8'));
const strip = (terms) => terms.map(({ span, ...rest }) => rest);
const budget = (c) => (c.budget !== undefined ? { fieldBudget: c.budget } : {});

test('parse: 표의 모든 문장 (정상·오류·정규형·왕복)', () => {
  for (const c of CASES.parse) {
    if (c.error) {
      assert.throws(() => parseTerms(c.text, budget(c)), (err) => {
        assert.ok(err instanceof QueryError, c.text);
        assert.deepEqual(err.asDict(), c.error, c.text);
        return true;
      });
      continue;
    }
    const terms = parseTerms(c.text, budget(c));
    assert.deepEqual(terms.map(termJson), c.terms, c.text);
    assert.equal(formatQuery(terms), c.canonical, c.text);
    assert.deepEqual(strip(parseTerms(c.canonical, budget(c)).map(termJson)), strip(c.terms), c.text);
  }
});

test('match: 고정 이벤트에 같은 결과 (compileQuery · livefilter.matchesQuery)', () => {
  for (const c of CASES.match) {
    const fn = compileQuery(c.params);
    assert.deepEqual(CASES.fixtures.filter(fn).map((f) => f.id), c.ids, c.name);
    assert.deepEqual(CASES.fixtures.filter((f) => matchesQuery(c.params, f)).map((f) => f.id), c.ids, c.name);
  }
});

test('fold: 옛 링크 파라미터 → 문장 + 남는 파라미터', () => {
  for (const c of CASES.fold) {
    assert.deepEqual(foldParams(c.params), { query: c.query, rest: c.rest }, JSON.stringify(c.params));
  }
});

test('fold 뒤에도 고정 이벤트 결과가 같다', () => {
  for (const c of CASES.fold.filter((x) => x.same_sql !== null)) {
    const { query, rest } = foldParams(c.params);
    const folded = { ...rest, ...(query ? { query } : {}) };
    assert.deepEqual(CASES.fixtures.filter(compileQuery(folded)).map((f) => f.id),
      CASES.fixtures.filter(compileQuery(c.params)).map((f) => f.id), JSON.stringify(c.params));
  }
});

test('edits: 드롭다운·수준 칩·상세 패널이 문장을 고치는 규칙', () => {
  const ops = { setKey, setLevels, addTerm };
  for (const c of CASES.edits) {
    assert.equal(ops[c.op](c.text, ...c.args), c.result, `${c.op}(${JSON.stringify(c.text)}, ${JSON.stringify(c.args)})`);
  }
});

test('원본 값 글자 표현은 PostgreSQL #>> 와 같다', () => {
  assert.equal(rawText(['x', 'y']), '["x", "y"]');
  assert.equal(rawText({ a: [1, 2], b: null }), '{"a": [1, 2], "b": null}');
  assert.equal(rawText(true), 'true');
  assert.equal(rawText(4625), '4625');
  assert.equal(rawText('그대로'), '그대로');
  assert.equal(getPath({ a: ['x', 'y'] }, 'a..1'), 'y');                 // 빈 단계는 버린다 (서버와 같게)
  assert.equal(getPath({ a: ['x'] }, 'a.²'), undefined);
  assert.equal(fieldValue('f.a', { raw: { a: ['x', 'y'] } }), '["x", "y"]');
});

test('위치: 코드 포인트 ↔ UTF-16 (이모지)', () => {
  const text = '😀 hots:x';
  assert.throws(() => parseTerms(text), (err) => err.start === 2 && err.end === 6);
  assert.equal(cpToUtf16(text, 2), 3);
  assert.equal(cpToUtf16(text, 6), 7);
  assert.equal(utf16ToCp(text, 7), 6);
});

test('자동완성 위치 판정', () => {
  assert.deepEqual(tokenAt('host:WEB', 8), { start: 5, end: 8, kind: 'value', key: 'host', prefix: 'WEB', chosen: [] });
  assert.deepEqual(tokenAt('x -lev', 6), { start: 3, end: 6, kind: 'key', key: '', prefix: 'lev' });
  assert.deepEqual(tokenAt('level:오류,심', 11), { start: 9, end: 11, kind: 'value', key: 'level', prefix: '심', chosen: ['오류'] });
});

test('어휘가 화면의 수준·분류 이름과 같다', () => {
  assert.deepEqual(Object.keys(CATEGORY_LABELS), CATEGORIES);
  assert.deepEqual(Object.fromEntries(Object.entries(LEVELS).map(([k, v]) => [Number(k), v.label])), LEVEL_NAMES);
});

test('잘못된 조건은 아무것도 맞지 않는다 (서버는 400)', () => {
  assert.equal(compileQuery({ query: 'hots:x' })(CASES.fixtures[0]), false);
  assert.equal(compileQuery({ level: 'x' })(CASES.fixtures[0]), false);
});
