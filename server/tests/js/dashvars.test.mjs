// 대시보드 변수 (B-07 2단계): 값은 한 값으로만 문장에 더해지고(다른 조건이 되지 않음), 같은 문장을 Python 파서도 같은 조건으로 읽는다.
//   node --test 'server/tests/js/*.test.mjs'
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { applyVars, varValues } from '../../../web/js/dashvars.js';
import { parseTerms, termJson } from '../../../web/js/querylang.js';

const PYRUN = fileURLToPath(new URL('./pyrun.py', import.meta.url));
const VARS = [{ name: 'host', key: 'host', label: 'PC' }, { name: 'user', key: 'user', default: '' },
  { name: 'eid', key: 'event_id' }, { name: 'lt', key: 'f.EventData.LogonType' }];

test('주소 값 → 기본값 → 비면 조건 없음', () => {
  assert.deepEqual(varValues(VARS, { 'var-host': ' EMR-DB-01 ' }), { host: 'EMR-DB-01', user: '', eid: '', lt: '' });
  assert.deepEqual(varValues([{ name: 'h', key: 'host', default: 'DC-01' }], {}), { h: 'DC-01' });
  const q = { since: '24h', query: 'event_id:4625' };
  assert.deepEqual(applyVars(q, VARS, {}), { query: q, errors: [] });
});

test('값은 한 값으로만 — 쉼표·공백·다른 조건처럼 보이는 글자가 조건이 되지 않는다', () => {
  const { query, errors } = applyVars({ query: 'level:오류' }, VARS,
    { host: 'WEB-01', user: 'kim -host:x,lee', eid: '4625', lt: '10' });
  assert.deepEqual(errors, []);
  const terms = parseTerms(query.query);
  assert.deepEqual(terms.map((t) => [t.key, t.values]), [
    ['level', [2]], ['host', ['WEB-01']], ['user', ['kim -host:x,lee']], ['event_id', [4625]], ['f', ['10']]]);
  assert.equal(applyVars({ query: 'host:WEB-01' }, VARS, { host: 'WEB-01' }).query.query, 'host:WEB-01');   // 이미 있으면 그대로
});

test('"variables": null 은 변수 없음 — 대시보드가 깨지지 않는다 (검토에서 재현)', () => {
  assert.deepEqual(varValues(null, { 'var-host': 'x' }), {});
  assert.deepEqual(applyVars({ query: 'a' }, null, { host: 'x' }), { query: { query: 'a' }, errors: [] });
});

test('검색으로 넘길 때는 누른 값이 이긴다 — 같은 키의 변수를 더하지 않는다 (PC 카드를 누르면 0건이던 것, 검토에서 재현)', () => {
  const values = { host: 'WEB-01' };
  assert.deepEqual(applyVars({ host: 'DB-02' }, VARS, values, { yieldToQuery: true }).query, { host: 'DB-02' });
  assert.equal(applyVars({ query: 'host:DB-02' }, VARS, values, { yieldToQuery: true }).query.query, 'host:DB-02');
  assert.equal(applyVars({ query: 'event_id:4625' }, VARS, values, { yieldToQuery: true }).query.query, 'event_id:4625 host:WEB-01');
  assert.equal(applyVars({ host: 'DB-02' }, VARS, values).query.query, 'host:WEB-01');   // 위젯 조회는 변수도 같이 (원래 뜻)
});

test('그 키에 맞지 않는 값은 위젯 조건에 넣지 않고 오류로', () => {
  const { query, errors } = applyVars({ query: '' }, VARS, { eid: 'abc', host: 'DC-01' });
  assert.equal(query.query, 'host:DC-01');
  assert.equal(errors.length, 1);
  assert.match(errors[0], /^eid: /);
});

test('Python 파서도 같은 조건으로 읽는다 (서버 SQL·알림과 같은 뜻, ADR-033)', (t) => {
  const ok = spawnSync('python3', ['-I', '-c', 'import sys; print(sys.version_info >= (3, 11))'], { encoding: 'utf8' });
  if (ok.status !== 0 || ok.stdout.trim() !== 'True') { t.skip('python3 3.11+ 없음'); return; }
  const samples = [{ host: 'PC 01', user: 'a,b' }, { user: '"x"' }, { host: 'WEB-*', lt: '3' }, { user: 'kim', eid: '4624' }];
  const texts = samples.map((values) => applyVars({ query: 'level:경고' }, VARS, values).query.query);
  const r = spawnSync('python3', ['-I', PYRUN], { input: texts.map((x) => JSON.stringify(x)).join('\n') + '\n', encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const py = r.stdout.trim().split('\n').map((line) => JSON.parse(line));
  texts.forEach((text, i) => assert.deepEqual(py[i].terms, parseTerms(text).map(termJson), text));
});
