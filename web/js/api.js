// 서버 API 호출. 모든 화면/위젯은 이 함수들만 쓴다.
//
// 인증 관련 규칙 (server/app/auth/deps.py 와 짝):
//   - 세션은 HttpOnly 쿠키라 스크립트가 직접 다루지 않는다 (같은 출처 요청에 자동 포함)
//   - 상태를 바꾸는 요청(POST/PUT/PATCH/DELETE)에는 X-WLM-CSRF: 1 헤더
//   - 모든 요청에 X-WLM-Idle-Sec(마지막 사용자 조작 후 경과 초) → 자동 새로고침은 세션을 연장하지 않는다
//   - 401 이면 'wlm:auth' 이벤트(reason=login), 비밀번호 변경 필요면 (reason=password)

let lastInput = Date.now();
for (const type of ['pointerdown', 'keydown', 'wheel', 'touchstart']) {
  window.addEventListener(type, () => { lastInput = Date.now(); }, { passive: true, capture: true });
}

function headers(method, extra = {}) {
  const h = { Accept: 'application/json', 'X-WLM-Idle-Sec': String(Math.round((Date.now() - lastInput) / 1000)), ...extra };
  if (method !== 'GET') h['X-WLM-CSRF'] = '1';
  return h;
}

function errorText(body, res) {
  if (body == null) return `${res.status} ${res.statusText}`;
  if (typeof body.detail === 'string') return body.detail;
  if (Array.isArray(body.detail)) return body.detail.map((d) => d.msg).join(', ');
  return JSON.stringify(body.detail ?? body);
}

async function handle(res, path) {
  if (res.ok) return res.json();
  let body = null;
  try { body = await res.json(); } catch { /* 본문이 JSON 이 아님 */ }
  const message = errorText(body, res);
  const reason = res.headers.get('X-WLM-Reason');
  // 로그인·인증 코드 API 자체의 실패(비밀번호·코드 틀림, 코드 대기 만료)는 그 화면에서 처리한다
  if (!path.startsWith('/api/auth/login') && !path.startsWith('/api/auth/mfa/verify')) {
    if (res.status === 401) window.dispatchEvent(new CustomEvent('wlm:auth', { detail: { reason: 'login', message } }));
    if (res.status === 403 && reason === 'password_change_required') {
      window.dispatchEvent(new CustomEvent('wlm:auth', { detail: { reason: 'password', message } }));
    }
    // 2단계 인증 (B-74): 코드를 넣어야 하는 세션 / 필수인데 아직 등록하지 않음
    if (res.status === 403 && reason === 'mfa_required') {
      window.dispatchEvent(new CustomEvent('wlm:auth', { detail: { reason: 'mfa', message } }));
    }
    if (res.status === 403 && reason === 'mfa_setup_required') {
      window.dispatchEvent(new CustomEvent('wlm:auth', { detail: { reason: 'mfa_setup', message } }));
    }
  }
  const error = new Error(message);
  error.status = res.status;
  error.reason = reason;
  // 검색 문장 오류: {param, code, start, end, message} — 입력 칸이 틀린 곳을 칠한다 (routers/query.QueryRejected)
  error.queryError = body?.query_error ?? null;
  throw error;
}

/** GET /api/... — params 의 빈 값은 빠진다. 배열은 콤마로 합친다. */
export async function get(path, params = {}) {
  const url = new URL(path, location.origin);
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    url.searchParams.set(k, Array.isArray(v) ? v.join(',') : v);
  }
  return handle(await fetch(url, { headers: headers('GET') }), path);
}

/** POST/PUT/PATCH/DELETE. body 가 문자열이면 text/plain (알림 YAML 저장 등), 객체면 JSON */
export async function send(method, path, body) {
  const isText = typeof body === 'string';
  const extra = body === undefined ? {} : { 'Content-Type': isText ? 'text/plain; charset=utf-8' : 'application/json' };
  const res = await fetch(path, {
    method,
    headers: headers(method, extra),
    body: body === undefined ? undefined : isText ? body : JSON.stringify(body),
  });
  return handle(res, path);
}

export const put = (path, body) => send('PUT', path, body);
