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

async function errorText(res) {
  try {
    const body = await res.json();
    if (typeof body.detail === 'string') return body.detail;
    if (Array.isArray(body.detail)) return body.detail.map((d) => d.msg).join(', ');
    return JSON.stringify(body.detail ?? body);
  } catch {
    return `${res.status} ${res.statusText}`;
  }
}

async function handle(res, path) {
  if (res.ok) return res.json();
  const message = await errorText(res);
  const reason = res.headers.get('X-WLM-Reason');
  // 로그인 API 자체의 실패(비밀번호 틀림 등)는 화면에서 처리한다
  if (!path.startsWith('/api/auth/login')) {
    if (res.status === 401) window.dispatchEvent(new CustomEvent('wlm:auth', { detail: { reason: 'login', message } }));
    if (res.status === 403 && reason === 'password_change_required') {
      window.dispatchEvent(new CustomEvent('wlm:auth', { detail: { reason: 'password', message } }));
    }
  }
  const error = new Error(message);
  error.status = res.status;
  error.reason = reason;
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
