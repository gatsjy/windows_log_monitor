// 수집 PC: 로그를 보내는 모든 PC/서버/장비의 수신 상태 + 에이전트 설치 안내.
import * as api from '../api.js';
import { can, isAdmin } from '../auth.js';
import { openDrawer } from '../drawer.js';
import { sourceLabel, statusBadge } from '../levels.js';
import { confirmModal, errorBox, fmtCompact, fmtDuration, fmtNum, fmtRelative, fmtTime, html, navigate, replaceParams, toast } from '../util.js';

// 수집 거절 장부의 상태 (B-40) — 사유는 서버가 준 문구 그대로
const REJECT_LABELS = { 400: '형식 오류', 401: 'API 키', 413: '너무 큼', 499: '연결 끊김', 500: '서버 오류', 503: '서버 설정' };

// 마지막 하트비트의 전송 방식. syslog 장비처럼 하트비트가 없으면 '–'. TLS 를 켠 서버에서 평문이면 경고 색
function transportLabel(value, serverTls) {
  if (value === 'tls') return html`<span class="tag-good" title="TLS 로 암호화해 보냅니다">TLS</span>`;
  if (value === 'web') {
    return html`<span class="tag-bad" title="화면 포트(8080)로 보냅니다 — 0.4 이전 설치 묶음. TLS 를 켜면 끊기니 새 묶음으로 다시 설치하세요">평문(화면 포트)</span>`;
  }
  if (value === 'plain') {
    return serverTls
      ? html`<span class="tag-bad" title="평문 — 새 설치 묶음(TLS)으로 다시 설치하세요">평문</span>`
      : html`<span class="muted" title="서버가 TLS 를 켜지 않았습니다">평문</span>`;
  }
  return html`<span class="muted">–</span>`;
}

export async function mount(root, params) {
  let since = params.since || '24h';
  let timer;
  // 15초마다 표를 다시 그리므로 선택은 표 밖에 기억한다 (새로고침 때 체크가 풀리지 않게)
  const selected = new Set();

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">수집 PC</h1>
        <p class="page-sub">로그를 보내는 PC·서버·장비 목록입니다. 마지막 수신 시각으로 상태를 판단합니다.</p></div>
      <div class="toolbar">
        <div class="seg" data-seg>${[['24h', '24시간'], ['7d', '7일'], ['30d', '30일']].map(([v, l]) =>
          html`<button data-v="${v}" class="${v === since ? 'on' : ''}">${l}</button>`)}</div>
      </div>
    </div>
    <div class="grid" data-summary style="margin-bottom:14px"></div>
    <section class="card" style="margin-bottom:14px"><div class="card-body flush" data-table><div class="skeleton"></div></div></section>
    <section class="card" style="margin-bottom:14px" data-problems hidden></section>
    <section class="card"><div class="card-head"><h2 class="card-title">에이전트 설치</h2></div>
      <div class="card-body" data-guide></div></section>`;

  root.querySelectorAll('[data-seg] button').forEach((b) => b.addEventListener('click', () => {
    since = b.dataset.v;
    root.querySelectorAll('[data-seg] button').forEach((x) => x.classList.toggle('on', x === b));
    replaceParams('agents', { since });
    load();
  }));

  renderGuide();

  // 폐쇄망 PC 배포용: 서버 주소·수집 포트·API 키가 채워진 설치 묶음(zip)을 내려받는다 (관리자)
  async function renderGuide() {
    const el = root.querySelector('[data-guide]');
    if (!can('agents.deploy')) {
      el.innerHTML = html`<p class="muted" style="margin:0">에이전트 설치 묶음은 관리자나 에이전트 배포 권한이 있는 그룹이 내려받아 배포합니다.</p>`;
      return;
    }
    let info;
    try {
      info = await api.get('/api/agents/package/info');
    } catch (err) {
      el.innerHTML = errorBox(err);
      return;
    }
    const opt = { os: 'windows', server: info.server && info.server !== 'localhost' ? info.server : '', port: info.port, iis: false, mssql: false };
    const tls = info.tls?.enabled ? info.tls : null;
    // 에이전트가 서버 인증서를 확인할 DNS 이름: 서버 주소가 인증서 이름이면 그것, 아니면(IP 등) 첫 이름 — 서버도 같은 규칙
    // 와일드카드(*.corp.local)뿐이면 그 아래 이름을 직접 적는다 — 서버 주소가 맞으면 그것으로 채운다
    const wildMatch = (host) => tls?.wildcards.some((w) => host.endsWith(w.slice(1)) && !host.slice(0, -w.length + 1).includes('.'));
    const pickName = () => {
      const host = opt.server.toLowerCase();
      if (tls?.server_names.includes(host) || wildMatch(host)) return host;
      return tls?.server_names[0] || '';
    };
    opt.name = pickName();
    const isIp = (v) => /^[0-9.]+$|:/.test(v);
    const draw = () => {
      const files = info.installers[opt.os] || [];
      const tlsBox = tls
        ? html`<div class="hint-box" style="margin-top:4px" data-tls>
            <b>TLS 수집</b> (포트 ${tls.port}) · 서버 인증서 만료 ${tls.not_after ? fmtTime(tls.not_after, { seconds: false }) : '–'}
            ${tls.days_left != null ? html`(D-${tls.days_left})` : ''} · CA 지문 <code>${(tls.ca_sha256 || '').slice(0, 16)}</code>
            ${tls.problems.length ? html`<ul class="ref-list" style="margin:6px 0 0">${tls.problems.map((p) =>
              html`<li class="${p.level === 'error' ? 'tag-bad' : ''}">${p.text}</li>`)}</ul>` : ''}</div>
          <label class="field"><span>인증서 이름 (에이전트가 서버를 확인할 이름)</span>
            ${tls.server_names.length
              ? html`<select class="input" data-name>${tls.server_names.map((n) => html`<option value="${n}" ${n === opt.name ? 'selected' : ''}>${n}</option>`)}</select>`
              : html`<input class="input" data-name value="${opt.name}" placeholder="${tls.wildcards[0] ? `예: logmon.${tls.wildcards[0].slice(2)} (${tls.wildcards[0]} 에 맞는 이름)` : 'DNS 이름'}">`}</label>
          <p class="muted" style="margin:0;font-size:12.5px;visibility:${isIp(opt.server) ? 'visible' : 'hidden'}" data-ip-hint>서버 주소가 IP 라도 됩니다. 인증서 이름은 확인용이라 DNS 에 등록되어 있지 않아도 됩니다.</p>`
        : html`<p class="hint-box" style="margin-top:4px" data-plain-note><b class="tag-bad">평문 전송</b>입니다 — 로그와 수집 키가 암호화되지 않습니다(ISMS 2.7.1).
            서버에서 TLS 를 켜면 이 창이 TLS 묶음을 만듭니다 (docs/AIRGAP.md §7.5).</p>`;
      el.innerHTML = html`
        <div class="pkg">
          <div class="pkg-form">
            <div class="field"><span>대상</span><div class="seg" data-os>
              <button type="button" data-v="windows" class="${opt.os === 'windows' ? 'on' : ''}">Windows PC·서버</button>
              <button type="button" data-v="linux" class="${opt.os === 'linux' ? 'on' : ''}">Linux 서버</button></div></div>
            <div class="form-row">
              <label class="field"><span>서버 주소 (PC 에서 보이는 이름·IP)</span><input class="input" data-server value="${opt.server}" placeholder="logmon.corp.local 또는 10.0.0.10"></label>
              <label class="field" style="max-width:150px"><span>수집 포트</span><input class="input num" data-port type="number" value="${opt.port}"></label>
            </div>
            ${tlsBox}
            ${opt.os === 'windows' ? html`<div class="field"><span>함께 수집</span><div class="check-list">
              <label><input type="checkbox" data-iis ${opt.iis ? 'checked' : ''}>IIS 접속 로그 (웹 서버)</label>
              <label><input type="checkbox" data-mssql ${opt.mssql ? 'checked' : ''}>SQL Server ERRORLOG (DB 서버)</label></div></div>` : ''}
            <div class="toolbar"><button class="btn primary" data-download><svg viewBox="0 0 24 24"><path d="M12 4v11M7 10l5 5 5-5M5 20h14"/></svg>설치 묶음 내려받기 (.zip)</button></div>
            <div data-msg></div>
          </div>
          <div class="pkg-info">
            <div class="section-title" style="margin-top:0">묶음에 들어가는 것</div>
            <ul class="ref-list">
              <li>${opt.os === 'windows' ? html`<code>install.cmd</code> — 관리자 권한으로 실행 (여러 대: <code>install.cmd /quiet</code> 를 GPO·SCCM 으로)` : html`<code>install-configured.sh</code> — <code>sudo</code> 로 실행`}</li>
              <li>서버 주소·수집 포트·<b>수집 API 키</b>가 채워진 설정 (${opt.os === 'windows' ? 'settings.json' : 'install-configured.sh'})</li>
              ${tls ? html`<li><code>ca.crt</code> — 서버 인증서를 확인할 CA (설치 스크립트가 지문을 대조하고 PC 에 복사)</li>` : ''}
              <li>Fluent Bit 설치 파일: ${files.length ? html`<span class="tag-good">${files.join(', ')}</span>`
                : html`<span class="tag-bad">없음</span> — 서버의 <code>agent-installers/</code> 에 넣으면 함께 들어갑니다 (docs/AIRGAP.md)`}</li>
              <li><code>설치방법.txt</code></li>
            </ul>
            <p class="hint-box" style="margin:10px 0 0">PC 에서는 압축을 풀고 실행만 하면 됩니다. 인터넷이 필요 없습니다.
              방화벽에서 PC → 서버 TCP <b>${opt.port}</b> 을 열어 두세요. 내려받기는 감사 로그에 남습니다.</p>
          </div>
        </div>
        <details class="manual"><summary>네트워크 장비 syslog · 수동 설치</summary>
          <ul class="ref-list">
            <li>네트워크 장비: 서버에서 <code>docker compose --profile syslog up -d</code> 후, 장비의 syslog 대상을 <code>${opt.server || '<서버IP>'}:514</code> (UDP/TCP)</li>
            <li>Windows 수동: <code>install.ps1 -ServerHost ${opt.server || '<서버IP>'} -ApiKey &lt;키&gt;${tls ? html` -CaFile ca.crt -TlsServerName ${opt.name}` : ''}</code> (포트 기본 ${opt.port})</li>
            <li>Linux 수동: <code>sudo ${tls ? html`TLS_CA_FILE=ca.crt TLS_SERVER_NAME=${opt.name} ` : ''}./install.sh ${opt.server || '<서버IP>'} ${opt.port} &lt;키&gt;</code></li>
          </ul></details>`;
      el.querySelectorAll('[data-os] button').forEach((b) => b.addEventListener('click', () => { opt.os = b.dataset.v; draw(); }));
      el.querySelector('[data-server]').addEventListener('input', (e) => { opt.server = e.target.value.trim(); });
      // 주소를 다 쓰고 나면 그 주소에 맞는 인증서 이름으로. 창을 다시 그리지 않는다 — 칸을 벗어나는 클릭(내려받기)이
      // 다시 그리기에 먹혀 사라지지 않게 그 자리에서 바꾼다
      el.querySelector('[data-server]').addEventListener('change', () => {
        if (!tls) return;
        opt.name = pickName();
        el.querySelector('[data-name]').value = opt.name;
        // 자리는 늘 차지하고 보이기만 바꾼다 (줄이 생기고 없어지면 단추가 움직여 클릭이 빗나간다)
        el.querySelector('[data-ip-hint]').style.visibility = isIp(opt.server) ? 'visible' : 'hidden';
      });
      el.querySelector('[data-name]')?.addEventListener('change', (e) => { opt.name = e.target.value.trim(); });
      el.querySelector('[data-port]').addEventListener('input', (e) => { opt.port = Number(e.target.value) || info.port; });
      el.querySelector('[data-iis]')?.addEventListener('change', (e) => { opt.iis = e.target.checked; });
      el.querySelector('[data-mssql]')?.addEventListener('change', (e) => { opt.mssql = e.target.checked; });
      el.querySelector('[data-download]').addEventListener('click', async (e) => {
        const msg = el.querySelector('[data-msg]');
        if (!opt.server) {
          msg.innerHTML = html`<div class="error-box" style="margin-top:8px">서버 주소를 입력하세요. PC 에서 이 서버에 접속할 때 쓰는 이름이나 IP 입니다.</div>`;
          return;
        }
        const q = new URLSearchParams({ os: opt.os, server: opt.server, port: String(opt.port), iis: String(opt.iis), mssql: String(opt.mssql) });
        if (tls && opt.name) q.set('name', opt.name);
        // 주소로 이동하지 않고 받아서 저장한다 — 서버가 묶음을 거절하면(인증서 만료·없는 이름 등) 화면을 떠나지 않고 이유를 보인다
        const button = e.currentTarget;
        button.disabled = true;
        try {
          const res = await fetch(`/api/agents/package?${q}`);
          if (!res.ok) {
            let detail = `${res.status} ${res.statusText}`;
            try {
              const body = await res.json();
              detail = Array.isArray(body.detail) ? body.detail.map((d) => d.msg).join(', ') : body.detail || detail;
            } catch { /* 본문이 JSON 이 아님 */ }
            msg.innerHTML = html`<div class="error-box" style="margin-top:8px">${detail}</div>`;
            return;
          }
          const name = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '')?.[1] || 'log-monitor-agent.zip';
          const link = Object.assign(document.createElement('a'), { href: URL.createObjectURL(await res.blob()), download: name });
          link.click();
          setTimeout(() => URL.revokeObjectURL(link.href), 60000);
          msg.innerHTML = html`<div class="hint-box" style="margin-top:8px">내려받았습니다 (${name}). 설정 파일에 API 키가 들어 있으니 배포 후 지우세요.</div>`;
        } catch (err) {
          msg.innerHTML = errorBox(err);
        } finally {
          button.disabled = false;
        }
      });
    };
    draw();
  }

  // 수집 거절·격리 (관리자, B-40): 없으면 칸을 숨긴다. 서버는 30초마다 장부를 쓰므로 조금 늦게 보일 수 있다
  async function loadProblems() {
    const box = root.querySelector('[data-problems]');
    if (!box || !isAdmin()) return;
    let data;
    try {
      data = await api.get('/api/agents/problems', { since });
    } catch (err) {
      box.hidden = false;
      box.innerHTML = errorBox(err);
      return;
    }
    const { rejections, quarantine } = data;
    box.hidden = !rejections.length && !quarantine.length;
    if (box.hidden) return;
    box.innerHTML = html`<div class="card-head"><h2 class="card-title">수집 거절·격리</h2></div>
      <div class="card-body flush">
      ${rejections.length ? html`<p class="hint-box" style="margin:12px 16px 0">서버가 받지 않은 수집 요청입니다. <b>API 키</b> 거절은 키를 바꾼 뒤 옛 설치 묶음으로
        보내는 PC 입니다 — 새 묶음으로 다시 설치하세요. 그동안 그 PC 의 로그는 PC 쪽 버퍼에 쌓입니다.</p>
      <div class="table-wrap"><table class="table"><thead><tr><th>보낸 곳 IP</th><th>거절</th><th>사유</th>
        <th class="r">횟수</th><th>처음</th><th>마지막</th></tr></thead>
        <tbody>${rejections.map((r) => html`<tr><td class="nowrap num"><b>${r.client_ip}</b></td>
          <td class="nowrap"><span class="${r.status >= 500 ? 'tag-bad' : ''}">${r.status} ${REJECT_LABELS[r.status] ?? ''}</span></td>
          <td class="ink-2">${r.reason}</td><td class="r num">${fmtNum(r.count)}</td>
          <td class="nowrap muted">${fmtTime(r.first_at, { seconds: false })}</td>
          <td class="nowrap" title="${fmtTime(r.last_at)}">${fmtRelative(r.last_at)}</td></tr>`)}</tbody></table></div>` : ''}
      ${quarantine.length ? html`<p class="hint-box" style="margin:12px 16px 0">값 때문에 저장하지 못한 레코드입니다. 같은 요청의 다른 로그는 저장했고,
        이 레코드는 원본 그대로 따로 보관합니다(로그 보관기간 동안). 원본을 보면 접속기록에 남습니다.</p>
      <div class="table-wrap"><table class="table"><thead><tr><th>받은 시각</th><th>PC</th><th>소스</th><th>보낸 곳 IP</th><th>저장하지 못한 이유</th>
        <th class="r">크기</th><th></th></tr></thead>
        <tbody>${quarantine.map((q) => html`<tr><td class="nowrap">${fmtTime(q.received_at)}</td><td class="nowrap"><b>${q.host}</b></td>
          <td class="nowrap ink-2">${sourceLabel(q.source)}</td><td class="nowrap num ink-2">${q.client_ip || '–'}</td>
          <td class="ink-2">${q.error}</td><td class="r num muted">${fmtNum(q.size)}자</td>
          <td class="r"><button class="btn sm" data-quarantine="${q.id}">원본 보기</button></td></tr>`)}</tbody></table></div>` : ''}
      </div>`;
    box.querySelectorAll('[data-quarantine]').forEach((b) => b.addEventListener('click', () => showQuarantine(b.dataset.quarantine)));
  }

  async function showQuarantine(id) {
    const body = openDrawer({ title: `격리한 레코드 #${id}` });
    body.innerHTML = '<div class="skeleton"></div>';
    try {
      const q = await api.get(`/api/agents/quarantine/${id}`);
      // 서버는 어떤 글자든 저장되게 ASCII 로 이스케이프해 둔다 — 읽기 좋게 풀어서 (잘린 것은 그대로)
      let record = q.record;
      try { record = JSON.stringify(JSON.parse(q.record), null, 2); } catch { /* 64KB 에서 잘린 원본 */ }
      body.innerHTML = html`<dl class="kv"><dt>받은 시각</dt><dd>${fmtTime(q.received_at)}</dd><dt>PC</dt><dd>${q.host}</dd>
        <dt>보낸 곳 IP</dt><dd class="num">${q.client_ip || '–'}</dd><dt>이유</dt><dd>${q.error}</dd></dl>
        <pre class="json" style="white-space:pre-wrap;overflow-wrap:anywhere">${record}</pre>`;
    } catch (err) {
      body.innerHTML = errorBox(err);
    }
  }

  async function load() {
    loadProblems();
    try {
      const { items, thresholds, transport } = await api.get('/api/agents', { since });
      const count = (s) => items.filter((a) => a.status === s).length;
      root.querySelector('[data-summary]').innerHTML = html`${[
        ['전체', items.length, ''], ['온라인', count('online'), statusBadge('online')],
        ['지연', count('stale'), statusBadge('stale')], ['오프라인', count('offline'), statusBadge('offline')],
      ].map(([label, n, badge]) => html`<section class="card" style="grid-column: span 3"><div class="card-body">
        <div class="stat"><div class="stat-meta">${badge || label}</div><div class="stat-value">${fmtNum(n)}<small>대</small></div></div>
      </div></section>`)}`;

      const table = root.querySelector('[data-table]');
      if (!items.length) {
        table.innerHTML = '<div class="empty">아직 로그를 보낸 PC 가 없습니다. 아래 설치 안내를 참고하세요.</div>';
        return;
      }
      const admin = isAdmin();
      // 목록에서 사라진 PC(다른 관리자가 지움 등)는 선택에서도 뺀다
      const present = new Set(items.map((a) => a.host));
      [...selected].forEach((h) => { if (!present.has(h)) selected.delete(h); });
      // TLS 를 켠 서버에서 아직 평문으로 보내는 PC — 평문 수집을 닫기 전에 0 이 되어야 한다 (ADR-036)
      const plain = transport?.tls ? items.filter((a) => a.last_transport === 'plain' || a.last_transport === 'web').length : 0;
      // 화면 포트로 보내는 옛 묶음(0.4 이전)은 TLS 를 켜는 순간 끊긴다 — 켜기 전에 알린다
      const web = transport?.tls ? 0 : items.filter((a) => a.last_transport === 'web').length;
      table.innerHTML = html`${plain ? html`<p class="hint-box" style="margin:12px 16px 0" data-plain>
          <b class="tag-bad">평문으로 보내는 PC ${fmtNum(plain)}대</b> — '에이전트 설치'에서 새 설치 묶음(TLS)을 받아 다시 설치하세요.
          모두 옮긴 뒤 평문 수집을 닫습니다(docs/AIRGAP.md §7.5).</p>` : ''}
        ${web ? html`<p class="hint-box" style="margin:12px 16px 0" data-web>
          <b class="tag-bad">화면 포트(8080)로 보내는 PC ${fmtNum(web)}대</b> — 0.4 이전 설치 묶음입니다. TLS 를 켜면 끊기니 먼저 새 묶음으로 다시 설치하세요.</p>` : ''}
        ${admin ? html`<div class="toolbar" data-bulk style="padding:10px 16px;justify-content:space-between">
          <span class="muted" data-bulk-count></span>
          <span class="toolbar">
            <button class="btn sm" data-select-offline>오프라인 PC 모두 선택</button>
            <button class="btn sm danger" data-bulk-del>선택한 PC 삭제</button>
          </span></div>` : ''}
        <div class="table-wrap"><table class="table">
        <thead><tr>${admin ? html`<th style="width:32px"><input type="checkbox" data-check-all aria-label="전체 선택"></th>` : ''}<th>상태</th><th>PC</th><th>소스</th><th>IP</th><th>연결</th><th>마지막 수신</th><th>하트비트</th>
          <th class="r">이벤트</th><th class="r">오류</th><th class="r">경고</th><th class="r">누적</th><th>최초 등록</th><th>설정 버전</th>
          ${admin ? html`<th class="r">관리</th>` : ''}</tr></thead>
        <tbody>${items.map((a) => html`<tr class="clickable" data-host="${a.host}">
          ${admin ? html`<td data-check-cell><input type="checkbox" data-check="${a.host}" aria-label="${a.host} 선택" ${selected.has(a.host) ? 'checked' : ''}></td>` : ''}
          <td>${statusBadge(a.status)}</td>
          <td class="nowrap"><b>${a.host}</b></td>
          <td class="nowrap ink-2">${a.sources.map(sourceLabel).join(', ') || '–'}</td>
          <td class="nowrap num ink-2">${a.last_ip || '–'}</td>
          <td class="nowrap">${transportLabel(a.last_transport, transport?.tls)}</td>
          <td class="nowrap" title="${fmtTime(a.last_seen)}">${fmtRelative(a.last_seen)}</td>
          <td class="nowrap ink-2">${a.last_heartbeat_at ? fmtRelative(a.last_heartbeat_at) : '–'}</td>
          <td class="r num">${fmtCompact(a.events)}</td>
          <td class="r num">${fmtNum(a.errors)}</td>
          <td class="r num">${fmtNum(a.warnings)}</td>
          <td class="r num muted">${fmtCompact(a.events_total)}</td>
          <td class="nowrap muted">${fmtTime(a.first_seen, { seconds: false })}</td>
          <td class="nowrap muted">${a.meta?.config_version ?? '–'}</td>
          ${admin ? html`<td class="r nowrap"><button class="btn sm danger" data-del="${a.host}">삭제</button></td>` : ''}
        </tr>`)}</tbody></table></div>
        <p class="muted" style="font-size:12px;padding:0 16px">온라인: ${fmtDuration(thresholds.online_sec)} 이내 수신 · 지연: ${fmtDuration(thresholds.stale_sec)} 이내 · 그 이후 오프라인. 행을 누르면 해당 PC 의 이벤트를 검색합니다.</p>`;
      const statusOf = new Map(items.map((a) => [a.host, a.status]));
      table.querySelectorAll('[data-host]').forEach((tr) =>
        tr.addEventListener('click', (e) => {
          if (e.target.closest('[data-del], [data-check-cell]')) return;
          navigate('events', { since, host: tr.dataset.host });
        }));
      if (!admin) return;

      const checks = [...table.querySelectorAll('[data-check]')];
      const checkAll = table.querySelector('[data-check-all]');
      const syncBulk = () => {
        const n = selected.size;
        table.querySelector('[data-bulk-count]').textContent = n ? `${fmtNum(n)}대 선택됨` : 'PC 를 골라 한 번에 삭제할 수 있습니다';
        table.querySelector('[data-bulk-del]').disabled = !n;
        checkAll.checked = n > 0 && checks.every((c) => c.checked);
        checkAll.indeterminate = n > 0 && !checkAll.checked;
      };
      checks.forEach((c) => c.addEventListener('change', () => {
        if (c.checked) selected.add(c.dataset.check); else selected.delete(c.dataset.check);
        syncBulk();
      }));
      checkAll.addEventListener('change', () => {
        checks.forEach((c) => { c.checked = checkAll.checked; if (c.checked) selected.add(c.dataset.check); else selected.delete(c.dataset.check); });
        syncBulk();
      });
      table.querySelector('[data-select-offline]').addEventListener('click', () => {
        checks.forEach((c) => { if (statusOf.get(c.dataset.check) === 'offline') { c.checked = true; selected.add(c.dataset.check); } });
        syncBulk();
      });
      syncBulk();

      table.querySelector('[data-bulk-del]').addEventListener('click', () => removeHosts([...selected].sort(), statusOf));
      table.querySelectorAll('[data-del]').forEach((btn) =>
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          removeHosts([btn.dataset.del], statusOf);
        }));
    } catch (err) {
      const table = root.querySelector('[data-table]');
      if (table) table.innerHTML = errorBox(err); // 화면을 떠난 뒤 끝난 요청이면 무시
    }
  }

  // 삭제 확인 → 일괄 API 한 번. 아직 보내고 있는(온라인) PC 는 곧 다시 등록되니 미리 알린다
  async function removeHosts(hosts, statusOf) {
    if (!hosts.length) return;
    const online = hosts.filter((h) => statusOf.get(h) === 'online');
    const lines = hosts.slice(0, 10).map((h) => `· ${h}`);
    if (hosts.length > 10) lines.push(`… 외 ${fmtNum(hosts.length - 10)}대`);
    const ok = await confirmModal({
      title: hosts.length > 1 ? `PC ${fmtNum(hosts.length)}대 삭제` : 'PC 삭제',
      message: [
        '다음 PC를 수집 목록에서 삭제할까요?', ...lines, '',
        '기존 이벤트 로그는 유지되며, PC에서 다시 로그를 보내면 다시 등록됩니다.',
        ...(online.length ? ['', `주의: ${fmtNum(online.length)}대는 지금 온라인이라 30초 안에 다시 나타납니다. 먼저 그 PC에서 에이전트를 제거(uninstall.ps1)하세요.`] : []),
      ].join('\n'),
      danger: true,
      confirmText: '삭제',
    });
    if (!ok) return;
    try {
      const res = await api.send('POST', '/api/agents/delete', { hosts });
      res.deleted.forEach((h) => selected.delete(h));
      res.missing.forEach((h) => selected.delete(h));
      await load();
      toast(`${fmtNum(res.deleted.length)}대가 수집 목록에서 삭제되었습니다.`
        + (res.missing.length ? ` (${fmtNum(res.missing.length)}대는 이미 없음)` : ''), { type: 'success' });
    } catch (err) {
      toast(err.message, { type: 'error' });
    }
  }

  await load();
  timer = setInterval(() => { if (!document.hidden) load(); }, 15000);
  return () => clearInterval(timer);
}
