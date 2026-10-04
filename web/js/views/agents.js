// 수집 PC: 로그를 보내는 모든 PC/서버/장비의 수신 상태 + 에이전트 설치 안내.
import * as api from '../api.js';
import { can } from '../auth.js';
import { sourceLabel, statusBadge } from '../levels.js';
import { errorBox, fmtCompact, fmtDuration, fmtNum, fmtRelative, fmtTime, html, navigate, replaceParams } from '../util.js';

export async function mount(root, params) {
  let since = params.since || '24h';
  let timer;

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
    const draw = () => {
      const files = info.installers[opt.os] || [];
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
            <li>Windows 수동: <code>install.ps1 -ServerHost ${opt.server || '<서버IP>'} -ApiKey &lt;키&gt;</code> (포트 기본 ${opt.port})</li>
            <li>Linux 수동: <code>sudo ./install.sh ${opt.server || '<서버IP>'} ${opt.port} &lt;키&gt;</code></li>
          </ul></details>`;
      el.querySelectorAll('[data-os] button').forEach((b) => b.addEventListener('click', () => { opt.os = b.dataset.v; draw(); }));
      el.querySelector('[data-server]').addEventListener('input', (e) => { opt.server = e.target.value.trim(); });
      el.querySelector('[data-port]').addEventListener('input', (e) => { opt.port = Number(e.target.value) || info.port; });
      el.querySelector('[data-iis]')?.addEventListener('change', (e) => { opt.iis = e.target.checked; });
      el.querySelector('[data-mssql]')?.addEventListener('change', (e) => { opt.mssql = e.target.checked; });
      el.querySelector('[data-download]').addEventListener('click', () => {
        const msg = el.querySelector('[data-msg]');
        if (!opt.server) {
          msg.innerHTML = html`<div class="error-box" style="margin-top:8px">서버 주소를 입력하세요. PC 에서 이 서버에 접속할 때 쓰는 이름이나 IP 입니다.</div>`;
          return;
        }
        const q = new URLSearchParams({ os: opt.os, server: opt.server, port: String(opt.port), iis: String(opt.iis), mssql: String(opt.mssql) });
        location.href = `/api/agents/package?${q}`; // 파일 내려받기 (쿠키 인증, 화면은 그대로)
        msg.innerHTML = html`<div class="hint-box" style="margin-top:8px">내려받기를 시작했습니다. 설정 파일에 API 키가 들어 있으니 배포 후 지우세요.</div>`;
      });
    };
    draw();
  }

  async function load() {
    try {
      const { items, thresholds } = await api.get('/api/agents', { since });
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
      table.innerHTML = html`<div class="table-wrap"><table class="table">
        <thead><tr><th>상태</th><th>PC</th><th>소스</th><th>IP</th><th>마지막 수신</th><th>하트비트</th>
          <th class="r">이벤트</th><th class="r">오류</th><th class="r">경고</th><th class="r">누적</th><th>최초 등록</th><th>설정 버전</th></tr></thead>
        <tbody>${items.map((a) => html`<tr class="clickable" data-host="${a.host}">
          <td>${statusBadge(a.status)}</td>
          <td class="nowrap"><b>${a.host}</b></td>
          <td class="nowrap ink-2">${a.sources.map(sourceLabel).join(', ') || '–'}</td>
          <td class="nowrap num ink-2">${a.last_ip || '–'}</td>
          <td class="nowrap" title="${fmtTime(a.last_seen)}">${fmtRelative(a.last_seen)}</td>
          <td class="nowrap ink-2">${a.last_heartbeat_at ? fmtRelative(a.last_heartbeat_at) : '–'}</td>
          <td class="r num">${fmtCompact(a.events)}</td>
          <td class="r num">${fmtNum(a.errors)}</td>
          <td class="r num">${fmtNum(a.warnings)}</td>
          <td class="r num muted">${fmtCompact(a.events_total)}</td>
          <td class="nowrap muted">${fmtTime(a.first_seen, { seconds: false })}</td>
          <td class="nowrap muted">${a.meta?.config_version ?? '–'}</td>
        </tr>`)}</tbody></table></div>
        <p class="muted" style="font-size:12px;padding:0 16px">온라인: ${fmtDuration(thresholds.online_sec)} 이내 수신 · 지연: ${fmtDuration(thresholds.stale_sec)} 이내 · 그 이후 오프라인. 행을 누르면 해당 PC 의 이벤트를 검색합니다.</p>`;
      table.querySelectorAll('[data-host]').forEach((tr) =>
        tr.addEventListener('click', () => navigate('events', { since, host: tr.dataset.host })));
    } catch (err) {
      const table = root.querySelector('[data-table]');
      if (table) table.innerHTML = errorBox(err); // 화면을 떠난 뒤 끝난 요청이면 무시
    }
  }

  await load();
  timer = setInterval(() => { if (!document.hidden) load(); }, 15000);
  return () => clearInterval(timer);
}
