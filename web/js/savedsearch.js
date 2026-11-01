// 저장한 검색 (B-64): 정기 점검의 반복 검색을 이름 붙여 저장·공유하고, 최근 검색을 다시 쓴다.
// 적용 = 검색 문장을 그 문장으로 바꿈(기간은 그대로), 더하기 = 지금 문장 뒤에 붙임(검색 문장은 조건을 모두 만족 — AND). 알림 규칙이 쓰는 검색(match.saved)은 고치면 다음 평가부터 규칙에 반영되므로
// 서버가 '알림 규칙을 고칠 수 있는 사람'만 고치게 하고, 화면은 서버가 준 can_edit 만 따른다.
import * as api from './api.js';
import { isAdmin } from './auth.js';
import { closeDrawer, openDrawer } from './drawer.js';
import { confirmModal, errorBox, fmtRelative, html, toast } from './util.js';

/**
 * @param {{query: () => string, apply: (text: string) => void}} ctx
 *   query: 지금 확정된 검색 문장, apply: 문장을 바꿔 바로 검색
 */
export function openSavedSearches(ctx) {
  const body = openDrawer({ title: '저장한 검색', subtitle: '자주 쓰는 검색을 이름 붙여 두고 다시 씁니다' });
  let editing = null;   // 고치는 중인 검색의 id
  let current = '';

  async function load() {
    body.innerHTML = '<div class="skeleton"></div>';
    try {
      const [saved, recent] = await Promise.all([api.get('/api/searches'), api.get('/api/searches/recent')]);
      render(saved.items, recent.items);
    } catch (err) {
      body.innerHTML = errorBox(err);
    }
  }

  function render(items, recent) {
    current = ctx.query().trim();
    body.innerHTML = html`
      <section class="form-section">
        <h3>지금 검색 저장</h3>
        ${current ? html`<code class="saved-q">${current}</code>
          <div class="form">
            <label class="field"><span>이름</span><input class="input" data-new-name maxlength="100" placeholder="예) 주간 점검 — 관리자 계정 로그온 실패"></label>
            <label class="field"><span>설명 (선택)</span><input class="input" data-new-desc maxlength="500" placeholder="무엇을 보려는 검색인지"></label>
            <div class="toolbar" style="gap:14px;flex-wrap:wrap">
              <label><input type="checkbox" data-new-shared> 모두에게 공유</label>
              ${isAdmin() ? html`<label title="점검 기준으로 정한 검색 — 관리자만 고치거나 지웁니다"><input type="checkbox" data-new-protected> 보호</label>` : ''}
            </div>
            <div class="toolbar"><button class="btn primary" data-new-save>저장</button></div>
          </div>` : html`<p class="muted">검색 문장을 먼저 입력하세요. 기간은 저장하지 않습니다 — 불러올 때 지금 고른 기간으로 찾습니다.</p>`}
      </section>
      <section class="form-section">
        <h3>저장한 검색 <span class="muted">${items.length}</span></h3>
        ${items.length ? html`<ul class="saved-list">${items.map((s) => item(s))}</ul>` : html`<p class="muted">아직 저장한 검색이 없습니다.</p>`}
      </section>
      <section class="form-section">
        <h3>최근 검색 <span class="muted">30일</span></h3>
        ${recent.length ? html`<ul class="saved-list">${recent.map((r, i) => html`<li class="saved-item">
            <button type="button" class="btn ghost sm saved-apply" data-recent="${i}" title="이 문장으로 검색"><code>${r.query}</code></button>
            <span class="muted">${fmtRelative(r.last_at)}</span></li>`)}</ul>`
          : html`<p class="muted">최근 30일에 검색한 문장이 없습니다.</p>`}
      </section>`;

    body.querySelector('[data-new-save]')?.addEventListener('click', async (e) => {
      const name = body.querySelector('[data-new-name]').value.trim();
      if (!name) { toast('이름을 적으세요.', { type: 'error' }); return; }
      e.target.disabled = true;
      try {
        await api.send('POST', '/api/searches', {
          name, query: current, description: body.querySelector('[data-new-desc]').value.trim(),
          shared: body.querySelector('[data-new-shared]').checked,
          protected: Boolean(body.querySelector('[data-new-protected]')?.checked),
        });
        toast(`'${name}' 검색을 저장했습니다.`, { type: 'success' });
        load();
      } catch (err) {
        e.target.disabled = false;
        toast(err.message, { type: 'error' });
      }
    });
    body.querySelectorAll('[data-recent]').forEach((b) => b.addEventListener('click', () => use(recent[Number(b.dataset.recent)].query)));
    const byId = new Map(items.map((s) => [String(s.id), s]));
    body.querySelectorAll('[data-apply]').forEach((b) => b.addEventListener('click', () => use(byId.get(b.dataset.apply).query)));
    body.querySelectorAll('[data-add]').forEach((b) => b.addEventListener('click', () => use(`${current} ${byId.get(b.dataset.add).query}`)));
    body.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => { editing = Number(b.dataset.edit); render(items, recent); }));
    body.querySelector('[data-edit-cancel]')?.addEventListener('click', () => { editing = null; render(items, recent); });
    body.querySelector('[data-edit-save]')?.addEventListener('click', () => update(byId.get(String(editing))));
    body.querySelectorAll('[data-delete]').forEach((b) => b.addEventListener('click', () => remove(byId.get(b.dataset.delete))));
  }

  function item(s) {
    const badges = [s.shared ? '공유' : '나만', s.protected ? '보호' : '', s.used_by.length ? `알림 규칙 ${s.used_by.length}개가 씀` : ''].filter(Boolean);
    if (editing === s.id) {
      return html`<li class="saved-item editing"><div class="form" style="flex:1">
        <label class="field"><span>이름</span><input class="input" data-edit-name maxlength="100" value="${s.name}" ${s.used_by.length ? 'disabled' : ''} title="${s.used_by.length ? '알림 규칙이 이 이름으로 씁니다' : ''}"></label>
        <label class="field"><span>검색 문장</span><input class="input" data-edit-query value="${s.query}"></label>
        <label class="field"><span>설명</span><input class="input" data-edit-desc maxlength="500" value="${s.description}"></label>
        <div class="toolbar" style="gap:14px;flex-wrap:wrap">
          <label><input type="checkbox" data-edit-shared ${s.shared ? 'checked' : ''}> 모두에게 공유</label>
          ${isAdmin() ? html`<label><input type="checkbox" data-edit-protected ${s.protected ? 'checked' : ''}> 보호</label>` : ''}
        </div>
        ${s.used_by.length ? html`<p class="muted" style="font-size:12.5px;margin:0">문장을 바꾸면 다음 평가부터 알림 규칙 ${s.used_by.join(', ')} 의 조건이 바뀌고, 관리자에게 알립니다.</p>` : ''}
        <div class="toolbar"><button class="btn primary" data-edit-save>저장</button><button class="btn ghost" data-edit-cancel>취소</button></div>
      </div></li>`;
    }
    return html`<li class="saved-item">
      <div class="saved-main">
        <div><strong>${s.name}</strong> <span class="muted saved-meta">${badges.join(' · ')} · ${s.owner}</span></div>
        <code class="saved-q">${s.query}</code>
        ${s.description ? html`<div class="muted saved-desc">${s.description}</div>` : ''}
      </div>
      <div class="toolbar">
        <button class="btn sm" data-apply="${s.id}" title="검색 문장을 이 문장으로 바꿉니다">적용</button>
        ${current && current !== s.query ? html`<button class="btn ghost sm" data-add="${s.id}" title="지금 문장에 이 조건을 더합니다 (모두 만족)">더하기</button>` : ''}
        ${s.can_edit && editing === null ? html`<button class="btn ghost sm" data-edit="${s.id}">고치기</button>
          <button class="btn ghost sm" data-delete="${s.id}" ${s.used_by.length ? 'disabled' : ''} title="${s.used_by.length ? '알림 규칙에서 먼저 빼세요' : ''}">삭제</button>` : ''}
      </div></li>`;
  }

  function use(text) {
    closeDrawer();
    ctx.apply(text);
  }

  async function update(s) {
    const value = (k) => body.querySelector(`[data-edit-${k}]`);
    try {
      await api.put(`/api/searches/${s.id}`, {
        name: value('name').value.trim(), query: value('query').value.trim(), description: value('desc').value.trim(),
        shared: value('shared').checked, protected: value('protected') ? value('protected').checked : s.protected,
      });
      editing = null;
      toast('고쳤습니다.', { type: 'success' });
      load();
    } catch (err) {
      toast(err.message, { type: 'error' });
    }
  }

  async function remove(s) {
    if (!await confirmModal({ title: '저장한 검색 삭제', message: `'${s.name}' 검색을 지웁니다.`, confirmText: '삭제', danger: true })) return;
    try {
      await api.send('DELETE', `/api/searches/${s.id}`);
      toast('지웠습니다.', { type: 'success' });
      load();
    } catch (err) {
      toast(err.message, { type: 'error' });
    }
  }

  load();
}
