// CSV 내려받기 공용: 사유를 받아(접속기록에 함께 남음, ADR-042) 받아서 저장한다.
// 주소로 이동하지 않는 것은 서버가 거절할 때(사유 없음·접속기록 실패 503) 화면을 떠나지 않고 이유를 보이기 위해서다.
import { promptModal, toast } from './util.js';

/** @param {string} path 예) '/api/audit'  @param {Record<string, string>} params format=csv 는 여기서 붙인다 */
export async function exportCsv(path, params = {}, { what = '자료' } = {}) {
  const reason = await promptModal({
    title: 'CSV 내려받기',
    message: `${what}에는 사용자·IP 같은 개인정보가 들어 있을 수 있습니다. 내려받는 사유를 적어 주세요 — 접속기록에 함께 남습니다.`,
    placeholder: '예) 월간 점검, 사고 조사',
    confirmText: '내려받기',
  });
  if (reason == null) return;
  if (reason.trim().length < 2) { toast('사유를 두 글자 이상 적어 주세요', { type: 'error' }); return; }
  const q = new URLSearchParams({ ...Object.fromEntries(Object.entries(params).filter(([, v]) => v != null && v !== '')),
    format: 'csv', reason: reason.trim() });
  try {
    const res = await fetch(`${path}?${q}`, { headers: { 'X-WLM-CSRF': '1' } });
    if (!res.ok) {
      let detail = `${res.status} ${res.statusText}`;
      try { detail = (await res.json()).detail || detail; } catch { /* 본문이 JSON 이 아님 */ }
      toast(detail, { type: 'error' });
      return;
    }
    const name = /filename="?([^";]+)"?/.exec(res.headers.get('Content-Disposition') || '')?.[1] || 'export.csv';
    const link = Object.assign(document.createElement('a'), { href: URL.createObjectURL(await res.blob()), download: name });
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 60000);
    toast(res.headers.get('X-WLM-Truncated') ? `내려받았습니다 (${name}) — 최대 건수에서 잘렸습니다. 기간을 나눠 받으세요` : `내려받았습니다 (${name})`);
  } catch (err) {
    toast(String(err.message || err), { type: 'error' });
  }
}
