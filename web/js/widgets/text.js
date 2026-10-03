// 안내문. text: 문자열 (줄바꿈 유지)
import { html } from '../util.js';

export default {
  label: '안내문',
  async render(body, cfg) {
    body.innerHTML = html`<p class="ink-2" style="margin:0;white-space:pre-wrap">${cfg.text || ''}</p>`;
  },
};
