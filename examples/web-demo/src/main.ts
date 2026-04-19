interface Entry {
  seq: string;
  key: string;
  data: string;
  timestampNs: string;
  leafHash: string;
}

interface AppendResult {
  seq: string;
  timestampNs: string;
  leafHash: string;
}

function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

const keyInput    = el<HTMLInputElement>('key');
const dataInput   = el<HTMLTextAreaElement>('data');
const appendBtn   = el<HTMLButtonElement>('appendBtn');
const reloadBtn   = el<HTMLButtonElement>('reloadBtn');
const statusEl    = el<HTMLDivElement>('status');
const tableWrap   = el<HTMLDivElement>('tableWrap');
const treeInfoEl  = el<HTMLDivElement>('treeInfo');

function setStatus(msg: string, ok: boolean): void {
  statusEl.textContent = msg;
  statusEl.className = ok ? 'ok' : 'err';
}

function formatTs(ns: string): string {
  const ms = Number(BigInt(ns) / 1_000_000n);
  return new Date(ms).toLocaleString();
}

function shortHash(hex: string): string {
  return hex.slice(0, 8) + '…' + hex.slice(-8);
}

function renderEntries(entries: Entry[]): void {
  if (entries.length === 0) {
    tableWrap.innerHTML = '<p class="empty">No entries in the log yet.</p>';
    treeInfoEl.innerHTML = '<span>Tree size: <span>0</span></span>';
    return;
  }

  treeInfoEl.innerHTML = `
    <span>Tree size: <span>${entries.length}</span></span>
    <span>Latest seq: <span>${entries[entries.length - 1]!.seq}</span></span>
    <span>Latest: <span>${formatTs(entries[entries.length - 1]!.timestampNs)}</span></span>
  `;

  const rows = [...entries].reverse().map((e) => `
    <tr>
      <td class="seq">${e.seq}</td>
      <td>${escHtml(e.key)}</td>
      <td class="data-cell">${escHtml(e.data)}</td>
      <td class="ts">${formatTs(e.timestampNs)}</td>
      <td class="hash" title="${e.leafHash}">${shortHash(e.leafHash)}</td>
    </tr>
  `).join('');

  tableWrap.innerHTML = `
    <table>
      <thead><tr>
        <th>Seq</th><th>Key</th><th>Data</th><th>Timestamp</th><th>Leaf Hash</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function escHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function loadEntries(): Promise<void> {
  reloadBtn.disabled = true;
  reloadBtn.textContent = 'Loading…';
  try {
    const res = await fetch('/api/entries');
    if (!res.ok) throw new Error(await res.text());
    const entries: Entry[] = await res.json();
    renderEntries(entries);
  } catch (e) {
    tableWrap.innerHTML = `<p class="empty" style="color:#fca5a5">Failed to load: ${e}</p>`;
  } finally {
    reloadBtn.disabled = false;
    reloadBtn.textContent = 'Reload Audit';
  }
}

async function appendEntry(): Promise<void> {
  const key  = keyInput.value.trim();
  const data = dataInput.value.trim();
  if (!key || !data) {
    setStatus('Key and Data are required.', false);
    return;
  }

  appendBtn.disabled = true;
  appendBtn.textContent = 'Appending…';
  statusEl.className = '';

  try {
    const res = await fetch('/api/entries', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key, data }),
    });
    if (!res.ok) {
      const err = await res.json() as { error: string };
      throw new Error(err.error);
    }
    const result: AppendResult = await res.json();
    setStatus(`Appended at seq ${result.seq} — leaf hash ${shortHash(result.leafHash)}`, true);
    dataInput.value = '';
    await loadEntries();
  } catch (e) {
    setStatus(`Error: ${e}`, false);
  } finally {
    appendBtn.disabled = false;
    appendBtn.textContent = 'Append';
  }
}

appendBtn.addEventListener('click', appendEntry);
reloadBtn.addEventListener('click', loadEntries);

dataInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) appendEntry();
});
