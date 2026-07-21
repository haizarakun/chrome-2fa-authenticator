chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!sender || sender.id !== chrome.runtime.id) return;
  if (msg && msg.type === 'offscreen-clear-clipboard') {
    clearClipboardIfUnchanged().finally(() => sendResponse());
    return true; // 非同期でsendResponseを呼ぶことを示す
  }
});

async function clearClipboardIfUnchanged() {
  const { clipboardExpected } = await chrome.storage.session.get(['clipboardExpected']);

  // 可能であれば「まだコピーしたコードのままか」を確認してから消す。
  // 別のものを既にコピーしていた場合はそれを巻き込んで消さない。
  if (clipboardExpected) {
    try {
      const current = await navigator.clipboard.readText();
      if (current !== clipboardExpected) return; // 既に別の内容 → 何もしない
    } catch (e) {
      // 読み取り不可（フォーカス無しなど）の場合は安全側に倒して消去を続行
    }
  }

  try {
    await navigator.clipboard.writeText('');
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = '';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e2) { /* noop */ }
    document.body.removeChild(ta);
  }
}
