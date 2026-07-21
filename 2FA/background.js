importScripts('crypto-lib.js');

const CLEAR_ALARM = 'clipboard-clear';
const CLEAR_DELAY_MIN = 0.5; // 30秒。ブラウザによっては1分に丸められる場合がある(alarms APIの仕様上の制約)。

// ===== vault書き込みの直列化キュー =====
// popup.jsとscan.jsは別プロセスなので、それぞれが直接 chrome.storage.local に
// 読み込み→復号→変更→暗号化→書き込みをすると、その間に相手が割り込んでどちらかの
// 変更が消える(lost update)。すべての書き込みをこのservice worker一箇所に集約し、
// Promiseチェーンで一件ずつ順番に処理することで競合そのものを起こさせない。
let vaultQueue = Promise.resolve();

function queueVaultTask(taskFn) {
  const result = vaultQueue.then(taskFn, taskFn);
  vaultQueue = result.then(() => {}, () => {}); // 失敗してもキューは止めない
  return result;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!sender || sender.id !== chrome.runtime.id) return;

  if (msg && msg.type === 'vaultMutate') {
    queueVaultTask(async () => {
      const key = await getSessionKey();
      if (!key) throw new Error('locked');

      const local = await chrome.storage.local.get(['vaultData']);
      const accounts = local.vaultData ? await decryptJSON(key, local.vaultData) : [];

      let result;
      if (msg.op === 'merge') {
        let addedCount = 0;
        const merged = accounts.slice();
        (msg.newAccounts || []).forEach(na => {
          if (!merged.some(c => c.secret === na.secret)) {
            merged.push(na);
            addedCount++;
          }
        });
        result = { accounts: merged, meta: { addedCount } };
      } else if (msg.op === 'delete') {
        result = { accounts: accounts.filter(a => a.secret !== msg.secret) };
      } else {
        throw new Error('unknown-op');
      }

      const payload = await encryptJSON(key, result.accounts);
      await chrome.storage.local.set({ vaultData: payload });
      return result;
    }).then(
      (result) => sendResponse({ ok: true, accounts: result.accounts, meta: result.meta }),
      (err) => sendResponse({ ok: false, error: err.message })
    );
    return true; // 非同期でsendResponseを呼ぶ
  }

  if (msg && msg.type === 'scheduleClipboardClear') {
    chrome.storage.session.set({ clipboardExpected: msg.expected || null });
    chrome.alarms.create(CLEAR_ALARM, { delayInMinutes: CLEAR_DELAY_MIN });
  }
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== CLEAR_ALARM) return;
  try {
    await ensureOffscreenDocument();
    await chrome.runtime.sendMessage({ type: 'offscreen-clear-clipboard' });
  } catch (e) {
    // オフスクリーン経由の消去に失敗しても致命的ではない
  } finally {
    chrome.storage.session.remove(['clipboardExpected']);
    // 使い終わったら閉じる（常駐させない）。応答処理の猶予を少し待つ。
    setTimeout(() => { chrome.offscreen.closeDocument().catch(() => {}); }, 500);
  }
});

async function ensureOffscreenDocument() {
  const existing = await chrome.runtime.getContexts({ contextTypes: ['OFFSCREEN_DOCUMENT'] });
  if (existing.length > 0) return;
  await chrome.offscreen.createDocument({
    url: 'offscreen.html',
    reasons: ['CLIPBOARD'],
    justification: 'コピーしたTOTPコードを一定時間後に自動でクリップボードから消去するため'
  });
}
