// ===== otpauth-migration / otpauth パーサー =====
function b64ToBuf(b64) {
  const cleanB64 = b64.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(cleanB64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function bufToBase32(buf) {
  const b32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (let i = 0; i < buf.length; i++) bits += buf[i].toString(2).padStart(8, '0');
  let b32 = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.substr(i, 5).padEnd(5, '0');
    b32 += b32chars[parseInt(chunk, 2)];
  }
  return b32;
}

function base32ToBuf(secret) {
  const b32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (let i = 0; i < secret.length; i++) {
    const val = b32chars.indexOf(secret[i].toUpperCase());
    if (val >= 0) bits += val.toString(2).padStart(5, '0');
  }
  const buf = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < buf.length; i++) {
    buf[i] = parseInt(bits.substr(i * 8, 8), 2);
  }
  return buf;
}

function readVarint(buf, offset) {
  let result = 0;
  let shift = 0;
  let b;
  let i = offset;
  do {
    if (i >= buf.length) return { value: 0, bytes: 0 };
    b = buf[i++];
    result |= (b & 0x7f) << shift;
    shift += 7;
  } while (b & 0x80);
  return { value: result, bytes: i - offset };
}

function parseMigrationURI(uri) {
  const accounts = [];
  try {
    const url = new URL(uri.trim());
    if (url.protocol !== 'otpauth-migration:') return null;
    const dataParam = url.searchParams.get('data');
    if (!dataParam) return null;

    const mainBuf = b64ToBuf(dataParam);
    let index = 0;

    while (index < mainBuf.length) {
      const tag = mainBuf[index++];
      const wireType = tag & 0x7;
      const fieldNum = tag >> 3;

      if (fieldNum === 1 && wireType === 2) {
        const lenVarint = readVarint(mainBuf, index);
        if (lenVarint.bytes === 0) break;
        const len = lenVarint.value;
        index += lenVarint.bytes;

        const subEnd = index + len;
        let secret = '';
        let name = 'Unknown';
        let issuer = '';

        while (index < subEnd) {
          if (index >= mainBuf.length) break;
          const subTag = mainBuf[index++];
          const subWire = subTag & 0x7;
          const subField = subTag >> 3;

          if (subWire === 2) {
            const subLenVarint = readVarint(mainBuf, index);
            const subLen = subLenVarint.value;
            index += subLenVarint.bytes;

            if (subField === 1) {
              secret = bufToBase32(mainBuf.slice(index, index + subLen));
            } else if (subField === 2) {
              name = new TextDecoder().decode(mainBuf.slice(index, index + subLen));
            } else if (subField === 3) {
              issuer = new TextDecoder().decode(mainBuf.slice(index, index + subLen));
            }
            index += subLen;
          } else if (subWire === 0) {
            const v = readVarint(mainBuf, index);
            index += v.bytes;
          } else if (subWire === 1) {
            index += 8;
          } else if (subWire === 5) {
            index += 4;
          } else {
            index++;
          }
        }

        if (secret) {
          accounts.push({ secret, name, issuer: issuer || 'Service' });
        }
        index = subEnd;
      } else {
        if (wireType === 0) {
          const v = readVarint(mainBuf, index);
          index += v.bytes;
        } else if (wireType === 2) {
          const v = mainBuf[index++];
          index += v;
        } else if (wireType === 1) {
          index += 8;
        } else if (wireType === 5) {
          index += 4;
        } else {
          index++;
        }
      }
    }
  } catch (e) {
    addLog(`パースエラー: ${e.message}`);
    return null;
  }
  return accounts.length > 0 ? accounts : null;
}

function parseSingleOtpauthURI(uri) {
  try {
    const url = new URL(uri.trim());
    if (url.protocol !== 'otpauth:') return null;
    if (url.host !== 'totp') return null; // HOTPは非対応
    const secret = url.searchParams.get('secret');
    if (!secret) return null;
    const issuer = url.searchParams.get('issuer') || '';
    let label = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
    let name = label;
    let labelIssuer = issuer;
    if (label.includes(':')) {
      const parts = label.split(':');
      labelIssuer = labelIssuer || parts[0];
      name = parts.slice(1).join(':');
    }
    return [{ secret, name: name || 'Unknown', issuer: labelIssuer || 'Service' }];
  } catch (e) {
    return null;
  }
}

async function generateTOTP(secretStr) {
  try {
    const cleanSecret = secretStr.replace(/[\s-]/g, '').toUpperCase();
    const keyBuf = base32ToBuf(cleanSecret);
    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / 30);

    const counterBuf = new Uint8Array(8);
    let tmp = counter;
    for (let i = 7; i >= 0; i--) {
      counterBuf[i] = tmp & 0xff;
      tmp = tmp >> 8;
    }

    const cryptoKey = await crypto.subtle.importKey(
      'raw', keyBuf, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, counterBuf);
    const hmac = new Uint8Array(signature);

    const offset = hmac[hmac.length - 1] & 0xf;
    const codeNum = ((hmac[offset] & 0x7f) << 24) |
                    ((hmac[offset + 1] & 0xff) << 16) |
                    ((hmac[offset + 2] & 0xff) << 8) |
                    (hmac[offset + 3] & 0xff);

    const codeStr = (codeNum % 1000000).toString().padStart(6, '0');
    return `${codeStr.substr(0, 3)} ${codeStr.substr(3, 3)}`;
  } catch (e) {
    return 'ERROR';
  }
}

// ===== ログ機能(非機密。issuer/name のみ記録し secret やコードは記録しない) =====
const LOG_LIMIT = 300;

function addLog(message) {
  const ts = new Date().toLocaleString('ja-JP', { hour12: false });
  const line = `[${ts}] ${message}`;
  chrome.storage.local.get(['appLogs'], (res) => {
    const logs = res.appLogs || [];
    logs.push(line);
    if (logs.length > LOG_LIMIT) logs.splice(0, logs.length - LOG_LIMIT);
    chrome.storage.local.set({ appLogs: logs }, () => renderLogs(logs));
  });
}

function renderLogs(logs) {
  const panel = document.getElementById('logPanel');
  if (!panel) return;
  panel.textContent = logs.join('\n');
  panel.scrollTop = panel.scrollHeight;
}

function setupLogUI() {
  const toggleBtn = document.getElementById('logToggleBtn');
  const panel = document.getElementById('logPanel');
  const actions = document.getElementById('logActions');
  const copyBtn = document.getElementById('logCopyBtn');
  const clearBtn = document.getElementById('logClearBtn');

  chrome.storage.local.get(['appLogs'], (res) => renderLogs(res.appLogs || []));

  toggleBtn.addEventListener('click', () => {
    const show = panel.style.display !== 'block';
    panel.style.display = show ? 'block' : 'none';
    actions.style.display = show ? 'flex' : 'none';
  });

  copyBtn.addEventListener('click', () => {
    chrome.storage.local.get(['appLogs'], (res) => {
      const text = (res.appLogs || []).join('\n');
      navigator.clipboard.writeText(text).then(() => {
        copyBtn.textContent = 'コピーしました';
        setTimeout(() => { copyBtn.textContent = 'ログをコピー'; }, 1200);
      }).catch(() => {
        copyBtn.textContent = 'コピー失敗';
        setTimeout(() => { copyBtn.textContent = 'ログをコピー'; }, 1200);
      });
    });
  });

  clearBtn.addEventListener('click', () => {
    chrome.storage.local.set({ appLogs: [] }, () => renderLogs([]));
  });
}

// ===== テーマカラー =====
function setupAccentColor() {
  const input = document.getElementById('accentColor');
  chrome.storage.local.get(['accentColor'], (res) => {
    const color = res.accentColor || '#1a73e8';
    input.value = color;
    applyAccentColor(color);
  });
  input.addEventListener('input', () => applyAccentColor(input.value));
  input.addEventListener('change', () => {
    chrome.storage.local.set({ accentColor: input.value }, () => addLog(`テーマカラーを変更: ${input.value}`));
  });
}

function applyAccentColor(hex) {
  document.documentElement.style.setProperty('--accent', hex);
  document.documentElement.style.setProperty('--accent-dark', shadeColor(hex, -15));
}

function setupBgColor() {
  const input = document.getElementById('bgColor');
  chrome.storage.local.get(['bgColor'], (res) => {
    const color = res.bgColor || '#fafafa';
    input.value = color;
    applyBgColor(color);
  });
  input.addEventListener('input', () => applyBgColor(input.value));
  input.addEventListener('change', () => {
    chrome.storage.local.set({ bgColor: input.value }, () => addLog(`背景カラーを変更: ${input.value}`));
  });
}

function applyBgColor(hex) {
  document.documentElement.style.setProperty('--bg-page', hex);
  document.documentElement.style.setProperty('--bg-card', shadeColor(hex, 20));
}

function shadeColor(hex, percent) {
  const clean = hex.replace('#', '');
  const num = parseInt(clean, 16);
  let r = (num >> 16) + Math.round(255 * (percent / 100));
  let g = ((num >> 8) & 0x00ff) + Math.round(255 * (percent / 100));
  let b = (num & 0x0000ff) + Math.round(255 * (percent / 100));
  r = Math.max(0, Math.min(255, r));
  g = Math.max(0, Math.min(255, g));
  b = Math.max(0, Math.min(255, b));
  return `#${(1 << 24 | r << 16 | g << 8 | b).toString(16).slice(1)}`;
}

// ===== カメラQRインポート起動 =====
function setupCameraScan() {
  document.getElementById('cameraScanBtn').addEventListener('click', () => {
    chrome.windows.create({ url: 'scan.html', type: 'popup', width: 420, height: 560 });
    addLog('カメラQR読み取りウィンドウを起動');
  });
}

// =====================================================================
// ===== マスターパスワード保管庫(vault)  =====
// secret は chrome.storage.local に平文では保存しない。
// AES-GCM(鍵はPBKDF2でパスワードから導出)で暗号化した状態でのみ保存する。
// 復号後の配列はこのポップアップのメモリ内(decryptedAccounts)にのみ存在し、
// ポップアップが閉じれば消える。
// =====================================================================
let decryptedAccounts = [];
let vaultKey = null; // CryptoKey（アンロック中のみ保持）

function vaultDom() {
  return {
    lockScreen: document.getElementById('lockScreen'),
    mainContent: document.getElementById('mainContent'),
    lockTitle: document.getElementById('lockTitle'),
    lockError: document.getElementById('lockError'),
    lockNote: document.getElementById('lockNote'),
    pwInput: document.getElementById('pwInput'),
    pwInput2: document.getElementById('pwInput2'),
    unlockBtn: document.getElementById('unlockBtn'),
  };
}

async function persistAccounts() {
  // 単純書き込み用（初回のvault作成時など、書き込み競合が起きようがない場面専用）
  const payload = await encryptJSON(vaultKey, decryptedAccounts);
  await chrome.storage.local.set({ vaultData: payload });
}

// 実際の変更(merge/delete)はbackground service workerに一本化して直列実行させる。
// これによりpopupとscan(カメラウィンドウ)が同時に書き込んでも競合しない。
async function vaultMutate(op, extra) {
  const res = await chrome.runtime.sendMessage({ type: 'vaultMutate', op, ...extra });
  if (!res || !res.ok) throw new Error((res && res.error) || 'vault-mutate-failed');
  return res;
}

function showUnlocked() {
  const dom = vaultDom();
  dom.lockScreen.style.display = 'none';
  dom.mainContent.style.display = 'block';
  document.getElementById('accountList').innerHTML = '';
  updateLoop();
}

function showLockScreenError(msg) {
  const dom = vaultDom();
  dom.lockError.textContent = msg;
}

async function initVault() {
  const dom = vaultDom();
  const local = await chrome.storage.local.get(['vaultSalt', 'vaultData', 'googleAccounts']);

  // ケース1: まだマスターパスワード未設定（初回起動 or 旧バージョンからの移行）
  if (!local.vaultSalt) {
    dom.lockTitle.textContent = 'マスターパスワードを設定';
    dom.pwInput2.style.display = 'block';
    dom.lockNote.textContent = local.googleAccounts && local.googleAccounts.length > 0
      ? `既存の${local.googleAccounts.length}件のアカウントを暗号化して移行します。`
      : 'このパスワードは保存されません。忘れると復元できないのでご注意ください。';

    dom.unlockBtn.onclick = async () => {
      const pw = dom.pwInput.value;
      const pw2 = dom.pwInput2.value;
      if (!pw) { showLockScreenError('パスワードを入力してください'); return; }
      if (pw !== pw2) { showLockScreenError('確認用パスワードが一致しません'); return; }
      if (pw.length < 4) { showLockScreenError('4文字以上にしてください'); return; }

      const salt = crypto.getRandomValues(new Uint8Array(16));
      vaultKey = await deriveKeyFromPassword(pw, salt);

      // 旧バージョン(平文保存)からの移行
      decryptedAccounts = local.googleAccounts || [];

      await chrome.storage.local.set({ vaultSalt: b64encode(salt) });
      await persistAccounts();
      if (local.googleAccounts) {
        await chrome.storage.local.remove(['googleAccounts']); // 平文データを削除
        addLog(`マスターパスワードを設定し、既存${decryptedAccounts.length}件を暗号化移行`);
      } else {
        addLog('マスターパスワードを設定');
      }
      await setSessionKey(vaultKey);
      showUnlocked();
    };
    return;
  }

  // ケース2: 既にこのブラウザセッション内でアンロック済み（キーがセッションに残っている）
  const cachedKey = await getSessionKey();
  if (cachedKey) {
    try {
      vaultKey = cachedKey;
      decryptedAccounts = local.vaultData ? await decryptJSON(cachedKey, local.vaultData) : [];
      if (local.googleAccounts) await chrome.storage.local.remove(['googleAccounts']);
      showUnlocked();
      return;
    } catch (e) {
      // セッションキーが古い/不正 → 通常のロック画面へフォールバック
      await clearSessionKey();
    }
  }

  // ケース3: 通常のロック解除画面
  dom.lockTitle.textContent = 'ロック解除';
  dom.pwInput2.style.display = 'none';
  dom.lockNote.textContent = '';

  dom.unlockBtn.onclick = async () => {
    const pw = dom.pwInput.value;
    if (!pw) { showLockScreenError('パスワードを入力してください'); return; }
    try {
      const salt = b64decode(local.vaultSalt);
      const key = await deriveKeyFromPassword(pw, salt);
      const accounts = local.vaultData ? await decryptJSON(key, local.vaultData) : [];
      vaultKey = key;
      decryptedAccounts = accounts;
      await setSessionKey(key);
      if (local.googleAccounts) await chrome.storage.local.remove(['googleAccounts']);
      showLockScreenError('');
      addLog('ロック解除');
      showUnlocked();
    } catch (e) {
      showLockScreenError('パスワードが違います');
    }
  };
}

async function lockVault() {
  vaultKey = null;
  decryptedAccounts = [];
  await clearSessionKey();
  document.getElementById('mainContent').style.display = 'none';
  document.getElementById('lockScreen').style.display = 'block';
  const dom = vaultDom();
  dom.pwInput.value = '';
  dom.pwInput2.value = '';
  dom.lockError.textContent = '';
  addLog('ロックしました');
  initVault();
}

// ===== アカウント一覧描画（暗号化復号済みのメモリ上データを描画） =====
async function updateLoop() {
  const container = document.getElementById('accountList');
  const remain = 30 - (Math.floor(Date.now() / 1000) % 30);
  document.getElementById('global-timer').innerText = `(${remain}s)`;

  if (decryptedAccounts.length > 0) {
    if (container.children.length !== decryptedAccounts.length) {
      container.innerHTML = '';
      decryptedAccounts.forEach((acc, index) => {
        const item = document.createElement('div');
        item.className = 'account-item';

        const issuerEl = document.createElement('div');
        issuerEl.className = 'account-issuer';
        issuerEl.textContent = `${acc.issuer} [#${index + 1}]`;

        const infoEl = document.createElement('div');
        infoEl.className = 'account-info';
        infoEl.textContent = acc.name;

        const codeEl = document.createElement('div');
        codeEl.className = 'code';
        codeEl.id = `code-${index}`;
        codeEl.title = 'クリックしてコピー';
        codeEl.textContent = '------';

        const copyHintEl = document.createElement('div');
        copyHintEl.className = 'copy-hint';

        codeEl.addEventListener('click', () => {
          const raw = codeEl.textContent.replace(/\s/g, '');
          if (!raw || raw === '------' || raw === 'ERROR') return;
          navigator.clipboard.writeText(raw).then(() => {
            chrome.runtime.sendMessage({ type: 'scheduleClipboardClear', expected: raw });
            addLog(`コードをコピー: ${acc.issuer} (${acc.name})`);
            copyHintEl.textContent = '⚠ コピーしました。他の拡張機能に読み取られる可能性があるため約30秒後に自動消去します';
            copyHintEl.classList.add('show');
            setTimeout(() => {
              copyHintEl.textContent = '';
              copyHintEl.classList.remove('show');
            }, 4000);
          }).catch(() => addLog('コードのコピーに失敗'));
        });

        const actionRow = document.createElement('div');
        actionRow.className = 'action-row';

        const qrContainer = document.createElement('div');
        qrContainer.className = 'qr-container';
        let qrInstance = null;

        const qrBtn = document.createElement('button');
        qrBtn.className = 'action-btn';
        qrBtn.textContent = 'QR表示';
        qrBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          if (qrContainer.style.display === 'none' || qrContainer.style.display === '') {
            qrContainer.style.display = 'block';
            qrBtn.textContent = 'QR閉じる';
            if (!qrInstance) {
              const otpauthUri = `otpauth://totp/${encodeURIComponent(acc.issuer)}:${encodeURIComponent(acc.name)}?secret=${acc.secret}&issuer=${encodeURIComponent(acc.issuer)}`;
              qrInstance = new QRCode(qrContainer, { text: otpauthUri, width: 130, height: 130, correctLevel: QRCode.CorrectLevel.L });
            }
          } else {
            qrContainer.style.display = 'none';
            qrBtn.textContent = 'QR表示';
          }
        });

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'action-btn btn-delete';
        deleteBtn.textContent = '削除';
        deleteBtn.addEventListener('click', async (e) => {
          e.stopPropagation();
          if (confirm(`「${acc.issuer} (${acc.name})」を削除しますか？\n※バックアップがない場合、元に戻せなくなります。`)) {
            try {
              const result = await vaultMutate('delete', { secret: acc.secret });
              decryptedAccounts = result.accounts;
              addLog(`アカウントを削除: ${acc.issuer} (${acc.name})`);
              container.innerHTML = '';
              updateLoop();
            } catch (err) {
              alert('削除に失敗しました。もう一度お試しください。');
              addLog(`削除失敗: ${err.message}`);
            }
          }
        });

        actionRow.appendChild(qrBtn);
        actionRow.appendChild(deleteBtn);

        item.appendChild(issuerEl);
        item.appendChild(infoEl);
        item.appendChild(codeEl);
        item.appendChild(copyHintEl);
        item.appendChild(actionRow);
        item.appendChild(qrContainer);
        container.appendChild(item);
      });
    }

    for (let i = 0; i < decryptedAccounts.length; i++) {
      const codeEl = document.getElementById(`code-${i}`);
      if (codeEl) codeEl.innerText = await generateTOTP(decryptedAccounts[i].secret);
    }
  } else {
    container.innerHTML = '<div style="text-align:center; font-size:12px; color:#999; padding:20px;">未設定</div>';
  }
}

document.getElementById('saveBtn').addEventListener('click', async () => {
  const inputVal = document.getElementById('secretInput').value.trim();
  if (!inputVal) return;
  if (!vaultKey) return;

  let parsedAccounts = null;
  if (inputVal.startsWith('otpauth-migration:')) {
    parsedAccounts = parseMigrationURI(inputVal);
  } else if (inputVal.startsWith('otpauth:')) {
    parsedAccounts = parseSingleOtpauthURI(inputVal);
  } else {
    alert('otpauth-migration:// または otpauth:// から始まるURIを入力してください。');
    addLog('読み込み失敗: 未対応のURI形式');
    return;
  }

  if (parsedAccounts) {
    try {
      const result = await vaultMutate('merge', { newAccounts: parsedAccounts });
      decryptedAccounts = result.accounts;
      document.getElementById('secretInput').value = '';
      document.getElementById('accountList').innerHTML = '';
      addLog(`テキスト貼り付けで読み込み: 新規${result.meta.addedCount}件 (合計${decryptedAccounts.length}件)`);
      alert(`読み込み完了！新たに ${result.meta.addedCount} 件を読み込みました。\n(現在合計: ${decryptedAccounts.length} 件)`);
      updateLoop();
    } catch (err) {
      alert('読み込みに失敗しました。もう一度お試しください。');
      addLog(`読み込み失敗: ${err.message}`);
    }
  } else {
    alert('データの解析に失敗しました。');
    addLog('読み込み失敗: データ解析エラー');
  }
});

// scan.html（別ウィンドウ）が vaultData を更新した場合に自動で再復号して反映
chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area === 'local' && changes.vaultData && vaultKey) {
    try {
      decryptedAccounts = await decryptJSON(vaultKey, changes.vaultData.newValue);
      document.getElementById('accountList').innerHTML = '';
      updateLoop();
    } catch (e) { /* 復号不能なら無視 */ }
  }
  if (area === 'local' && changes.appLogs) {
    renderLogs(changes.appLogs.newValue || []);
  }
});

document.getElementById('lockBtn').addEventListener('click', lockVault);

['pwInput', 'pwInput2'].forEach(id => {
  document.getElementById(id).addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('unlockBtn').click();
  });
});

setupLogUI();
setupAccentColor();
setupBgColor();
setupCameraScan();
initVault();
setInterval(updateLoop, 1000);
