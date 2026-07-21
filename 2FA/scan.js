// ===== otpauth-migration / otpauth パーサー（popup.js と同一ロジック） =====
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
    return null;
  }
  return accounts.length > 0 ? accounts : null;
}

function parseSingleOtpauthURI(uri) {
  try {
    const url = new URL(uri.trim());
    if (url.protocol !== 'otpauth:') return null;
    if (url.host !== 'totp') return null;
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

function addLog(message) {
  const ts = new Date().toLocaleString('ja-JP', { hour12: false });
  const line = `[${ts}] ${message}`;
  chrome.storage.local.get(['appLogs'], (res) => {
    const logs = res.appLogs || [];
    logs.push(line);
    if (logs.length > 300) logs.splice(0, logs.length - 300);
    chrome.storage.local.set({ appLogs: logs });
  });
}

// ===== カメラ制御 =====
const video = document.getElementById('video');
const canvas = document.getElementById('canvas');
const ctx = canvas.getContext('2d', { willReadFrequently: true });
const cameraSelect = document.getElementById('cameraSelect');
const statusEl = document.getElementById('status');
const closeBtn = document.getElementById('closeBtn');

let currentStream = null;
let scanning = false;
let stopped = false;

function setStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = 'status' + (cls ? ' ' + cls : '');
}

async function listCameras() {
  const devices = await navigator.mediaDevices.enumerateDevices();
  const cams = devices.filter(d => d.kind === 'videoinput');
  cameraSelect.innerHTML = '';
  cams.forEach((cam, i) => {
    const opt = document.createElement('option');
    opt.value = cam.deviceId;
    opt.textContent = cam.label || `カメラ ${i + 1}`;
    cameraSelect.appendChild(opt);
  });
  return cams;
}

async function startCamera(deviceId) {
  if (currentStream) {
    currentStream.getTracks().forEach(t => t.stop());
    currentStream = null;
  }
  const constraints = {
    video: deviceId ? { deviceId: { exact: deviceId } } : { facingMode: 'environment' }
  };
  try {
    currentStream = await navigator.mediaDevices.getUserMedia(constraints);
    video.srcObject = currentStream;
    await video.play();
    setStatus('QRコードをカメラに映してください', null);
    if (!scanning) {
      scanning = true;
      requestAnimationFrame(scanLoop);
    }
  } catch (e) {
    setStatus(`カメラ起動に失敗: ${e.message}`, 'err');
    addLog(`カメラ起動失敗: ${e.message}`);
  }
}

function scanLoop() {
  if (stopped) return;
  if (video.readyState === video.HAVE_ENOUGH_DATA) {
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'dontInvert' });
    if (code && code.data) {
      handleDecoded(code.data);
      return; // handleDecoded が成功時に止める
    }
  }
  requestAnimationFrame(scanLoop);
}

function handleDecoded(text) {
  let parsedAccounts = null;
  if (text.startsWith('otpauth-migration:')) {
    parsedAccounts = parseMigrationURI(text);
  } else if (text.startsWith('otpauth:')) {
    parsedAccounts = parseSingleOtpauthURI(text);
  }

  if (!parsedAccounts) {
    setStatus('QRを検出しましたが2FA用ではありません。継続してスキャン中...', 'err');
    addLog('QR検出: 非対応形式のためスキップ');
    requestAnimationFrame(scanLoop);
    return;
  }

  stopped = true;
  (async () => {
    const key = await getSessionKey();
    if (!key) {
      setStatus('ロックされています。先にメインパネルでロック解除してください。', 'err');
      if (currentStream) currentStream.getTracks().forEach(t => t.stop());
      return;
    }
    try {
      const res = await chrome.runtime.sendMessage({ type: 'vaultMutate', op: 'merge', newAccounts: parsedAccounts });
      if (!res || !res.ok) throw new Error((res && res.error) || 'vault-mutate-failed');
      addLog(`カメラQR読み取りで同期: 新規${res.meta.addedCount}件 (合計${res.accounts.length}件)`);
      setStatus(`インポート完了: 新規${res.meta.addedCount}件（合計${res.accounts.length}件）`, 'ok');
      if (currentStream) currentStream.getTracks().forEach(t => t.stop());
      setTimeout(() => window.close(), 1200);
    } catch (e) {
      setStatus('保管データの書き込みに失敗しました。パスワードが変更された可能性があります。', 'err');
      addLog(`カメラQR読み取り失敗: ${e.message}`);
      if (currentStream) currentStream.getTracks().forEach(t => t.stop());
    }
  })();
}

cameraSelect.addEventListener('change', () => {
  stopped = false;
  startCamera(cameraSelect.value);
});

closeBtn.addEventListener('click', () => {
  if (currentStream) currentStream.getTracks().forEach(t => t.stop());
  window.close();
});

(async function init() {
  const key = await getSessionKey();
  if (!key) {
    setStatus('ロックされています。先にメインパネルでロック解除してから開いてください。', 'err');
    cameraSelect.style.display = 'none';
    return;
  }
  try {
    // ラベル取得のため先に一度パーミッションを得る
    const tmpStream = await navigator.mediaDevices.getUserMedia({ video: true });
    const cams = await listCameras();
    if (cams.length === 0) {
      tmpStream.getTracks().forEach(t => t.stop());
      setStatus('利用可能なカメラが見つかりません。', 'err');
      return;
    }
    // 取得済みのストリームをそのまま最初のカメラとして使い回す（二重リクエストを回避）
    currentStream = tmpStream;
    video.srcObject = currentStream;
    await video.play();
    setStatus('QRコードをカメラに映してください', null);
    scanning = true;
    requestAnimationFrame(scanLoop);
  } catch (e) {
    setStatus(`カメラへのアクセスが拒否されました: ${e.message}`, 'err');
    addLog(`カメラ権限拒否: ${e.message}`);
  }
})();
