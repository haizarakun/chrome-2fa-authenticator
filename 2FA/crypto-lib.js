// ===== マスターパスワードによる保管データの暗号化(AES-GCM + PBKDF2) =====
const PBKDF2_ITERATIONS = 200000;

function b64encode(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function b64decode(str) {
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function deriveKeyFromPassword(password, saltBytes) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true, // extractable: セッションキャッシュのためexport可能にする
    ['encrypt', 'decrypt']
  );
}

async function importRawKey(rawBytes) {
  return crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
}

async function exportRawKey(key) {
  return crypto.subtle.exportKey('raw', key);
}

async function encryptJSON(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const data = enc.encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { iv: b64encode(iv), ct: b64encode(ct) };
}

// 復号失敗(パスワード誤り/改ざん)時は例外を投げる
async function decryptJSON(key, payload) {
  const iv = b64decode(payload.iv);
  const ct = b64decode(payload.ct);
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(dec));
}

// chrome.storage.session はディスクに書かれない揮発ストレージ（ブラウザ終了で消える）。
// アンロック中の鍵をここに保持し、ポップアップ/スキャン画面の間で使い回すことで
// 開くたびにパスワードを再要求しない。
async function getSessionKey() {
  const res = await chrome.storage.session.get(['vaultKeyB64']);
  if (!res.vaultKeyB64) return null;
  return importRawKey(b64decode(res.vaultKeyB64));
}

async function setSessionKey(key) {
  const raw = await exportRawKey(key);
  await chrome.storage.session.set({ vaultKeyB64: b64encode(raw) });
}

async function clearSessionKey() {
  await chrome.storage.session.remove(['vaultKeyB64']);
}
