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
    console.error('パースエラー:', e);
    return null;
  }
  return accounts.length > 0 ? accounts : null;
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

async function updateLoop() {
  chrome.storage.local.get(['googleAccounts'], async (res) => {
    const container = document.getElementById('accountList');
    const remain = 30 - (Math.floor(Date.now() / 1000) % 30);
    document.getElementById('global-timer').innerText = `(${remain}s)`;

    if (res.googleAccounts && res.googleAccounts.length > 0) {
      if (container.children.length !== res.googleAccounts.length) {
        container.innerHTML = '';
        res.googleAccounts.forEach((acc, index) => {
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
          codeEl.textContent = '------';

          const actionRow = document.createElement('div');
          actionRow.className = 'action-row';

          // QRコード表示用のコンテナ（ローカルライブラリ用）
          const qrContainer = document.createElement('div');
          qrContainer.className = 'qr-container';
          
          let qrInstance = null;

          // QRコード表示ボタン
          const qrBtn = document.createElement('button');
          qrBtn.className = 'action-btn';
          qrBtn.textContent = 'QR表示';
          qrBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            if (qrContainer.style.display === 'none' || qrContainer.style.display === '') {
              qrContainer.style.display = 'block';
              qrBtn.textContent = 'QR閉じる';
              
              // 初回クリック時のみ、ローカルライブラリを使って完全にオフラインでQR生成
              if (!qrInstance) {
                const otpauthUri = `otpauth://totp/${encodeURIComponent(acc.issuer)}:${encodeURIComponent(acc.name)}?secret=${acc.secret}&issuer=${encodeURIComponent(acc.issuer)}`;
                qrInstance = new QRCode(qrContainer, {
                  text: otpauthUri,
                  width: 130,
                  height: 130,
                  correctLevel: QRCode.CorrectLevel.L
                });
              }
            } else {
              qrContainer.style.display = 'none';
              qrBtn.textContent = 'QR表示';
            }
          });

          // 削除ボタン
          const deleteBtn = document.createElement('button');
          deleteBtn.className = 'action-btn btn-delete';
          deleteBtn.textContent = '削除';
          deleteBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            if (confirm(`「${acc.issuer} (${acc.name})」を削除しますか？\n※バックアップがない場合、元に戻せなくなります。`)) {
              chrome.storage.local.get(['googleAccounts'], (currentRes) => {
                let list = currentRes.googleAccounts || [];
                list.splice(index, 1);
                chrome.storage.local.set({ googleAccounts: list }, () => {
                  container.innerHTML = '';
                  updateLoop();
                });
              });
            }
          });

          actionRow.appendChild(qrBtn);
          actionRow.appendChild(deleteBtn);

          item.appendChild(issuerEl);
          item.appendChild(infoEl);
          item.appendChild(codeEl);
          item.appendChild(actionRow);
          item.appendChild(qrContainer);
          container.appendChild(item);
        });
      }

      for (let i = 0; i < res.googleAccounts.length; i++) {
        const codeEl = document.getElementById(`code-${i}`);
        if (codeEl) codeEl.innerText = await generateTOTP(res.googleAccounts[i].secret);
      }
    } else {
      container.innerHTML = '<div style="text-align:center; font-size:12px; color:#999; padding:20px;">未設定</div>';
    }
  });
}

document.getElementById('saveBtn').addEventListener('click', () => {
  const inputVal = document.getElementById('secretInput').value.trim();
  if (!inputVal) return;

  if (inputVal.startsWith('otpauth-migration:')) {
    const parsedAccounts = parseMigrationURI(inputVal);
    if (parsedAccounts) {
      chrome.storage.local.get(['googleAccounts'], (res) => {
        let currentAccounts = res.googleAccounts || [];
        
        parsedAccounts.forEach(newAcc => {
          const isDuplicate = currentAccounts.some(curr => curr.secret === newAcc.secret);
          if (!isDuplicate) {
            currentAccounts.push(newAcc);
          }
        });

        chrome.storage.local.set({ googleAccounts: currentAccounts }, () => {
          document.getElementById('secretInput').value = '';
          const container = document.getElementById('accountList');
          container.innerHTML = '';
          alert(`同期完了！新たに ${parsedAccounts.length} 件を読み込みました。\n(現在合計: ${currentAccounts.length} 件)`);
          updateLoop();
        });
      });
    } else {
      alert('データの解析に失敗しました。');
    }
  } else {
    alert('otpauth-migration:// から始まるURLを入力してください。');
  }
});

updateLoop();
setInterval(updateLoop, 1000);
