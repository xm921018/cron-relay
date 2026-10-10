// Cloudflare Worker —— 成员自助接入。
// 主通道：手机 + 短信验证码登录网易云 → 拿 MUSIC_U。
// 备用通道：成员手动粘贴浏览器里的 MUSIC_U（短信收不到 / 登录失败时用）。
// 两通道都：解析分享链接拿 song id → 用 KV 维护主号池 → 重算分片 → 覆盖写 GitHub Secrets(NB_POOL_1..5)。
// 需要的 CF 环境变量/绑定：
//   GH_TOKEN   有 repo 权限的 GitHub PAT（写 secret 用，仅服务端，不落前端）
//   GH_OWNER   仓库 owner（如 xm921018）
//   GH_REPO    仓库名（如 cron-relay）
//   GROUP_PASS 群口令（群内共享的一个暗号，防外人乱加；不是逐人邀请码）
//   POOL       KV namespace 绑定（维护主号池，cookie 不落 GitHub 仓库文件）
// 注意：cookie 只在 KV 与 GitHub Secrets（加密）中存在，仓库文件无明文。

import nacl from './nacl.js';

const BASE = 'https://music.163.com';
const NONCE = '0CoJUm6Qyw8W8jud';
const SECRET = 'TA3YiYCfY2dDJQgg';
const VI = '0102030405060708';
const ENCSEC = '84ca47bca10bad09a6b04c5c927ef077d9b9f1e37098aa3eac6ea70eb59df0aa28b691b7e75e4f1f9831754919ea784c8f74fbfadf2898b0be17849fd656060162857830e241aba44991601f137624094c114ea8d17bce815b0cd4e5b8e2fbaba978c6d1d14dc3d1faf852bdd28818031ccdaaa13a6018e1024e2aae98844210';

const UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148';

// ---- base64 ----
const b64enc = (u8) => btoa(String.fromCharCode(...new Uint8Array(u8)));
const b64dec = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const utf8 = (s) => new TextEncoder().encode(s);

// ---- AES-CBC (WebCrypto) ----
async function aesCbc(dataU8, keyStr) {
  const key = await crypto.subtle.importKey('raw', utf8(keyStr), { name: 'AES-CBC' }, false, ['encrypt']);
  const n = 16 - dataU8.length % 16;
  const pad = new Uint8Array(dataU8.length + n);
  pad.set(dataU8); pad.fill(n, dataU8.length);
  const ct = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: utf8(VI) }, key, pad);
  return new Uint8Array(ct);
}
async function weapi(data) {
  let p = await aesCbc(utf8(JSON.stringify(data)), NONCE);
  p = await aesCbc(p, SECRET);
  return { params: b64enc(p), encSecKey: ENCSEC };
}

async function neteaseSendCode(phone) {
  const body = await weapi({ phone, ctcode: '86' });
  const r = await fetch(`${BASE}/weapi/captcha/sent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA, Referer: BASE + '/' },
    body: new URLSearchParams(body).toString(),
  });
  const j = await r.json();
  if (j.code === 200) return { ok: true };
  return { ok: false, msg: '短信发送失败 code=' + j.code };
}

async function neteaseLogin(phone, code) {
  const body = await weapi({ phone, countrycode: '86', captcha: code, rememberLogin: 'true' });
  const r = await fetch(`${BASE}/weapi/login/cellphone`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA, Referer: BASE + '/' },
    body: new URLSearchParams(body).toString(),
  });
  const j = await r.json();
  if (j.code !== 200) return { ok: false, msg: '登录失败 code=' + j.code };
  const ck = j.cookie || '';
  let musicU = '';
  const m = ck.match(/MUSIC_U=([^;]+)/);
  if (m) musicU = m[1];
  if (!musicU) {
    const h = r.headers.get('set-cookie') || '';
    const m2 = h.match(/MUSIC_U=([^;]+)/);
    if (m2) musicU = m2[1];
  }
  if (!musicU) return { ok: false, msg: '未取到登录凭证' };
  return { ok: true, musicU, uid: (j.profile || {}).userId };
}

// 校验一个 MUSIC_U 是否还活着（备用通道即时反馈）
async function validateCookie(musicU) {
  try {
    const ck = 'MUSIC_U=' + musicU;
    const r = await fetch(`${BASE}/weapi/w/nuser/account/get`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA, Referer: BASE + '/', 'Cookie': ck },
      body: new URLSearchParams(weapi({})).toString(),
    });
    const j = await r.json();
    const uid = (j.profile || {}).userId;
    if (j.code === 200 && uid) return { ok: true, uid };
    return { ok: false, msg: 'MUSIC_U 无效或已失效（请重新从浏览器复制）' };
  } catch (e) {
    return { ok: false, msg: '校验失败，请重试' };
  }
}

async function resolveSong(link) {
  let url = link.trim();
  try {
    const r = await fetch(url, { redirect: 'follow', headers: { 'User-Agent': UA } });
    url = r.url;
  } catch (e) {}
  const m = url.match(/[?&]id=(\d+)/);
  if (!m) return { ok: false, msg: '链接里没找到歌曲 id' };
  return { ok: true, song: Number(m[1]) };
}

// ---- GitHub Secrets（sealed box） ----
// GH_TOKEN / GROUP_PASS 存于 KV（加密、不落仓库、不暴露给前端），运行时从 POOL 读取。
// 这样无需 Cloudflare Secret 权限即可配置，且 GitHub PAT 也不会进公开仓库文件。
let _cfg;
async function cfg() {
  if (!_cfg) {
    _cfg = {
      ghToken: await ENV.POOL.get('GH_TOKEN'),
      groupPass: await ENV.POOL.get('GROUP_PASS'),
      owner: ENV.GH_OWNER,
      repo: ENV.GH_REPO,
    };
  }
  return _cfg;
}
const GH = async () => { const c = await cfg(); return { token: c.ghToken, owner: c.owner, repo: c.repo }; };
async function ghPublicKey() {
  const g = await GH();
  const r = await fetch(`https://api.github.com/repos/${g.owner}/${g.repo}/actions/secrets/public-key`, { headers: { Authorization: `token ${g.token}`, Accept: 'application/vnd.github+json' } });
  return r.json();
}
async function ghPutSecret(name, value) {
  const g = await GH();
  const pk = await ghPublicKey();
  const theirPub = b64dec(pk.key);
  const eph = nacl.box.keyPair();
  const nonce = new Uint8Array(24);
  const box = nacl.box(utf8(value), nonce, theirPub, eph.secretKey);
  const r = await fetch(`https://api.github.com/repos/${g.owner}/${g.repo}/actions/secrets/${name}`, {
    method: 'PUT',
    headers: { Authorization: `token ${g.token}`, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ encrypted_value: b64enc(box), key_id: pk.key_id }),
  });
  return r.status;
}

// ---- 分片写回 NB_POOL_1..5 ----
async function pushPool(entries) {
  const chunks = [];
  let cur = [];
  let size = 0;
  for (const e of entries) {
    const s = JSON.stringify(e).length + 1;
    if (size + s > 45000 && cur.length) { chunks.push(cur); cur = []; size = 0; }
    cur.push(e); size += s;
  }
  if (cur.length) chunks.push(cur);
  for (let i = 0; i < 5; i++) {
    const name = `NB_POOL_${i + 1}`;
    if (i < chunks.length) await ghPutSecret(name, b64enc(utf8(JSON.stringify(chunks[i]))));
    else await ghPutSecret(name, b64enc(utf8('[]')));
  }
}

async function addEntry(entry) {
  let master = [];
  try { master = JSON.parse(await ENV.POOL.get('master') || '[]'); } catch (e) {}
  master.push(entry);
  await ENV.POOL.put('master', JSON.stringify(master));
  await pushPool(master);
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/' || url.pathname === '/index.html') {
      return new Response(INDEX_HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
    if (url.pathname === '/api/sendcode' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const send = await neteaseSendCode(body.phone);
      if (!send.ok) return json({ message: send.msg }, 400);
      return json({ message: 'ok' });
    }
    if (url.pathname === '/api/join' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (body.pass !== c.groupPass) return json({ message: '群口令错误' }, 403);
      const login = await neteaseLogin(body.phone, body.code);
      if (!login.ok) return json({ message: login.msg }, 400);
      const song = await resolveSong(body.link);
      if (!song.ok) return json({ message: song.msg }, 400);
      await addEntry({ ck: 'MUSIC_U=' + login.musicU, song: song.song, added: new Date().toISOString().slice(0, 10), name: body.phone });
      return json({ message: '登记成功，次日生效。' });
    }
    if (url.pathname === '/api/join_manual' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ message: '参数错误' }, 400); }
      const c = await cfg();
      if (body.pass !== c.groupPass) return json({ message: '群口令错误' }, 403);
      const mu = (body.musicU || '').trim();
      if (!mu) return json({ message: '请填写 MUSIC_U' }, 400);
      const v = await validateCookie(mu);
      if (!v.ok) return json({ message: v.msg }, 400);
      const song = await resolveSong(body.link);
      if (!song.ok) return json({ message: song.msg }, 400);
      await addEntry({ ck: 'MUSIC_U=' + mu, song: song.song, added: new Date().toISOString().slice(0, 10), name: 'manual:' + v.uid });
      return json({ message: '备用登记成功，次日生效。' });
    }
    return json({ message: 'not found' }, 404);
  },
};

function json(o, status = 200) { return new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json' } }); }

const INDEX_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>成员接入</title><style>body{font-family:-apple-system,system-ui,"PingFang SC",sans-serif;background:#f5f6f8;margin:0;padding:24px 0;display:flex;flex-direction:column;align-items:center;gap:18px}.card{background:#fff;padding:28px 24px;border-radius:14px;width:330px;box-shadow:0 2px 12px rgba(0,0,0,.08)}h1{font-size:18px;margin:0 0 4px}h1.alt{color:#b06a00}p{font-size:13px;color:#666;margin:0 0 18px;line-height:1.5}label{display:block;font-size:13px;margin:12px 0 4px;color:#333}input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #ddd;border-radius:8px;font-size:14px}.row{display:flex;gap:8px}.row input{flex:1}button{margin-top:14px;width:100%;padding:11px;border:0;border-radius:8px;background:#3b6d11;color:#fff;font-size:15px;cursor:pointer}button.mini{margin-top:0;width:auto;padding:10px 12px;font-size:13px;background:#5a8f1d;white-space:nowrap}button:disabled{opacity:.55;cursor:default}.msg{margin-top:14px;font-size:13px;min-height:18px;line-height:1.5}.ok{color:#3b6d11}.err{color:#a32d2d}.tip{color:#666}details{margin-top:14px;font-size:12px;color:#666;line-height:1.6}summary{cursor:pointer;color:#3b6d11}code{background:#eee;padding:1px 4px;border-radius:4px}</style></head><body><div class="card"><h1>成员接入（方式一 · 手机登录）</h1><p>① 填手机号 → ② 点「获取验证码」收短信 → ③ 填验证码和歌曲链接 → ④ 点登记。系统自动登录并登记，<b>次日生效</b>。</p><label>手机号</label><input id="phone" inputmode="numeric" maxlength="11" placeholder="11 位手机号"><label>短信验证码</label><div class="row"><input id="code" inputmode="numeric" maxlength="6" placeholder="网易云短信验证码"><button id="send" class="mini">获取验证码</button></div><label>分享链接</label><input id="link" placeholder="粘贴 APP 内分享的单曲链接"><label>群口令</label><input id="pass" type="password" placeholder="群内获取的群口令"><button id="btn">登录并登记</button><div class="msg tip" id="msg">提示：链接在网易云 APP 里「分享→复制链接」即可。</div></div><div class="card"><h1 class="alt">成员接入（方式二 · 备用手动）</h1><p>手机短信收不到、或登录总失败时用本方式：自己从浏览器复制 <code>MUSIC_U</code> 粘贴过来，同样<b>次日生效</b>。</p><label>MUSIC_U</label><input id="mu" placeholder="粘贴浏览器里的 MUSIC_U 值"><label>分享链接</label><input id="link2" placeholder="粘贴 APP 内分享的单曲链接"><label>群口令</label><input id="pass2" type="password" placeholder="群内获取的群口令"><button id="btn2">备用登记</button><details><summary>怎么拿到 MUSIC_U？（点开看）</summary>用电脑浏览器打开 <code>https://music.163.com</code> 并登录 → 按 <code>F12</code> → 切到「Application / 应用」标签 → 左侧展开 <code>Cookies</code> → 选 <code>music.163.com</code> → 在右边找到名为 <code>MUSIC_U</code> 的那一行，复制它的「Value / 值」整串粘进来即可。</details><div class="msg tip" id="msg2"></div></div><script>const $=id=>document.getElementById(id);function setMsg(el,t,cls){const m=$(el);m.textContent=t;m.className='msg'+(cls?(' '+cls):'')}let timer=null;$('send').onclick=async()=>{const phone=$('phone').value.trim();if(!/^1\\d{10}$/.test(phone)){setMsg('msg','请先填写正确的 11 位手机号','err');return}$('send').disabled=true;setMsg('msg','正在发送验证码…');try{const r=await fetch('/api/sendcode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone})});const d=await r.json();if(r.ok){setMsg('msg','验证码已发送，请查收短信','ok');startCd()}else{setMsg('msg',d.message||'发送失败，请重试','err');$('send').disabled=false}}catch(e){setMsg('msg','网络错误，请重试','err');$('send').disabled=false}};function startCd(){let cd=60;$('send').textContent=cd+'s';timer=setInterval(()=>{cd--;if(cd<=0){clearInterval(timer);timer=null;$('send').textContent='获取验证码';$('send').disabled=false}else{$('send').textContent=cd+'s'}},1000)}$('btn').onclick=async()=>{const phone=$('phone').value.trim(),code=$('code').value.trim(),link=$('link').value.trim(),pass=$('pass').value.trim();if(!/^1\\d{10}$/.test(phone)){setMsg('msg','手机号格式不对','err');return}if(!/^\\d{4,6}$/.test(code)){setMsg('msg','请填写验证码','err');return}if(!link){setMsg('msg','请填写歌曲链接','err');return}setMsg('msg','处理中…');$('btn').disabled=true;try{const r=await fetch('/api/join',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone,code,link,pass})});const d=await r.json();if(r.ok){setMsg('msg',d.message||'登记成功，次日开始。','ok')}else{setMsg('msg',d.message||'失败','err')}}catch(e){setMsg('msg','网络错误','err')}$('btn').disabled=false};$('btn2').onclick=async()=>{const musicU=$('mu').value.trim(),link=$('link2').value.trim(),pass=$('pass2').value.trim();if(!musicU){setMsg('msg2','请填写 MUSIC_U','err');return}if(!link){setMsg('msg2','请填写歌曲链接','err');return}setMsg('msg2','处理中…');$('btn2').disabled=true;try{const r=await fetch('/api/join_manual',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({musicU,link,pass})});const d=await r.json();if(r.ok){setMsg('msg2',d.message||'备用登记成功，次日开始。','ok')}else{setMsg('msg2',d.message||'失败','err')}}catch(e){setMsg('msg2','网络错误','err')}$('btn2').disabled=false}<\/script></body></html>`;
