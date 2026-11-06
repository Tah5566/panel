import { connect } from 'cloudflare:sockets';

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const json = (o, s = 200, h = {}) =>
  new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', ...h } });

// ---------- Auth (panel) ----------
async function sign(env, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(env.ADMIN_PASSWORD), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
async function isAdmin(request, env) {
  const m = (request.headers.get('cookie') || '').match(/s=(\d+)\.([a-f0-9]+)/);
  if (!m || Number(m[1]) < Date.now() / 1000) return false;
  return (await sign(env, m[1])) === m[2];
}

// ---------- VLESS ----------
const cache = new Map(); // uuid -> {ok, t}
async function uuidAllowed(env, uuid) {
  const c = cache.get(uuid);
  if (c && Date.now() - c.t < 30000) return c.ok;
  const row = await env.DB.prepare(
    'SELECT id FROM users WHERE uuid=? AND active=1 AND (expires_at IS NULL OR expires_at>?)'
  ).bind(uuid, Math.floor(Date.now() / 1000)).first();
  cache.set(uuid, { ok: !!row, t: Date.now() });
  return !!row;
}

function parseVless(buf) {
  const v = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const h = hex(buf.slice(1, 17));
  const uuid = `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  let i = 18 + buf[17];
  const cmd = buf[i++];
  const port = v.getUint16(i); i += 2;
  const atype = buf[i++];
  let addr;
  if (atype === 1) { addr = buf.slice(i, i + 4).join('.'); i += 4; }
  else if (atype === 2) { const l = buf[i++]; addr = new TextDecoder().decode(buf.slice(i, i + l)); i += l; }
  else if (atype === 3) {
    const p = []; for (let k = 0; k < 8; k++) p.push(v.getUint16(i + k * 2).toString(16));
    addr = p.join(':'); i += 16;
  } else throw new Error('bad address type');
  return { version: buf[0], uuid, cmd, port, addr, payload: buf.slice(i) };
}

function handleVless(request, env) {
  const [client, server] = Object.values(new WebSocketPair());
  server.accept();
  let writer = null, remote = null, started = false;

  server.addEventListener('message', async (ev) => {
    try {
      const data = new Uint8Array(ev.data);
      if (started) { await writer?.write(data); return; }
      started = true;
      const h = parseVless(data);
      if (h.cmd !== 1 || !(await uuidAllowed(env, h.uuid))) { server.close(1008, 'denied'); return; }
      remote = connect({ hostname: h.addr, port: h.port });
      writer = remote.writable.getWriter();
      await writer.write(h.payload);
      let first = true;
      remote.readable.pipeTo(new WritableStream({
        write(chunk) {
          if (first) {
            first = false;
            const out = new Uint8Array(2 + chunk.byteLength);
            out[0] = h.version; out.set(chunk, 2);
            server.send(out);
          } else server.send(chunk);
        },
        close() { try { server.close(); } catch {} },
        abort() { try { server.close(); } catch {} },
      })).catch(() => { try { server.close(); } catch {} });
    } catch {
      try { server.close(1011, 'error'); } catch {}
    }
  });
  server.addEventListener('close', () => { try { remote?.close(); } catch {} });
  return new Response(null, { status: 101, webSocket: client });
}

// ---------- Subscription ----------
async function subscription(env, token, host) {
  const u = await env.DB.prepare('SELECT * FROM users WHERE sub_token=?').bind(token).first();
  if (!u) return new Response('not found', { status: 404 });
  const now = Math.floor(Date.now() / 1000);
  const valid = u.active && (!u.expires_at || u.expires_at > now);
  const s = await env.DB.prepare("SELECT value FROM settings WHERE key='addresses'").first();
  const addrs = (s?.value || '').split(/\s+/).filter(Boolean);
  if (!addrs.includes(host)) addrs.unshift(host);
  const lines = valid
    ? addrs.map((a) =>
        `vless://${u.uuid}@${a}:443?encryption=none&security=tls&sni=${host}&fp=chrome&type=ws&host=${host}&path=%2Fws#${encodeURIComponent(u.name)}-${a}`)
    : [];
  return new Response(btoa(lines.join('\n')), {
    headers: {
      'content-type': 'text/plain',
      'subscription-userinfo': `upload=0; download=0; total=0; expire=${u.expires_at || 0}`,
    },
  });
}

// ---------- API ----------
async function api(request, env, url) {
  const p = url.pathname, m = request.method;
  if (p === '/api/login' && m === 'POST') {
    const { password } = await request.json().catch(() => ({}));
    if (!password || password !== env.ADMIN_PASSWORD) return json({ error: 'bad' }, 401);
    const exp = String(Math.floor(Date.now() / 1000) + 7 * 86400);
    return json({ ok: 1 }, 200, { 'set-cookie': `s=${exp}.${await sign(env, exp)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800` });
  }
  if (!(await isAdmin(request, env))) return json({ error: 'auth' }, 401);

  if (p === '/api/state') {
    const users = (await env.DB.prepare('SELECT id,name,uuid,sub_token,active,expires_at FROM users ORDER BY id DESC').all()).results;
    const s = await env.DB.prepare("SELECT value FROM settings WHERE key='addresses'").first();
    return json({ users, addresses: s?.value || '' });
  }
  if (p === '/api/users' && m === 'POST') {
    const { name, days } = await request.json();
    if (!name) return json({ error: 'name' }, 400);
    const exp = days ? Math.floor(Date.now() / 1000) + Number(days) * 86400 : null;
    await env.DB.prepare('INSERT INTO users(name,uuid,sub_token,active,expires_at,created_at) VALUES(?,?,?,1,?,?)')
      .bind(String(name).slice(0, 60), crypto.randomUUID(), crypto.randomUUID().replace(/-/g, ''), exp, Math.floor(Date.now() / 1000)).run();
    return json({ ok: 1 });
  }
  let mm;
  if ((mm = p.match(/^\/api\/users\/(\d+)\/toggle$/)) && m === 'POST') {
    await env.DB.prepare('UPDATE users SET active=1-active WHERE id=?').bind(mm[1]).run();
    cache.clear();
    return json({ ok: 1 });
  }
  if ((mm = p.match(/^\/api\/users\/(\d+)$/)) && m === 'DELETE') {
    await env.DB.prepare('DELETE FROM users WHERE id=?').bind(mm[1]).run();
    cache.clear();
    return json({ ok: 1 });
  }
  if (p === '/api/settings' && m === 'POST') {
    const { addresses } = await request.json();
    await env.DB.prepare("INSERT INTO settings(key,value) VALUES('addresses',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .bind(String(addresses || '').slice(0, 5000)).run();
    return json({ ok: 1 });
  }
  return json({ error: 'nf' }, 404);
}

// ---------- Panel UI ----------
const PANEL = `<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Panel</title>
<style>body{font-family:sans-serif;max-width:780px;margin:20px auto;padding:0 12px}table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #ccc;padding:6px;text-align:right}input,textarea,button{padding:6px;margin:2px}textarea{width:100%;height:90px;direction:ltr}</style>
<div id=app></div>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s).replace(/[&<>"']/g,c=>'&#'+c.charCodeAt(0)+';');
async function api(p,m,b){const r=await fetch(p,{method:m||'GET',headers:{'content-type':'application/json'},body:b?JSON.stringify(b):undefined});if(r.status===401){login();throw 0}return r.json()}
function login(){$('#app').innerHTML='<h3>ورود</h3><input id=pw type=password placeholder=password><button onclick=doLogin()>ورود</button>'}
async function doLogin(){const r=await fetch('/api/login',{method:'POST',body:JSON.stringify({password:$('#pw').value})});r.ok?load():alert('رمز اشتباه')}
async function load(){
 const d=await api('/api/state');
 let h='<h3>کاربران</h3><input id=n placeholder="نام"><input id=days type=number placeholder="تعداد روز (خالی = نامحدود)"><button onclick=add()>افزودن</button><table><tr><th>نام</th><th>انقضا</th><th>وضعیت</th><th></th></tr>';
 for(const u of d.users){
  h+='<tr><td>'+esc(u.name)+'</td><td>'+(u.expires_at?new Date(u.expires_at*1000).toLocaleDateString():'نامحدود')+'</td><td>'+(u.active?'فعال':'غیرفعال')+'</td><td>'
   +'<button data-t="'+u.sub_token+'" onclick="copySub(this.dataset.t)">لینک اشتراک</button>'
   +'<button onclick="tog('+u.id+')">فعال/غیرفعال</button><button onclick="del('+u.id+')">حذف</button></td></tr>';
 }
 h+='</table><h3>آدرس‌ها (IP یا دامنه، هر کدام در یک خط)</h3><textarea id=addr>'+esc(d.addresses)+'</textarea><button onclick=saveAddr()>ذخیره</button>';
 $('#app').innerHTML=h;
}
async function add(){await api('/api/users','POST',{name:$('#n').value,days:$('#days').value});load()}
async function tog(id){await api('/api/users/'+id+'/toggle','POST');load()}
async function del(id){if(confirm('حذف شود؟')){await api('/api/users/'+id,'DELETE');load()}}
async function saveAddr(){await api('/api/settings','POST',{addresses:$('#addr').value});alert('ذخیره شد')}
function copySub(t){const l=location.origin+'/sub/'+t;navigator.clipboard.writeText(l).then(()=>alert('کپی شد:\\n'+l))}
load().catch(()=>{});
</script></html>`;

// ---------- Router ----------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/ws' && request.headers.get('upgrade') === 'websocket') return handleVless(request, env);
    if (url.pathname.startsWith('/api/')) return api(request, env, url);
    if (url.pathname === '/panel') return new Response(PANEL, { headers: { 'content-type': 'text/html;charset=utf-8' } });
    const sm = url.pathname.match(/^\/sub\/([a-f0-9]+)$/);
    if (sm) return subscription(env, sm[1], url.hostname);
    return new Response('OK', { status: 200 });
  },
};
