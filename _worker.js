// _worker.js
// Complete worker file with robustness fixes for ADD, sendMessage, httpConnect,
// and a safe /{password}/config.json route branch.
//
// Note: Some runtime-specific helpers (connect, MD5MD5, config_Json, etc.)
// are provided as minimal placeholders below — replace them with your real implementations
// when integrating into your project.

//
// Configuration placeholders — replace with your real values or inject via env.
//
const BotToken = typeof BOT_TOKEN !== 'undefined' ? BOT_TOKEN : (globalThis.BOT_TOKEN || '');
const ChatID = typeof CHAT_ID !== 'undefined' ? CHAT_ID : (globalThis.CHAT_ID || '');

//
// Utility placeholders (implement or import real implementations in your project)
//
async function MD5MD5(input) {
  // Placeholder: replace with your actual MD5MD5 implementation
  // This simple stub returns a hex-like string for demonstration.
  // DO NOT use in production — include real crypto implementation.
  if (typeof input !== 'string') input = String(input);
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = (hash << 5) - hash + input.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(16);
}

async function config_Json(password, hostHeader, sub, UA, RproxyIP, url, fakeUserID, fakeHostName, env) {
  // Minimal example response — replace with the actual config generator.
  const payload = {
    password,
    hostHeader,
    sub,
    UA,
    RproxyIP,
    query: Object.fromEntries(url.searchParams.entries()),
    fakeUserID,
    fakeHostName,
    env: env || {}
  };
  return new Response(JSON.stringify(payload, null, 2), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
}

function isValidToken(token) {
  // Example simple check stub. Replace with real validation if needed.
  return typeof token === 'string' && token.length > 0;
}

//
// Network connect placeholder
// Replace this function with the actual runtime-specific connect implementation.
// For example, on Cloudflare Workers you cannot create raw TCP sockets — use the appropriate runtime APIs.
//
async function connect({ hostname, port }) {
  // This is a placeholder that throws to indicate runtime-specific implementation is required.
  throw new Error('connect() is a placeholder. Replace with runtime-specific socket connect implementation.');
}

//
// Robust ADD implementation
//
async function ADD(内容) {
  // Make ADD robust to null/undefined and various separators.
  if (!内容 && 内容 !== 0) return [];

  let str = String(内容);
  // Replace tabs, quotes, CRLF etc with commas, collapse multiple commas.
  let 替换后的内容 = str.replace(/[\t"'\r\n]+/g, ',').replace(/,+/g, ',').trim();

  // Remove leading/trailing commas
  if (替换后的内容.startsWith(',')) 替换后的内容 = 替换后的内容.slice(1);
  if (替换后的内容.endsWith(',')) 替换后的内容 = 替换后的内容.slice(0, -1);

  if (替换后的内容 === '') return [];

  const 地址数组 = 替换后的内容.split(',').map(s => s.trim()).filter(Boolean);
  return 地址数组;
}

//
// sendMessage: Safe Telegram notification with IP lookup guarded
//
async function sendMessage(type, ip, add_data = "") {
  if (BotToken !== '' && ChatID !== '') {
    try {
      let msg = `${type}\nIP: ${ip || 'unknown'}\n${add_data || ''}`;
      // IP info fetch guarded with try/catch and response parsing guarded
      try {
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
        if (response && response.ok) {
          const ipInfo = await response.json().catch(() => null);
          if (ipInfo) {
            msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country || ''}\n城市: ${ipInfo.city || ''}\n组织: ${ipInfo.org || ''}\nASN: ${ipInfo.as || ''}\n${add_data || ''}`;
          }
        }
      } catch (e) {
        // Do not fail the whole flow if IP lookup fails
        console.warn('IP lookup failed in sendMessage:', e);
      }
      const tgUrl = `https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
      return fetch(tgUrl, {
        method: 'GET',
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml',
          'User-Agent': 'Mozilla/5.0 (compatible)'
        }
      }).catch(e => {
        console.error('Telegram sendMessage fetch failed:', e);
        return null;
      });
    } catch (e) {
      console.error('sendMessage error', e);
      return null;
    }
  } else {
    // No token/chat configured; return null to signal no-op
    return null;
  }
}

//
// Improved httpConnect implementation (runtime-agnostic structure)
// - Note: This function expects a runtime-provided `connect` function that returns an object
//   with readable and writable streams compatible with the Streams API.
// - parsedSocks5Address should be an object: { username, password, hostname, port }.
//
async function httpConnect(addressRemote, portRemote, parsedSocks5Address, log = console.log) {
  if (!parsedSocks5Address || !parsedSocks5Address.hostname) {
    throw new Error('parsedSocks5Address missing or invalid');
  }
  const { username, password, hostname, port } = parsedSocks5Address;
  const sock = await connect({ hostname, port });

  // Build CONNECT request
  let connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n`;
  connectRequest += `Host: ${addressRemote}:${portRemote}\r\n`;
  if (username && password) {
    // btoa may not be available in all runtimes; provide safe fallback
    const toBase64 = (str) => {
      if (typeof btoa === 'function') return btoa(str);
      // simple base64 fallback using Buffer if available (Node-like)
      if (typeof Buffer !== 'undefined') return Buffer.from(str, 'utf8').toString('base64');
      throw new Error('No base64 encoder available for Proxy-Authorization header');
    };
    const base64Auth = toBase64(`${username}:${password}`);
    connectRequest += `Proxy-Authorization: Basic ${base64Auth}\r\n`;
  }
  connectRequest += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n`;
  connectRequest += `Connection: Keep-Alive\r\n\r\n`;

  log(`HTTP CONNECT -> proxy ${hostname}:${port} to ${addressRemote}:${portRemote}`);

  // send request
  const writer = sock.writable.getWriter();
  try {
    await writer.write(new TextEncoder().encode(connectRequest));
  } catch (err) {
    try { writer.releaseLock(); } catch (e) {}
    throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
  }

  // read response header
  const reader = sock.readable.getReader();
  try {
    const chunks = [];
    let total = 0;
    const start = Date.now();
    while (true) {
      const { value, done } = await reader.read();
      if (done) throw new Error('HTTP代理连接中断');
      chunks.push(value);
      total += value.length;
      const acc = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) { acc.set(c, off); off += c.length; }
      const text = new TextDecoder().decode(acc);
      const idx = text.indexOf('\r\n\r\n');
      if (idx !== -1) {
        const header = text.slice(0, idx + 4);
        log(`收到HTTP代理响应: ${header.split('\r\n')[0]}`);
        if (/^HTTP\/\d+\.\d+\s+200/i.test(header)) {
          // preserve remaining bytes if any
          const remaining = acc.slice(idx + 4);
          if (remaining.length > 0) {
            try {
              const rs = new ReadableStream({
                start(ctrl) {
                  ctrl.enqueue(remaining);
                  ctrl.close();
                }
              });
              // best-effort: replace readable if runtime allows
              // @ts-ignore
              sock.readable = rs;
            } catch (e) {
              log('cannot reassign sock.readable in this runtime, remaining data kept in buffer (may be dropped)');
            }
          }
          return sock;
        } else {
          throw new Error(`HTTP代理连接失败: ${header.split('\r\n')[0]}`);
        }
      }
      if (Date.now() - start > 10000) throw new Error('HTTP代理 CONNECT 超时');
    }
  } finally {
    try { reader.releaseLock(); } catch (e) {}
    try { writer.releaseLock(); } catch (e) {}
  }
}

//
// Fetch event handler — basic dispatch showing config.json route example.
// Replace or integrate into your existing request handler logic.
//
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request).catch(err => {
    console.error('Unhandled fetch error:', err);
    return new Response('Internal Server Error', { status: 500 });
  }));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  // Example password extraction — adjust to your routing logic
  // If path like "/<password>/config.json", capture password
  const matches = path.match(/^\/([^/]+)\/config\.json$/);
  if (matches) {
    const password = matches[1];
    // Basic values used in original logic — adapt as needed
    const UA = request.headers.get('User-Agent') || '';
    const fakeUserID = 'fakeUID123'; // replace with real logic to obtain fakeUserID
    const fakeHostName = request.headers.get('Host') || 'unknown';
    const env = {}; // populate with runtime env if needed
    // Token validation using MD5MD5 as in the patched code
    const token = url.searchParams.get('token');
    try {
      if (token === await MD5MD5(fakeUserID + UA)) {
        // sub, RproxyIP are placeholders — replace or remove as appropriate
        const sub = null;
        const RproxyIP = request.headers.get('X-Real-IP') || request.headers.get('X-Forwarded-For') || '';
        return await config_Json(password, request.headers.get('Host'), sub, UA, RproxyIP, url, fakeUserID, fakeHostName, env);
      } else {
        return new Response('invalid token', { status: 403 });
      }
    } catch (e) {
      console.error('Error in config.json branch:', e);
      return new Response('error', { status: 500 });
    }
  }

  // Default response for other routes
  return new Response('OK', { status: 200 });
}

//
// Exports for testing (if running in Node-like environment)
//
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ADD,
    sendMessage,
    httpConnect,
    MD5MD5,
    config_Json,
    connect
  };
}