// ============================================================
// Self-Hosted Permanent Image Host + ImgBB-Style Custom API
// Storage: Backblaze B2 (Private) | DB: Cloudflare D1 | Cache: Edge
// ============================================================

const COOKIE_NAME = 'pv_admin_session';
const MIME_EXT_MAP = {
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
  'image/svg+xml': 'svg',
  'image/avif': 'avif',
};

// ---------- Utility & Auth Helpers ----------
function randomId(length = 8) {
  const chars = 'abcdefghijkmnpqrstuvwxyz23456789';
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let res = '';
  for (let i = 0; i < length; i++) res += chars[bytes[i] % chars.length];
  return res;
}

function randomSecret(prefix = 'pv_') {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return prefix + Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

async function hmacHex(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function createSessionToken(password) {
  const payload = String(Date.now() + 1000 * 60 * 60 * 24 * 7);
  const sig = await hmacHex(payload, password);
  return `${payload}.${sig}`;
}

async function verifySessionToken(token, password) {
  if (!token || !password) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [payload, sig] = parts;
  const exp = Number(payload);
  if (!Number.isFinite(exp) || Date.now() > exp) return false;
  const expected = await hmacHex(payload, password);
  if (sig.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

function getCookie(req, name = COOKIE_NAME) {
  const header = req.headers.get('cookie');
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return decodeURIComponent(rest.join('='));
  }
  return undefined;
}

function buildCookie(value, maxAge) {
  return `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${maxAge}`;
}

async function isAdminReq(req, env) {
  return verifySessionToken(getCookie(req), (env.ADMIN_PASSWORD || '').trim());
}

// ---------- Pure WebCrypto AWS S3 v4 Signer (for Backblaze B2) ----------
async function sha256Hex(data) {
  const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hmacRaw(keyData, msg) {
  const rawKey = typeof keyData === 'string' ? new TextEncoder().encode(keyData) : keyData;
  const key = await crypto.subtle.importKey('raw', rawKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg)));
}

async function b2SignedFetch(env, method, filename, bodyBytes = null, contentType = null) {
  const endpoint = (env.B2_ENDPOINT || '').replace(/^https?:\/\//i, '').replace(/\/+$/, '').trim();
  const bucket = (env.B2_BUCKET || '').trim();
  const keyId = (env.B2_KEY_ID || '').trim();
  const appKey = (env.B2_APP_KEY || '').trim();
  const region = endpoint.split('.')[1] || 'us-west-004';

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const canonicalUri = `/${bucket}/${filename}`;
  const payloadHash = bodyBytes
    ? await sha256Hex(bodyBytes)
    : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  const canonicalHeaders = `host:${endpoint}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = `${method}\n${canonicalUri}\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  const scope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${await sha256Hex(canonicalRequest)}`;

  const kDate = await hmacRaw('AWS4' + appKey, dateStamp);
  const kRegion = await hmacRaw(kDate, region);
  const kService = await hmacRaw(kRegion, 's3');
  const kSigning = await hmacRaw(kService, 'aws4_request');
  const sigBytes = await hmacRaw(kSigning, stringToSign);
  const signature = Array.from(sigBytes).map((b) => b.toString(16).padStart(2, '0')).join('');

  const headers = {
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
    Authorization: `AWS4-HMAC-SHA256 Credential=${keyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
  if (contentType) headers['Content-Type'] = contentType;

  return fetch(`https://${endpoint}${canonicalUri}`, {
    method,
    headers,
    body: bodyBytes,
  });
}

// ---------- D1 Database Helpers ----------
async function getSettings(db) {
  const { results } = await db.prepare('SELECT key, value FROM settings').all();
  const map = {};
  for (const r of results) map[r.key] = r.value;
  return {
    site_name: map.site_name || 'PixelVault',
    public_upload: map.public_upload || '0',
    max_size_mb: map.max_size_mb || '15',
    allowed_mimes: map.allowed_mimes || 'image/jpeg,image/png,image/webp,image/gif,image/svg+xml,image/avif',
  };
}

// ---------- Response Helpers ----------
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
};

function jsonRes(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

function htmlRes(html, status = 200, extraHeaders = {}) {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', ...extraHeaders },
  });
}

// ---------- HTML Views ----------
function layoutHtml({ title, siteName, isAdmin, body }) {
  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(title)} — ${escapeHtml(siteName)}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background: radial-gradient(circle at top, #13182b 0%, #090b12 60%); min-height: 100vh; }
    .glass { background: rgba(255, 255, 255, 0.03); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); }
  </style>
</head>
<body class="text-slate-100 antialiased selection:bg-indigo-500/30">
  <header class="border-b border-white/10 bg-black/30 backdrop-blur-md sticky top-0 z-40">
    <div class="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
      <a href="/" class="flex items-center gap-2.5">
        <div class="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
          </svg>
        </div>
        <span class="font-bold text-lg tracking-tight">${escapeHtml(siteName)}</span>
      </a>
      <nav class="flex items-center gap-3">
        <a href="/" class="px-3.5 py-1.5 rounded-lg text-sm font-medium text-slate-300 hover:text-white hover:bg-white/5">Upload</a>
        <a href="/admin" class="px-3.5 py-1.5 rounded-lg text-sm font-medium ${isAdmin ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30' : 'bg-white/5 text-slate-200 hover:bg-white/10'}">
          ${isAdmin ? 'Dashboard' : 'Admin Login'}
        </a>
      </nav>
    </div>
  </header>
  <main class="max-w-6xl mx-auto px-4 py-8">${body}</main>
  <footer class="border-t border-white/5 mt-16 py-6 text-center text-xs text-slate-500">
    ${escapeHtml(siteName)} — Permanent Self-Hosted Image Infrastructure
  </footer>
</body>
</html>`;
}

function renderHome(settings, isAdmin) {
  const canUpload = isAdmin || settings.public_upload === '1';
  const body = `
    <div class="max-w-3xl mx-auto">
      <div class="text-center mb-8">
        <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-xs font-medium mb-4">
          <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          100% Self-Hosted • Direct CDN Links • Zero Auto-Delete
        </div>
        <h1 class="text-3xl sm:text-5xl font-extrabold tracking-tight bg-gradient-to-r from-white via-slate-200 to-indigo-300 bg-clip-text text-transparent">
          Upload & Share Images Forever
        </h1>
        <p class="text-slate-400 mt-3 text-sm sm:text-base">
          Drag & drop, browse, or press <kbd class="px-2 py-0.5 rounded bg-white/10 text-slate-200 text-xs font-mono">Ctrl + V</kbd> to paste images instantly.
        </p>
      </div>
      ${
        !canUpload
          ? `<div class="glass rounded-2xl p-8 text-center">
              <h2 class="text-xl font-bold mb-2">Private Host Mode Enabled</h2>
              <p class="text-slate-400 text-sm mb-6">Public uploads are turned off to protect your storage. Login as Admin to upload.</p>
              <a href="/admin" class="inline-flex px-6 py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 font-semibold text-sm transition">Login as Admin</a>
            </div>`
          : `<div class="glass rounded-2xl p-6 sm:p-8 shadow-2xl">
              <div class="flex flex-wrap items-center justify-between gap-3 mb-4 pb-4 border-b border-white/10">
                <span class="text-xs text-slate-400">Max File Size: <strong class="text-slate-200">${escapeHtml(settings.max_size_mb)} MB</strong></span>
                <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
                  <input id="webpToggle" type="checkbox" class="rounded bg-white/10 border-white/20 text-indigo-500" />
                  <span>Auto-optimize to WebP (Saves storage)</span>
                </label>
              </div>
              <div id="dropzone" class="border-2 border-dashed border-white/15 hover:border-indigo-400/60 rounded-2xl p-10 text-center cursor-pointer transition bg-white/[0.01] hover:bg-indigo-500/[0.03]">
                <input id="fileInput" type="file" accept="image/*" multiple class="hidden" />
                <div class="w-16 h-16 mx-auto rounded-2xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 mb-4">
                  <svg class="w-8 h-8" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                  </svg>
                </div>
                <p class="text-base font-semibold text-slate-100">Drop images here or click to browse</p>
                <p class="text-xs text-slate-400 mt-1">PNG, JPG, WEBP, GIF, SVG, AVIF • Multiple files supported</p>
              </div>
              <div id="progressWrap" class="hidden mt-5">
                <div class="flex justify-between text-xs text-slate-300 mb-1.5">
                  <span id="progressLabel">Uploading...</span>
                  <span id="progressPct">0%</span>
                </div>
                <div class="w-full h-2 rounded-full bg-white/10 overflow-hidden">
                  <div id="progressBar" class="h-full bg-gradient-to-r from-indigo-500 to-purple-500 w-0 transition-all"></div>
                </div>
              </div>
              <div id="errorBox" class="hidden mt-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm"></div>
            </div>
            <div id="results" class="mt-8 space-y-4"></div>
            <script>
              (function() {
                var dropzone = document.getElementById('dropzone');
                var fileInput = document.getElementById('fileInput');
                var progressWrap = document.getElementById('progressWrap');
                var progressBar = document.getElementById('progressBar');
                var progressLabel = document.getElementById('progressLabel');
                var progressPct = document.getElementById('progressPct');
                var errorBox = document.getElementById('errorBox');
                var results = document.getElementById('results');
                var webpToggle = document.getElementById('webpToggle');

                dropzone.onclick = function() { fileInput.click(); };
                fileInput.onchange = function(e) {
                  if (e.target.files && e.target.files.length) handleFiles(e.target.files);
                  fileInput.value = '';
                };
                dropzone.ondragover = function(e) { e.preventDefault(); dropzone.classList.add('border-indigo-400'); };
                dropzone.ondragleave = function() { dropzone.classList.remove('border-indigo-400'); };
                dropzone.ondrop = function(e) {
                  e.preventDefault();
                  dropzone.classList.remove('border-indigo-400');
                  if (e.dataTransfer.files && e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
                };
                window.addEventListener('paste', function(e) {
                  var items = (e.clipboardData || {}).items || [];
                  var files = [];
                  for (var i = 0; i < items.length; i++) {
                    if (items[i].type && items[i].type.indexOf('image') === 0) {
                      var f = items[i].getAsFile();
                      if (f) files.push(f);
                    }
                  }
                  if (files.length) handleFiles(files);
                });

                function optimizeToWebP(file) {
                  return new Promise(function(resolve) {
                    if (!webpToggle.checked || file.type === 'image/gif' || file.type === 'image/svg+xml' || file.type === 'image/webp') return resolve(file);
                    var img = new Image();
                    var url = URL.createObjectURL(file);
                    img.onload = function() {
                      var canvas = document.createElement('canvas');
                      canvas.width = img.width; canvas.height = img.height;
                      canvas.getContext('2d').drawImage(img, 0, 0);
                      canvas.toBlob(function(blob) {
                        URL.revokeObjectURL(url);
                        if (!blob || blob.size >= file.size) return resolve(file);
                        var dot = file.name.lastIndexOf('.');
                        var base = dot > 0 ? file.name.slice(0, dot) : file.name;
                        resolve(new File([blob], base + '.webp', { type: 'image/webp' }));
                      }, 'image/webp', 0.86);
                    };
                    img.onerror = function() { URL.revokeObjectURL(url); resolve(file); };
                    img.src = url;
                  });
                }

                async function handleFiles(fileList) {
                  errorBox.classList.add('hidden');
                  var files = Array.from(fileList);
                  progressWrap.classList.remove('hidden');
                  for (var i = 0; i < files.length; i++) {
                    progressLabel.textContent = 'Uploading ' + (i + 1) + ' of ' + files.length + '...';
                    var pct = Math.round(((i + 0.3) / files.length) * 100);
                    progressBar.style.width = pct + '%';
                    progressPct.textContent = pct + '%';
                    try {
                      var processed = await optimizeToWebP(files[i]);
                      var fd = new FormData();
                      fd.append('image', processed);
                      var res = await fetch('/api/v1/upload', { method: 'POST', body: fd });
                      var json = await res.json();
                      if (!res.ok || !json.success) throw new Error(json.error || 'Upload failed');
                      renderResultCard(json.data);
                    } catch (err) {
                      errorBox.textContent = err.message || 'Upload failed';
                      errorBox.classList.remove('hidden');
                    }
                  }
                  progressBar.style.width = '100%';
                  progressPct.textContent = '100%';
                  progressLabel.textContent = 'Completed!';
                  setTimeout(function() { progressWrap.classList.add('hidden'); progressBar.style.width = '0%'; }, 1500);
                }

                function makeLinkRow(title, value) {
                  var row = document.createElement('div');
                  row.className = 'flex items-center gap-2';
                  var lbl = document.createElement('span');
                  lbl.className = 'w-24 text-xs text-slate-400 shrink-0';
                  lbl.textContent = title;
                  var inp = document.createElement('input');
                  inp.type = 'text'; inp.readOnly = true; inp.value = value;
                  inp.className = 'w-full bg-black/40 border border-white/10 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none';
                  inp.onclick = function() { inp.select(); };
                  var btn = document.createElement('button');
                  btn.type = 'button';
                  btn.className = 'px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-medium text-white shrink-0';
                  btn.textContent = 'Copy';
                  btn.onclick = function() {
                    navigator.clipboard.writeText(value);
                    btn.textContent = 'Copied!';
                    setTimeout(function() { btn.textContent = 'Copy'; }, 1400);
                  };
                  row.appendChild(lbl); row.appendChild(inp); row.appendChild(btn);
                  return row;
                }

                function renderResultCard(data) {
                  var card = document.createElement('div');
                  card.className = 'glass rounded-2xl p-4 sm:p-5 flex flex-col sm:flex-row gap-4 items-start';
                  var thumb = document.createElement('a');
                  thumb.href = data.viewer_url; thumb.target = '_blank';
                  thumb.className = 'w-full sm:w-32 h-32 rounded-xl overflow-hidden bg-black/50 border border-white/10 shrink-0 block';
                  var im = document.createElement('img');
                  im.src = data.direct_url; im.className = 'w-full h-full object-cover';
                  thumb.appendChild(im);

                  var info = document.createElement('div');
                  info.className = 'flex-1 w-full space-y-2.5';
                  var head = document.createElement('div');
                  head.className = 'flex items-center justify-between gap-2';
                  var name = document.createElement('div');
                  name.className = 'text-sm font-semibold text-white truncate';
                  name.textContent = data.original_name;
                  var badge = document.createElement('a');
                  badge.href = data.viewer_url; badge.target = '_blank';
                  badge.className = 'text-xs text-indigo-300 hover:underline shrink-0';
                  badge.textContent = 'Open Viewer →';
                  head.appendChild(name); head.appendChild(badge);

                  info.appendChild(head);
                  info.appendChild(makeLinkRow('Direct URL', data.direct_url));
                  info.appendChild(makeLinkRow('Viewer URL', data.viewer_url));
                  info.appendChild(makeLinkRow('HTML Embed', '<img src="' + data.direct_url + '" alt="' + data.original_name + '" />'));
                  info.appendChild(makeLinkRow('Markdown', '![' + data.original_name + '](' + data.direct_url + ')'));
                  card.appendChild(thumb); card.appendChild(info);
                  results.prepend(card);
                }
              })();
            </script>`
      }
    </div>`;
  return layoutHtml({ title: 'Upload Images', siteName: settings.site_name, isAdmin, body });
}

function renderViewer(img, origin, settings, isAdmin) {
  const directUrl = `${origin}/i/${img.filename}`;
  const viewerUrl = `${origin}/v/${img.id}`;
  const links = [
    ['Direct Image URL', directUrl],
    ['Viewer Page URL', viewerUrl],
    ['HTML Code', `<img src="${directUrl}" alt="${img.original_name}" />`],
    ['Markdown', `![${img.original_name}](${directUrl})`],
    ['BBCode', `[img]${directUrl}[/img]`],
  ];
  const body = `
    <div class="max-w-4xl mx-auto space-y-6">
      <div class="glass rounded-2xl p-4 sm:p-6">
        <div class="flex flex-wrap items-center justify-between gap-4 mb-4">
          <div>
            <h1 class="text-xl font-bold text-white break-all">${escapeHtml(img.original_name)}</h1>
            <div class="flex flex-wrap items-center gap-3 text-xs text-slate-400 mt-1">
              <span>${escapeHtml(img.mime_type)}</span><span>•</span>
              <span>${formatBytes(img.size_bytes)}</span><span>•</span>
              <span>${img.views} views</span><span>•</span>
              <span>${new Date(img.created_at).toLocaleDateString()}</span>
            </div>
          </div>
          <div class="flex gap-2">
            <a href="${directUrl}" download="${escapeHtml(img.original_name)}" class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold text-white">Download</a>
            <a href="${directUrl}" target="_blank" class="px-4 py-2 rounded-xl bg-white/10 hover:bg-white/15 text-xs font-semibold text-slate-200">Raw Image ↗</a>
          </div>
        </div>
        <div class="rounded-xl bg-black/50 border border-white/10 p-3 flex items-center justify-center min-h-[260px]">
          <img src="${directUrl}" alt="${escapeHtml(img.original_name)}" class="max-h-[70vh] w-auto rounded-lg object-contain" />
        </div>
      </div>
      <div class="glass rounded-2xl p-5 space-y-3">
        <h2 class="text-sm font-semibold text-slate-200 mb-2">Embed & Share Links</h2>
        ${links
          .map(
            ([label, val]) => `
          <div class="flex flex-col sm:flex-row sm:items-center gap-2">
            <span class="sm:w-36 text-xs text-slate-400 shrink-0">${label}</span>
            <div class="flex-1 flex gap-2">
              <input type="text" readonly value="${escapeHtml(val)}" onclick="this.select()" class="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none" />
              <button type="button" data-copy="${escapeHtml(val)}" onclick="cpVal(this)" class="px-3.5 py-2 rounded-lg bg-white/10 hover:bg-indigo-600 text-xs font-medium text-white shrink-0">Copy</button>
            </div>
          </div>`
          )
          .join('')}
      </div>
    </div>
    <script>
      function cpVal(btn) {
        navigator.clipboard.writeText(btn.getAttribute('data-copy'));
        btn.textContent = 'Copied!';
        setTimeout(function() { btn.textContent = 'Copy'; }, 1500);
      }
    </script>`;
  return layoutHtml({ title: img.original_name, siteName: settings.site_name, isAdmin, body });
}

function renderLogin(settings, errorMsg = '') {
  const body = `
    <div class="max-w-md mx-auto mt-12">
      <div class="glass rounded-2xl p-8 shadow-2xl">
        <h1 class="text-2xl font-bold text-center mb-2">Admin Login</h1>
        <p class="text-slate-400 text-xs text-center mb-6">Enter your admin password to manage images, settings, and API keys.</p>
        ${errorMsg ? `<div class="mb-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">${escapeHtml(errorMsg)}</div>` : ''}
        <form method="POST" action="/api/admin/login" class="space-y-4">
          <input type="password" name="password" required autofocus placeholder="Admin Password" class="w-full bg-black/40 border border-white/15 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-indigo-500" />
          <button type="submit" class="w-full py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 font-semibold text-sm text-white">Unlock Dashboard</button>
        </form>
      </div>
    </div>`;
  return layoutHtml({ title: 'Admin Login', siteName: settings.site_name, isAdmin: false, body });
}

function renderAdmin(settings, origin) {
  const body = `
    <div class="space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 class="text-2xl font-bold">Admin Dashboard</h1>
          <p class="text-xs text-slate-400">Manage images, storage quota, settings, and your own upload API keys.</p>
        </div>
        <div class="flex gap-2">
          <a href="/" class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold text-white">+ Upload</a>
          <form method="POST" action="/api/admin/logout"><button type="submit" class="px-4 py-2 rounded-xl bg-white/5 hover:bg-rose-500/20 text-xs font-semibold text-slate-300">Logout</button></form>
        </div>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div class="glass rounded-2xl p-5"><p class="text-xs text-slate-400">Total Images</p><p id="statCount" class="text-2xl font-bold mt-1">—</p></div>
        <div class="glass rounded-2xl p-5"><p class="text-xs text-slate-400">Storage Used (10 GB Free)</p><p id="statStorage" class="text-2xl font-bold mt-1">—</p></div>
        <div class="glass rounded-2xl p-5"><p class="text-xs text-slate-400">Total Viewer Hits</p><p id="statViews" class="text-2xl font-bold mt-1">—</p></div>
      </div>

      <div class="flex gap-2 border-b border-white/10 pb-3">
        <button type="button" onclick="switchTab('gallery')" id="tab-gallery" class="px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 text-white">Images Gallery</button>
        <button type="button" onclick="switchTab('api')" id="tab-api" class="px-4 py-2 rounded-xl text-xs font-semibold bg-white/5 text-slate-300">API Keys & Docs</button>
        <button type="button" onclick="switchTab('settings')" id="tab-settings" class="px-4 py-2 rounded-xl text-xs font-semibold bg-white/5 text-slate-300">Site Settings</button>
      </div>

      <section id="panel-gallery" class="space-y-4">
        <div class="flex gap-2">
          <input id="searchInput" type="text" placeholder="Search by filename or ID..." class="w-full sm:w-80 bg-black/40 border border-white/10 rounded-xl px-4 py-2 text-sm text-white" />
          <button type="button" onclick="loadImages()" class="px-4 py-2 rounded-xl bg-white/10 text-xs font-semibold">Search</button>
        </div>
        <div id="galleryGrid" class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4"></div>
      </section>

      <section id="panel-api" class="hidden space-y-6">
        <div class="glass rounded-2xl p-5 space-y-4">
          <h2 class="text-base font-bold">Generate New API Key</h2>
          <div class="flex flex-wrap gap-2">
            <input id="newKeyName" type="text" placeholder="e.g., My App / Website" class="flex-1 min-w-[220px] bg-black/40 border border-white/15 rounded-xl px-4 py-2 text-sm text-white" />
            <button type="button" onclick="createKey()" class="px-5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold text-white">Generate Key</button>
          </div>
          <div id="keysList" class="space-y-2 pt-2"></div>
        </div>
        <div class="glass rounded-2xl p-5 space-y-3">
          <h2 class="text-base font-bold">Your Upload API Usage (ImgBB Style)</h2>
          <p class="text-xs text-slate-400">Endpoint: <code class="text-indigo-300 font-mono">POST ${escapeHtml(origin)}/api/v1/upload?key=YOUR_API_KEY</code></p>
          <pre class="bg-black/60 border border-white/10 rounded-xl p-4 text-xs font-mono text-sky-300 overflow-x-auto">const fd = new FormData();
fd.append('image', fileInput.files[0]);
const res = await fetch('${escapeHtml(origin)}/api/v1/upload?key=YOUR_API_KEY', {
  method: 'POST',
  body: fd
});
const data = await res.json();
// data.data.direct_url  &  data.data.viewer_url</pre>
        </div>
      </section>

      <section id="panel-settings" class="hidden">
        <div class="glass rounded-2xl p-6 max-w-xl space-y-4">
          <h2 class="text-base font-bold">Website Settings</h2>
          <div><label class="block text-xs text-slate-400 mb-1">Site Name</label><input id="setSiteName" type="text" value="${escapeHtml(settings.site_name)}" class="w-full bg-black/40 border border-white/15 rounded-xl px-4 py-2.5 text-sm text-white" /></div>
          <div>
            <label class="block text-xs text-slate-400 mb-1">Public Upload</label>
            <select id="setPublicUpload" class="w-full bg-black/40 border border-white/15 rounded-xl px-4 py-2.5 text-sm text-white">
              <option value="0" ${settings.public_upload === '0' ? 'selected' : ''}>Private (Only Admin & API Keys)</option>
              <option value="1" ${settings.public_upload === '1' ? 'selected' : ''}>Public (Anyone can upload)</option>
            </select>
          </div>
          <div><label class="block text-xs text-slate-400 mb-1">Max File Size (MB)</label><input id="setMaxSize" type="number" min="1" max="50" value="${escapeHtml(settings.max_size_mb)}" class="w-full bg-black/40 border border-white/15 rounded-xl px-4 py-2.5 text-sm text-white" /></div>
          <div><label class="block text-xs text-slate-400 mb-1">Allowed MIME Types</label><input id="setMimes" type="text" value="${escapeHtml(settings.allowed_mimes)}" class="w-full bg-black/40 border border-white/15 rounded-xl px-4 py-2.5 text-xs font-mono text-white" /></div>
          <button type="button" onclick="saveSettings()" class="px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold text-white">Save Settings</button>
          <span id="settingsMsg" class="text-xs text-emerald-400 ml-3"></span>
        </div>
      </section>
    </div>

    <script>
      function fmtBytes(b) {
        if (!b) return '0 B';
        var u = ['B','KB','MB','GB'], i = Math.floor(Math.log(b)/Math.log(1024));
        return (b/Math.pow(1024, i)).toFixed(2) + ' ' + u[i];
      }
      function switchTab(name) {
        ['gallery','api','settings'].forEach(function(t) {
          document.getElementById('panel-' + t).classList.toggle('hidden', t !== name);
          document.getElementById('tab-' + t).className = t === name ? 'px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 text-white' : 'px-4 py-2 rounded-xl text-xs font-semibold bg-white/5 text-slate-300';
        });
        if (name === 'api') loadKeys();
      }
      async function loadImages() {
        var q = document.getElementById('searchInput').value || '';
        var res = await fetch('/api/admin/images?q=' + encodeURIComponent(q));
        var data = await res.json();
        document.getElementById('statCount').textContent = data.total;
        document.getElementById('statStorage').textContent = fmtBytes(data.totalBytes);
        document.getElementById('statViews').textContent = data.totalViews;
        var grid = document.getElementById('galleryGrid');
        grid.innerHTML = '';
        if (!data.images.length) { grid.innerHTML = '<p class="col-span-full text-sm text-slate-500 py-10 text-center">No images found.</p>'; return; }
        data.images.forEach(function(img) {
          var directUrl = window.location.origin + '/i/' + img.filename;
          var card = document.createElement('div'); card.className = 'glass rounded-xl overflow-hidden flex flex-col';
          var a = document.createElement('a'); a.href = '/v/' + img.id; a.target = '_blank'; a.className = 'h-40 bg-black/50 block overflow-hidden';
          var im = document.createElement('img'); im.src = directUrl; im.loading = 'lazy'; im.className = 'w-full h-full object-cover';
          a.appendChild(im);
          var meta = document.createElement('div'); meta.className = 'p-3 space-y-2 flex-1 flex flex-col justify-between';
          var t = document.createElement('div'); t.className = 'text-xs font-medium text-white truncate'; t.textContent = img.original_name;
          var s = document.createElement('div'); s.className = 'text-[11px] text-slate-400'; s.textContent = fmtBytes(img.size_bytes) + ' • ' + img.source;
          var act = document.createElement('div'); act.className = 'flex gap-1.5 pt-1';
          var cp = document.createElement('button'); cp.className = 'flex-1 py-1.5 rounded-lg bg-white/10 hover:bg-indigo-600 text-[11px]'; cp.textContent = 'Copy URL';
          cp.onclick = function() { navigator.clipboard.writeText(directUrl); cp.textContent = 'Copied!'; setTimeout(function(){ cp.textContent='Copy URL'; }, 1200); };
          var del = document.createElement('button'); del.className = 'px-2.5 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-600 text-rose-300 hover:text-white text-[11px]'; del.textContent = 'Delete';
          del.onclick = async function() { if (!confirm('Delete permanently?')) return; await fetch('/api/admin/images/' + img.id, { method: 'DELETE' }); loadImages(); };
          act.appendChild(cp); act.appendChild(del); meta.appendChild(t); meta.appendChild(s); meta.appendChild(act);
          card.appendChild(a); card.appendChild(meta); grid.appendChild(card);
        });
      }
      async function loadKeys() {
        var res = await fetch('/api/admin/keys'); var data = await res.json();
        var list = document.getElementById('keysList'); list.innerHTML = '';
        if (!data.keys.length) { list.innerHTML = '<p class="text-xs text-slate-500">No API keys yet.</p>'; return; }
        data.keys.forEach(function(k) {
          var row = document.createElement('div'); row.className = 'flex flex-wrap items-center justify-between gap-2 p-3 rounded-xl bg-black/40 border border-white/10';
          var left = document.createElement('div');
          var n = document.createElement('div'); n.className = 'text-xs font-semibold text-white'; n.textContent = k.name + ' (' + k.upload_count + ' uploads)';
          var v = document.createElement('div'); v.className = 'text-[11px] font-mono text-indigo-300 mt-0.5'; v.textContent = k.api_key;
          left.appendChild(n); left.appendChild(v);
          var btns = document.createElement('div'); btns.className = 'flex gap-2';
          var cp = document.createElement('button'); cp.className = 'px-3 py-1.5 rounded-lg bg-white/10 hover:bg-indigo-600 text-xs'; cp.textContent = 'Copy';
          cp.onclick = function() { navigator.clipboard.writeText(k.api_key); cp.textContent = 'Copied!'; setTimeout(function(){ cp.textContent='Copy'; }, 1200); };
          var rm = document.createElement('button'); rm.className = 'px-3 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-600 text-rose-300 text-xs'; rm.textContent = 'Revoke';
          rm.onclick = async function() { if (!confirm('Revoke key?')) return; await fetch('/api/admin/keys/' + k.id, { method: 'DELETE' }); loadKeys(); };
          btns.appendChild(cp); btns.appendChild(rm); row.appendChild(left); row.appendChild(btns); list.appendChild(row);
        });
      }
      async function createKey() {
        var name = document.getElementById('newKeyName').value.trim() || 'App Key';
        await fetch('/api/admin/keys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: name }) });
        document.getElementById('newKeyName').value = ''; loadKeys();
      }
      async function saveSettings() {
        var res = await fetch('/api/admin/settings', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            site_name: document.getElementById('setSiteName').value.trim(),
            public_upload: document.getElementById('setPublicUpload').value,
            max_size_mb: document.getElementById('setMaxSize').value,
            allowed_mimes: document.getElementById('setMimes').value.trim()
          })
        });
        var msg = document.getElementById('settingsMsg');
        msg.textContent = res.ok ? 'Saved!' : 'Error';
        setTimeout(function(){ msg.textContent = ''; }, 2000);
      }
      document.getElementById('searchInput').onkeydown = function(e) { if (e.key === 'Enter') loadImages(); };
      loadImages();
    </script>`;
  return layoutHtml({ title: 'Dashboard', siteName: settings.site_name, isAdmin: true, body });
}

// ---------- Main Router ----------
export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const origin = url.origin;

    try {
      // 1. Home
      if (path === '/' && request.method === 'GET') {
        const settings = await getSettings(env.DB);
        return htmlRes(renderHome(settings, await isAdminReq(request, env)));
      }

      // 2. Direct Image Route (/i/filename)
      if (path.startsWith('/i/') && request.method === 'GET') {
        const filename = path.slice(3);
        if (!filename) return new Response('Not found', { status: 404 });

        const cacheKey = new Request(url.toString(), { method: 'GET' });
        const cache = caches.default;
        const cached = await cache.match(cacheKey);
        if (cached) return cached;

        const record = await env.DB.prepare('SELECT * FROM images WHERE filename = ?').bind(filename).first();
        if (!record) return new Response('Image not found', { status: 404 });

        const b2Res = await b2SignedFetch(env, 'GET', filename);
        if (!b2Res.ok || !b2Res.body) return new Response('Image unavailable', { status: 404 });

        const headers = new Headers();
        headers.set('Content-Type', record.mime_type);
        headers.set('Cache-Control', 'public, max-age=31536000, immutable');
        headers.set('Access-Control-Allow-Origin', '*');
        headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
        headers.set('Content-Security-Policy', 'sandbox');

        const res = new Response(b2Res.body, { status: 200, headers });
        ctx.waitUntil(cache.put(cacheKey, res.clone()));
        return res;
      }

      // 3. Viewer Page (/v/id)
      if (path.startsWith('/v/') && request.method === 'GET') {
        const id = path.slice(3);
        const img = await env.DB.prepare('SELECT * FROM images WHERE id = ?').bind(id).first();
        if (!img) return new Response('Image not found', { status: 404 });
        ctx.waitUntil(env.DB.prepare('UPDATE images SET views = views + 1 WHERE id = ?').bind(id).run());
        const settings = await getSettings(env.DB);
        return htmlRes(renderViewer(img, origin, settings, await isAdminReq(request, env)));
      }

      // 4. Upload API (Web + External ImgBB-style API)
      if (path === '/api/v1/upload' && request.method === 'POST') {
        const settings = await getSettings(env.DB);
        const isAdmin = await isAdminReq(request, env);
        const authHeader = request.headers.get('authorization') || '';
        const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
        let providedKey = request.headers.get('x-api-key') || bearer || url.searchParams.get('key') || '';

        let authorized = isAdmin || settings.public_upload === '1';
        let source = 'web';

        const verifyKey = async (k) => {
          const row = await env.DB.prepare('SELECT id FROM api_keys WHERE api_key = ?').bind(k).first();
          if (!row) return false;
          await env.DB.prepare('UPDATE api_keys SET upload_count = upload_count + 1, last_used_at = ? WHERE id = ?')
            .bind(new Date().toISOString(), row.id)
            .run();
          return true;
        };

        if (providedKey) {
          if (!(await verifyKey(providedKey))) return jsonRes({ success: false, status: 401, error: 'Invalid API key' }, 401);
          authorized = true;
          source = 'api';
        }

        let bytes, mimeType = '', originalName = 'image.png';
        const ctype = request.headers.get('content-type') || '';

        if (ctype.includes('multipart/form-data')) {
          const form = await request.formData();
          const formKey = form.get('key');
          if (!providedKey && typeof formKey === 'string' && formKey) {
            if (!(await verifyKey(formKey))) return jsonRes({ success: false, status: 401, error: 'Invalid API key' }, 401);
            authorized = true;
            source = 'api';
          }
          if (!authorized) return jsonRes({ success: false, status: 401, error: 'Unauthorized' }, 401);

          const file = form.get('image');
          if (!file || typeof file === 'string') return jsonRes({ success: false, status: 400, error: 'Missing image file' }, 400);
          originalName = file.name || 'upload.png';
          mimeType = file.type;
          bytes = new Uint8Array(await file.arrayBuffer());
        } else if (ctype.includes('application/json')) {
          if (!authorized) return jsonRes({ success: false, status: 401, error: 'Unauthorized' }, 401);
          const body = await request.json();
          if (!body.image) return jsonRes({ success: false, status: 400, error: 'Missing image base64' }, 400);
          let b64 = body.image;
          const m = b64.match(/^data:(image\/[a-zA-Z0-9+.-]+);base64,(.+)$/);
          if (m) { mimeType = m[1]; b64 = m[2]; } else { mimeType = 'image/png'; }
          originalName = body.name || `upload.${MIME_EXT_MAP[mimeType] || 'png'}`;
          bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
        } else {
          return jsonRes({ success: false, status: 400, error: 'Use multipart/form-data or application/json' }, 400);
        }

        const allowed = settings.allowed_mimes.split(',').map((s) => s.trim().toLowerCase());
        if (!allowed.includes((mimeType || '').toLowerCase())) {
          return jsonRes({ success: false, status: 400, error: `Unsupported image type: ${mimeType}` }, 400);
        }
        const maxBytes = Number(settings.max_size_mb || '15') * 1024 * 1024;
        if (!bytes.byteLength || bytes.byteLength > maxBytes) {
          return jsonRes({ success: false, status: 400, error: `Max size is ${settings.max_size_mb} MB` }, 400);
        }

        const id = randomId(8);
        const ext = MIME_EXT_MAP[mimeType.toLowerCase()] || 'png';
        const filename = `${id}.${ext}`;
        const deleteToken = randomSecret('del_');
        const createdAt = new Date().toISOString();

        const putRes = await b2SignedFetch(env, 'PUT', filename, bytes, mimeType);
        if (!putRes.ok) {
          return jsonRes({ success: false, status: 500, error: `Storage error (${putRes.status}): ${await putRes.text()}` }, 500);
        }

        await env.DB.prepare(
          'INSERT INTO images (id, filename, original_name, mime_type, size_bytes, delete_token, source, views, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)'
        ).bind(id, filename, originalName, mimeType, bytes.byteLength, deleteToken, source, createdAt).run();

        return jsonRes({
          success: true,
          status: 200,
          data: {
            id,
            filename,
            original_name: originalName,
            mime: mimeType,
            size: bytes.byteLength,
            direct_url: `${origin}/i/${filename}`,
            viewer_url: `${origin}/v/${id}`,
            delete_url: `${origin}/api/v1/delete/${id}?token=${deleteToken}`,
            created_at: createdAt,
          },
        });
      }

      // 5. Token Delete API
      if (path.startsWith('/api/v1/delete/')) {
        const id = path.slice('/api/v1/delete/'.length);
        const token = url.searchParams.get('token');
        const img = await env.DB.prepare('SELECT * FROM images WHERE id = ?').bind(id).first();
        if (!img) return jsonRes({ success: false, error: 'Not found' }, 404);
        if (!token || token !== img.delete_token) return jsonRes({ success: false, error: 'Invalid token' }, 403);
        await b2SignedFetch(env, 'DELETE', img.filename);
        await env.DB.prepare('DELETE FROM images WHERE id = ?').bind(id).run();
        return jsonRes({ success: true });
      }

      // 6. Admin Login / Logout / Dashboard
      if (path === '/admin' && request.method === 'GET') {
        const settings = await getSettings(env.DB);
        if (!(await isAdminReq(request, env))) return htmlRes(renderLogin(settings));
        return htmlRes(renderAdmin(settings, origin));
      }

      if (path === '/api/admin/login' && request.method === 'POST') {
        const form = await request.formData();
        const pass = form.get('password');
        const settings = await getSettings(env.DB);
        if (typeof pass !== 'string' || pass !== (env.ADMIN_PASSWORD || '').trim()) {
          return htmlRes(renderLogin(settings, 'Wrong password!'), 401);
        }
        const token = await createSessionToken(pass);
        return new Response(null, {
          status: 302,
          headers: { Location: '/admin', 'Set-Cookie': buildCookie(token, 60 * 60 * 24 * 7) },
        });
      }

      if (path === '/api/admin/logout' && request.method === 'POST') {
        return new Response(null, {
          status: 302,
          headers: { Location: '/admin', 'Set-Cookie': buildCookie('', 0) },
        });
      }

      // Admin Protected APIs
      if (path.startsWith('/api/admin/')) {
        if (!(await isAdminReq(request, env))) return jsonRes({ error: 'Unauthorized' }, 401);

        if (path === '/api/admin/images' && request.method === 'GET') {
          const q = (url.searchParams.get('q') || '').trim();
          const listRes = q
            ? await env.DB.prepare('SELECT * FROM images WHERE original_name LIKE ? OR id LIKE ? ORDER BY created_at DESC LIMIT 60').bind(`%${q}%`, `%${q}%`).all()
            : await env.DB.prepare('SELECT * FROM images ORDER BY created_at DESC LIMIT 60').all();
          const stats = await env.DB.prepare('SELECT COUNT(*) as total, COALESCE(SUM(size_bytes),0) as totalBytes, COALESCE(SUM(views),0) as totalViews FROM images').first();
          return jsonRes({ images: listRes.results, total: stats.total || 0, totalBytes: stats.totalBytes || 0, totalViews: stats.totalViews || 0 });
        }

        if (path.startsWith('/api/admin/images/') && request.method === 'DELETE') {
          const id = path.slice('/api/admin/images/'.length);
          const img = await env.DB.prepare('SELECT * FROM images WHERE id = ?').bind(id).first();
          if (!img) return jsonRes({ error: 'Not found' }, 404);
          await b2SignedFetch(env, 'DELETE', img.filename);
          await env.DB.prepare('DELETE FROM images WHERE id = ?').bind(id).run();
          return jsonRes({ success: true });
        }

        if (path === '/api/admin/keys' && request.method === 'GET') {
          const res = await env.DB.prepare('SELECT * FROM api_keys ORDER BY created_at DESC').all();
          return jsonRes({ keys: res.results });
        }

        if (path === '/api/admin/keys' && request.method === 'POST') {
          const body = await request.json();
          const id = randomId(8);
          const apiKey = randomSecret('pv_key_');
          await env.DB.prepare('INSERT INTO api_keys (id, name, api_key, upload_count, created_at) VALUES (?, ?, ?, 0, ?)')
            .bind(id, (body.name || 'My App').slice(0, 50), apiKey, new Date().toISOString())
            .run();
          return jsonRes({ success: true, apiKey });
        }

        if (path.startsWith('/api/admin/keys/') && request.method === 'DELETE') {
          const id = path.slice('/api/admin/keys/'.length);
          await env.DB.prepare('DELETE FROM api_keys WHERE id = ?').bind(id).run();
          return jsonRes({ success: true });
        }

        if (path === '/api/admin/settings' && request.method === 'PUT') {
          const body = await request.json();
          const updates = [
            ['site_name', body.site_name || 'PixelVault'],
            ['public_upload', body.public_upload === '1' ? '1' : '0'],
            ['max_size_mb', String(body.max_size_mb || '15')],
            ['allowed_mimes', String(body.allowed_mimes || 'image/jpeg,image/png,image/webp,image/gif')],
          ];
          await env.DB.batch(
            updates.map(([k, v]) =>
              env.DB.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(k, v)
            )
          );
          return jsonRes({ success: true });
        }
      }

      return new Response('Not Found', { status: 404 });
    } catch (err) {
      return jsonRes({ success: false, error: err.message || 'Server error' }, 500);
    }
  },
};
