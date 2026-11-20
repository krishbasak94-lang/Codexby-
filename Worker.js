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
                  inf
