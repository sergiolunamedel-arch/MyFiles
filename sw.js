/* MyFiles — service worker (PWA).
   · App instalable y que abre sin conexión (la lista se ve en modo lectura con la última copia).
   · «Compartir con MyFiles» desde el celular (Web Share Target): los archivos se guardan aquí y la app los sube.
   · Nunca guarda contenido de archivos (blobs) ni nada de escritura; «Olvidar token» borra la copia de la lista. */
'use strict';
const VERSION = 'myfiles-2.2.0';
const SHELL_CACHE = 'myfiles-shell-' + VERSION;
const API_CACHE = 'myfiles-api';
const SHARE_CACHE = 'myfiles-share';
const SHELL = ['./', './index.html', './manifest.webmanifest', './icons/icon-192.png', './icons/icon-512.png',
               './icons/apple-touch-icon.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(SHELL_CACHE).then((c) => c.addAll(SHELL)).catch(() => {}).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys
    .filter((k) => k.startsWith('myfiles-shell-') && k !== SHELL_CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener('message', (e) => {
  const t = e.data && e.data.type;
  if (t === 'clear-api') e.waitUntil(caches.delete(API_CACHE));
  if (t === 'clear-share') e.waitUntil(caches.delete(SHARE_CACHE));
});

/* Solo lecturas de metadatos (repo, ramas, árboles, commits). Nunca blobs ni contenido. */
function isApiRead(url) {
  return /\/repos\/[^/]+\/[^/]+(\/git\/(trees|ref|commits)\/[^?]+|\/commits)?(\?.*)?$/.test(url.pathname + url.search)
    && !/\/git\/blobs\//.test(url.pathname);
}

async function networkFirst(req, cacheName, cacheKey) {
  const cache = await caches.open(cacheName);
  try {
    const res = await fetch(req);
    if (res && res.ok) cache.put(cacheKey || req, res.clone()).catch(() => {});
    return res;
  } catch (err) {
    const hit = await cache.match(cacheKey || req, { ignoreSearch: cacheName === SHELL_CACHE });
    if (hit) return hit;
    throw err;
  }
}

async function receiveShare(req) {
  const form = await req.formData();
  const cache = await caches.open(SHARE_CACHE);
  const files = form.getAll('files').filter((f) => f && typeof f !== 'string');
  let i = 0;
  for (const f of files) {
    await cache.put(new Request('./__shared/' + Date.now() + '_' + (i++)),
      new Response(f, { headers: { 'x-name': encodeURIComponent(f.name || 'archivo'), 'content-type': f.type || 'application/octet-stream' } }));
  }
  const text = [form.get('title'), form.get('text'), form.get('url')].filter((x) => x && typeof x === 'string').join('\n');
  if (!files.length && text) {
    await cache.put(new Request('./__shared/' + Date.now() + '_t'),
      new Response(text, { headers: { 'x-name': encodeURIComponent('compartido.txt'), 'content-type': 'text/plain' } }));
  }
  return Response.redirect('./?shared=1', 303);
}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method === 'POST' && url.origin === location.origin && url.pathname.endsWith('/share-target')) {
    e.respondWith(receiveShare(req));
    return;
  }
  if (req.method !== 'GET') return;
  if (url.origin === location.origin) {
    if (req.mode === 'navigate') { e.respondWith(networkFirst(req, SHELL_CACHE, './index.html')); return; }
    const rel = './' + url.pathname.split('/').pop();
    if (SHELL.some((s) => url.pathname.endsWith(s.slice(1)) && s !== './') || rel === './index.html') {
      e.respondWith(networkFirst(req, SHELL_CACHE));
    }
    return;
  }
  if (isApiRead(url)) e.respondWith(networkFirst(req, API_CACHE));
});
