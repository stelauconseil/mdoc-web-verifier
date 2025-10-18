// Service Worker for ISO 18013-5 Web Proximity Reader PWA
// IMPORTANT: Increment version number when you update files to trigger cache refresh
const CACHE_VERSION = 3; // <-- INCREMENT THIS NUMBER WHEN UPDATING
const CACHE_NAME = `mdoc-reader-v${CACHE_VERSION}`;
const RUNTIME_CACHE = `mdoc-runtime-v${CACHE_VERSION}`;

// Files to cache on install
const PRECACHE_URLS = [
  "/",
  "/index.html",
  "/manifest.json",
  "/assets/icon-192.png",
  "/assets/icon-512.png",
];

// CDN resources - cache but don't precache
const CDN_URLS = [
  "https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js",
  "https://cdn.jsdelivr.net/npm/cbor-web@9.0.2/dist/cbor.js",
];

// Install event - cache essential files
self.addEventListener("install", (event) => {
  console.log("[Service Worker] Installing...");
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => {
        console.log("[Service Worker] Precaching app shell");
        return cache.addAll(
          PRECACHE_URLS.filter(
            (url) =>
              url !== "/assets/icon-192.png" && url !== "/assets/icon-512.png"
          )
        );
      })
      .then(() => self.skipWaiting())
      .catch((err) => console.error("[Service Worker] Precache failed:", err))
  );
});

// Activate event - clean up old caches
self.addEventListener("activate", (event) => {
  console.log("[Service Worker] Activating...");
  event.waitUntil(
    caches
      .keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter(
              (cacheName) =>
                cacheName !== CACHE_NAME && cacheName !== RUNTIME_CACHE
            )
            .map((cacheName) => {
              console.log("[Service Worker] Deleting old cache:", cacheName);
              return caches.delete(cacheName);
            })
        );
      })
      .then(() => self.clients.claim())
  );
});

// Fetch event - network first for API calls, cache first for assets
self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== "GET") {
    return;
  }

  // Skip chrome-extension and other non-http(s) requests
  if (!url.protocol.startsWith("http")) {
    return;
  }

  // Skip Web Bluetooth GATT requests (not cacheable)
  if (url.hostname.includes("bluetooth")) {
    return;
  }

  // Handle CDN resources with network-first strategy
  if (CDN_URLS.some((cdn) => request.url.startsWith(cdn))) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          // Cache successful responses
          if (response && response.status === 200) {
            const responseClone = response.clone();
            caches.open(RUNTIME_CACHE).then((cache) => {
              cache.put(request, responseClone);
            });
          }
          return response;
        })
        .catch(() => {
          // Fall back to cache if network fails
          return caches.match(request);
        })
    );
    return;
  }

  // For app shell and assets, use cache-first strategy
  event.respondWith(
    caches
      .match(request)
      .then((cached) => {
        if (cached) {
          console.log("[Service Worker] Serving from cache:", request.url);
          return cached;
        }

        // Not in cache, fetch from network
        return fetch(request).then((response) => {
          // Don't cache non-successful responses
          if (
            !response ||
            response.status !== 200 ||
            response.type === "error"
          ) {
            return response;
          }

          // Cache the new resource for future use
          const responseClone = response.clone();
          caches.open(RUNTIME_CACHE).then((cache) => {
            cache.put(request, responseClone);
          });

          return response;
        });
      })
      .catch((err) => {
        console.error("[Service Worker] Fetch failed:", err);
        // Return offline page or fallback
        return new Response("Offline - please check your connection", {
          status: 503,
          statusText: "Service Unavailable",
          headers: new Headers({
            "Content-Type": "text/plain",
          }),
        });
      })
  );
});

// Handle messages from clients
self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "SKIP_WAITING") {
    self.skipWaiting();
  }

  if (event.data && event.data.type === "CACHE_URLS") {
    event.waitUntil(
      caches.open(RUNTIME_CACHE).then((cache) => {
        return cache.addAll(event.data.urls);
      })
    );
  }
});

// Periodic background sync (if supported)
self.addEventListener("periodicsync", (event) => {
  if (event.tag === "clear-old-cache") {
    event.waitUntil(clearOldCache());
  }
});

async function clearOldCache() {
  const cacheNames = await caches.keys();
  const oldCaches = cacheNames.filter(
    (name) =>
      name.startsWith("mdoc-") && name !== CACHE_NAME && name !== RUNTIME_CACHE
  );

  await Promise.all(oldCaches.map((name) => caches.delete(name)));
  console.log("[Service Worker] Cleared old caches:", oldCaches);
}
