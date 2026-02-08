/*
  Service Worker cleanup stub.

  PWA functionality has been removed from the site, but previously-installed
  service workers may still control existing clients.

  This stub:
  - Clears all caches
  - Unregisters itself
  - Passes through fetches to the network
*/

self.addEventListener("install", (event) => {
    event.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", (event) => {
    event.waitUntil(
        (async () => {
            try {
                const keys = await caches.keys();
                await Promise.all(keys.map((k) => caches.delete(k)));
            } catch {}

            try {
                await self.registration.unregister();
            } catch {}

            try {
                const clients = await self.clients.matchAll({
                    type: "window",
                    includeUncontrolled: true,
                });
                for (const client of clients) {
                    try {
                        client.postMessage({
                            type: "SW_REMOVED",
                            message:
                                "Service Worker removed; reload for network-only mode.",
                        });
                    } catch {}
                }
            } catch {}
        })(),
    );
});

self.addEventListener("fetch", (event) => {
    // Network-only pass-through
    if (event.request && event.request.method === "GET") {
        event.respondWith(fetch(event.request));
    }
});
