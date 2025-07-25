self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open("chat-cache").then((cache) => {
            return cache.addAll([
                "/",
                "/static/css/style.css", 
                "/static/js/main.js",
                "/static/icons/logo-192x192.png",
                "/static/icons/logo-512x512.png",
            ]);
        })
    );
});

self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            return response || fetch(event.request);
        })
    );
});