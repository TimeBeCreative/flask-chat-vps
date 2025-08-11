self.addEventListener('push', function(event) {
    
    const data = event.data ? event.data.json() : {};
  
    const title = data.title || 'New Notification';
    const options = {
        body: data.body || 'You have a new message.',
        icon: data.icon || '/static/images/LogoSmall.png',
        badge: data.badge || '/static/images/LogoSmall.png'
    };

    event.waitUntil(
        self.registration.showNotification(title, options)
    );
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close();
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clientList) {
            for (const client of clientList) {
                if ('focus' in client) {
                    return client.focus();
                }
                if (clients.openWindow) {
                    return clients.openWindow('/');
                }
            }
        })
    );
});