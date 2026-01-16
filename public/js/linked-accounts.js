(function() {
    'use strict';

    const discordIcon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>';
    const googleIcon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>';
    const genericIcon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M8 12h8M12 8v8"/></svg>';

    function getCSRFToken() {
        const match = document.cookie.match(/csrf_token=([^;]+)/);
        return match ? match[1] : '';
    }

    function formatDate(dateString) {
        if (!dateString) return '';
        try {
            const date = new Date(dateString);
            return date.toLocaleDateString(undefined, {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });
        } catch (e) {
            return dateString;
        }
    }

    function getProviderIcon(providerType, providerName) {
        if (providerType === 'google' || providerName.toLowerCase() === 'google') {
            return googleIcon;
        }
        if (providerType === 'discord' || providerName.toLowerCase() === 'discord') {
            return discordIcon;
        }
        return genericIcon;
    }

    function getProviderClass(providerType, providerName) {
        if (providerType === 'google' || providerName.toLowerCase() === 'google') {
            return 'google';
        }
        if (providerType === 'discord' || providerName.toLowerCase() === 'discord') {
            return 'discord';
        }
        return 'oauth';
    }

    function renderLinkedProviders(linked) {
        const container = document.getElementById('linked-providers-list');
        if (!container) return;

        if (!linked || linked.length === 0) {
            container.innerHTML = '<p class="empty-state">No accounts linked yet.</p>';
            return;
        }

        let html = '';
        linked.forEach(function(p) {
            const icon = getProviderIcon(p.provider_type || '', p.provider_name);
            const iconClass = getProviderClass(p.provider_type || '', p.provider_name);
            const linkedDate = formatDate(p.linked_at);
            html += '<div class="provider-item">';
            html += '<div class="provider-icon ' + iconClass + '">' + icon + '</div>';
            html += '<div class="provider-info">';
            html += '<span class="provider-name">' + escapeHtml(p.provider_name || 'Unknown') + '</span>';
            html += '<span class="provider-email">' + escapeHtml(p.email || '') + '</span>';
            if (linkedDate) {
                html += '<span class="linked-date">Linked on ' + linkedDate + '</span>';
            }
            html += '</div>';
            html += '<div class="unlink-btn">';
            html += '<button class="btn ghost" onclick="unlinkProvider(\'' + escapeHtml(p.provider_id) + '\')">Unlink</button>';
            html += '</div>';
            html += '</div>';
        });
        container.innerHTML = html;
    }

    function renderAvailableProviders(available, linked) {
        const container = document.getElementById('available-providers-list');
        if (!container) return;

        if (!available || available.length === 0) {
            container.innerHTML = '<p class="empty-state">No providers available.</p>';
            return;
        }

        const linkedIds = (linked || []).map(function(p) { return p.provider_id; });
        const availableToLink = available.filter(function(p) {
            return linkedIds.indexOf(p.id) === -1 && p.enabled;
        });

        if (availableToLink.length === 0) {
            container.innerHTML = '<p class="empty-state">All providers are already linked.</p>';
            return;
        }

        let html = '';
        availableToLink.forEach(function(p) {
            const iconClass = getProviderClass(p.provider_type || '', p.name);
            let icon = getProviderIcon(p.provider_type || '', p.name);
            html += '<button class="btn oauth-btn ' + iconClass + '" onclick="linkProvider(\'' + escapeHtml(p.id) + '\')">';
            html += icon;
            html += '<span>Link ' + escapeHtml(p.name || p.provider_type) + '</span>';
            html += '</button>';
        });
        container.innerHTML = html;
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    window.linkProvider = function(providerId) {
        window.location.href = '/api/users/me/identity-providers/' + providerId + '/link';
    };

    window.unlinkProvider = function(providerId) {
        if (!confirm('Unlink this provider? You will no longer be able to login with it.')) {
            return;
        }
        fetch('/api/users/me/identity-providers/' + providerId, {
            method: 'DELETE',
            headers: {
                'X-CSRF-Token': getCSRFToken()
            }
        })
        .then(function(resp) { return resp.json(); })
        .then(function(data) {
            if (data.error) {
                alert('Failed to unlink: ' + data.error);
            } else {
                loadLinkedAccounts();
            }
        })
        .catch(function(err) {
            console.error('Failed to unlink provider:', err);
            alert('Failed to unlink provider');
        });
    };

    function loadLinkedAccounts() {
        Promise.all([
            fetch('/api/users/me/identity-providers').then(function(r) { return r.json(); }),
            fetch('/api/identity-providers/public').then(function(r) { return r.json(); })
        ])
        .then(function(results) {
            var linkedData = results[0];
            var availableData = results[1];
            renderLinkedProviders(linkedData.providers || []);
            renderAvailableProviders(availableData.providers || [], linkedData.providers || []);
        })
        .catch(function(err) {
            console.error('Failed to load linked accounts:', err);
            document.getElementById('linked-providers-list').innerHTML = '<p class="empty-state">Failed to load data.</p>';
            document.getElementById('available-providers-list').innerHTML = '';
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadLinkedAccounts);
    } else {
        loadLinkedAccounts();
    }
})();
