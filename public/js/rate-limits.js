(function() {
    'use strict';

    let allRateLimits = [];

    function fetchRateLimits() {
        return fetch('/api/rate-limits')
            .then(function(r) { return r.ok ? r.json() : Promise.reject(r.status); })
            .then(function(data) {
                allRateLimits = (data && data.rate_limits) || [];
                return allRateLimits;
            });
    }

    function saveRateLimit(domain, config) {
        return fetch('/api/domains/' + encodeURIComponent(domain) + '/rate-limit', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCSRFToken()
            },
            body: JSON.stringify(config)
        }).then(function(r) {
            if (!r.ok) {
                return r.json().then(function(err) { throw err; });
            }
            return r.json();
        });
    }

    function getCSRFToken() {
        var match = document.cookie.match(/csrf_token=([^;]+)/);
        return match ? match[1] : '';
    }

    function escapeHtml(text) {
        if (!text) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function renderTable(rateLimits) {
        var tableBody = document.querySelector('.table tbody');
        if (!tableBody) return;

        if (!rateLimits || rateLimits.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="5" class="empty-state">No domains configured.</td></tr>';
            return;
        }

        var html = '';
        rateLimits.forEach(function(rl) {
            var domain = rl.domain || '';
            var rps = rl.requests_per_second || 10;
            var burst = rl.burst || 20;
            var enabled = rl.enabled === true || rl.enabled === 'true';

            html += '<tr data-domain="' + escapeHtml(domain) + '">';
            html += '<td><a href="/domains/' + encodeURIComponent(domain) + '" class="domain-link" style="color:inherit;text-decoration:none;">' + escapeHtml(domain) + '</a></td>';
            html += '<td><input type="number" class="rps-input" value="' + rps + '" min="1" max="1000" style="width:80px;padding:8px;border:1px solid #374151;border-radius:6px;background:#1f2937;color:#e5e7eb;"></td>';
            html += '<td><input type="number" class="burst-input" value="' + burst + '" min="1" max="10000" style="width:80px;padding:8px;border:1px solid #374151;border-radius:6px;background:#1f2937;color:#e5e7eb;"></td>';
            html += '<td>';
            html += '<label class="toggle-switch">';
            html += '<input type="checkbox" class="enabled-input" ' + (enabled ? 'checked' : '') + '>';
            html += '<span class="toggle-slider"></span>';
            html += '</label>';
            html += '</td>';
            html += '<td class="actions">';
            html += '<button class="btn primary save-btn" type="button">Save</button>';
            html += '<span class="save-status"></span>';
            html += '</td>';
            html += '</tr>';
        });

        tableBody.innerHTML = html;

        document.querySelectorAll('.save-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var row = btn.closest('tr');
                var domain = row.dataset.domain;
                var rps = parseInt(row.querySelector('.rps-input').value, 10) || 10;
                var burst = parseInt(row.querySelector('.burst-input').value, 10) || 20;
                var enabled = row.querySelector('.enabled-input').checked;

                var statusSpan = row.querySelector('.save-status');
                btn.disabled = true;
                btn.textContent = 'Saving...';
                statusSpan.textContent = '';

                saveRateLimit(domain, {
                    enabled: enabled,
                    requests_per_second: rps,
                    burst: burst
                }).then(function() {
                    btn.textContent = 'Saved!';
                    statusSpan.innerHTML = '<span style="color:#22c55e;">Saved</span>';
                    if (typeof showToast === 'function') {
                        showToast('Rate limit saved for ' + domain, 'success');
                    }
                    setTimeout(function() {
                        btn.textContent = 'Save';
                        btn.disabled = false;
                        statusSpan.textContent = '';
                    }, 2000);
                }).catch(function(err) {
                    btn.textContent = 'Save';
                    btn.disabled = false;
                    var errorMsg = err && err.error ? err.error : 'Failed to save';
                    statusSpan.innerHTML = '<span style="color:#ef4444;">' + escapeHtml(errorMsg) + '</span>';
                    if (typeof showToast === 'function') {
                        showToast(errorMsg, 'error');
                    }
                });
            });
        });
    }

    function handleSearch() {
        var searchInput = document.querySelector('.search-input');
        if (!searchInput) return;

        var query = searchInput.value.toLowerCase().trim();
        if (!query) {
            renderTable(allRateLimits);
            return;
        }

        var filtered = allRateLimits.filter(function(rl) {
            return (rl.domain || '').toLowerCase().indexOf(query) !== -1;
        });
        renderTable(filtered);
    }

    function init() {
        var refreshBtn = document.getElementById('refresh-rate-limits-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', function() {
                refreshBtn.disabled = true;
                refreshBtn.innerHTML = '<span class="icon orange"><svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M21 12a9 9 0 1 1-2.64-6.36" stroke="currentColor" stroke-width="2"/><path d="M21 3v6h-6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></span><span>Refresh</span>';
                fetchRateLimits().then(function(rateLimits) {
                    renderTable(rateLimits);
                    refreshBtn.disabled = false;
                }).catch(function() {
                    refreshBtn.disabled = false;
                    if (typeof showToast === 'function') {
                        showToast('Failed to load rate limits', 'error');
                    }
                });
            });
        }

        var searchInput = document.querySelector('.search-input');
        if (searchInput) {
            searchInput.addEventListener('input', handleSearch);
        }

        fetchRateLimits().then(function(rateLimits) {
            renderTable(rateLimits);
        }).catch(function() {
            if (typeof showToast === 'function') {
                showToast('Failed to load rate limits', 'error');
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
