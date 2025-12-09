/**
 * SIP Honeypot Dashboard - Frontend Application
 */

class HoneypotDashboard {
    constructor() {
        this.token = localStorage.getItem('token');
        this.user = null;
        this.currentPage = localStorage.getItem('currentPage') || 'dashboard';
        this.blocklistOffset = 0;
        this.logsOffset = 0;
        this.pageSize = 50;

        this.init();
    }

    async init() {
        this.setupEventListeners();

        if (this.token) {
            try {
                await this.loadCurrentUser();
                this.showDashboard();
            } catch {
                this.showLogin();
            }
        } else {
            this.showLogin();
        }
    }

    setupEventListeners() {
        // Login form
        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.login();
        });

        // Logout
        document.getElementById('logout-btn').addEventListener('click', () => this.logout());

        // Navigation
        document.querySelectorAll('.nav-menu a').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const page = e.target.dataset.page;
                this.navigateTo(page);
            });
        });

        // Blocklist
        document.getElementById('add-ip-btn').addEventListener('click', () => this.showAddIPModal());
        document.getElementById('bulk-add-btn').addEventListener('click', () => this.showBulkAddModal());
        document.getElementById('blocklist-prev').addEventListener('click', () => this.blocklistPrevPage());
        document.getElementById('blocklist-next').addEventListener('click', () => this.blocklistNextPage());
        document.getElementById('blocklist-search').addEventListener('input',
            this.debounce(() => this.loadBlocklist(), 300));
        document.getElementById('blocklist-source-filter').addEventListener('change', () => {
            this.blocklistOffset = 0;
            this.loadBlocklist();
        });

        // Whitelist
        document.getElementById('add-whitelist-btn').addEventListener('click', () => this.showAddWhitelistModal());

        // Logs
        document.getElementById('logs-refresh').addEventListener('click', () => this.loadLogs());
        document.getElementById('logs-ip-filter').addEventListener('input',
            this.debounce(() => this.loadLogs(), 300));
        document.getElementById('logs-method-filter').addEventListener('change', () => this.loadLogs());
        document.getElementById('logs-prev').addEventListener('click', () => this.logsPrevPage());
        document.getElementById('logs-next').addEventListener('click', () => this.logsNextPage());

        // Export
        document.getElementById('preview-export').addEventListener('click', () => this.previewExport());
        document.getElementById('download-export').addEventListener('click', () => this.downloadExport());
        document.getElementById('copy-export').addEventListener('click', () => this.copyExport());

        // Analytics
        document.getElementById('refresh-geo-btn')?.addEventListener('click', () => this.refreshGeoData());

        // Abuse Reports
        document.getElementById('abuse-check-btn')?.addEventListener('click', () => this.checkAbuseContact());
        document.getElementById('abuse-ip-input')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.checkAbuseContact();
        });
        document.getElementById('block-email-btn')?.addEventListener('click', () => this.addEmailBlock());
        document.getElementById('block-email-input')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.addEmailBlock();
        });

        // Settings
        document.getElementById('save-settings-btn')?.addEventListener('click', () => this.saveSettings());
        document.getElementById('test-smtp-btn')?.addEventListener('click', () => this.testSmtp());

        // Users
        document.getElementById('add-user-btn').addEventListener('click', () => this.showAddUserModal());

        // Modal close
        document.getElementById('modal-overlay').addEventListener('click', (e) => {
            if (e.target.id === 'modal-overlay') this.closeModal();
        });
    }

    // API Helpers
    async api(endpoint, options = {}) {
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        const response = await fetch(`/api${endpoint}`, {
            ...options,
            headers
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'API request failed');
        }

        return data;
    }

    // Auth
    async login() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const errorEl = document.getElementById('login-error');

        try {
            const data = await this.api('/auth/login', {
                method: 'POST',
                body: JSON.stringify({ username, password })
            });

            this.token = data.token;
            this.user = data.user;
            localStorage.setItem('token', this.token);
            this.showDashboard();
        } catch (error) {
            errorEl.textContent = error.message;
        }
    }

    async logout() {
        try {
            await this.api('/auth/logout', { method: 'POST' });
        } catch {}

        this.token = null;
        this.user = null;
        localStorage.removeItem('token');
        this.showLogin();
    }

    async loadCurrentUser() {
        const data = await this.api('/auth/me');
        this.user = data;
    }

    // Navigation
    showLogin() {
        document.getElementById('login-page').classList.remove('hidden');
        document.getElementById('dashboard-page').classList.add('hidden');
    }

    showDashboard() {
        document.getElementById('login-page').classList.add('hidden');
        document.getElementById('dashboard-page').classList.remove('hidden');
        document.getElementById('current-user').textContent = this.user?.username || '';

        // Show/hide admin elements
        if (this.user?.role === 'admin') {
            document.getElementById('users-nav').classList.remove('hidden');
            document.getElementById('settings-nav').classList.remove('hidden');
        } else {
            document.getElementById('users-nav').classList.add('hidden');
            document.getElementById('settings-nav').classList.add('hidden');
        }

        // Navigate to saved page or default to dashboard
        const savedPage = localStorage.getItem('currentPage') || 'dashboard';
        this.navigateTo(savedPage);
    }

    navigateTo(page) {
        this.currentPage = page;
        localStorage.setItem('currentPage', page);

        // Update nav
        document.querySelectorAll('.nav-menu a').forEach(link => {
            link.classList.toggle('active', link.dataset.page === page);
        });

        // Hide all views
        document.querySelectorAll('.view').forEach(view => {
            view.classList.add('hidden');
        });

        // Show selected view
        document.getElementById(`${page}-view`).classList.remove('hidden');

        // Load data
        switch (page) {
            case 'dashboard':
                this.loadDashboard();
                break;
            case 'blocklist':
                this.loadBlocklist();
                break;
            case 'whitelist':
                this.loadWhitelist();
                break;
            case 'logs':
                this.loadLogs();
                break;
            case 'abuse':
                this.loadAbuseHistory();
                this.loadEmailBlocklist();
                break;
            case 'settings':
                this.loadSettings();
                break;
            case 'users':
                this.loadUsers();
                break;
        }
    }

    // Dashboard
    async loadDashboard() {
        try {
            const stats = await this.api('/stats');

            document.getElementById('stat-total-logs').textContent =
                this.formatNumber(stats.total_logs);
            document.getElementById('stat-logs-24h').textContent =
                this.formatNumber(stats.logs_24h);
            document.getElementById('stat-unique-ips').textContent =
                this.formatNumber(stats.unique_ips);
            document.getElementById('stat-blocked-ips').textContent =
                this.formatNumber(stats.blocked_ips);
            document.getElementById('stat-time-wasted').textContent =
                this.formatTimeWasted(stats.time_wasted || 0);

            // Top attackers
            const attackersTable = document.querySelector('#top-attackers-table tbody');
            attackersTable.innerHTML = stats.top_attackers.map(row => `
                <tr>
                    <td><span class="ip-address">${this.escapeHtml(row.source_ip)}</span></td>
                    <td>${row.count}</td>
                    <td>
                        <button class="btn btn-small btn-danger action-btn"
                                onclick="app.blockIP('${row.source_ip}')">Block</button>
                    </td>
                </tr>
            `).join('');

            // Methods
            const methodsTable = document.querySelector('#methods-table tbody');
            methodsTable.innerHTML = stats.method_breakdown.map(row => `
                <tr>
                    <td>${this.escapeHtml(row.method)}</td>
                    <td>${row.count}</td>
                </tr>
            `).join('');

            // Load analytics
            await this.loadAnalytics();

            // Load active sessions
            await this.loadActiveSessions();

            // Start auto-refresh for active sessions (every 5 seconds)
            this.startSessionRefresh();
        } catch (error) {
            this.showToast('Failed to load dashboard', 'error');
        }
    }

    startSessionRefresh() {
        // Clear any existing interval
        if (this.sessionRefreshInterval) {
            clearInterval(this.sessionRefreshInterval);
        }
        // Refresh active sessions every 5 seconds when on dashboard
        this.sessionRefreshInterval = setInterval(() => {
            if (document.getElementById('dashboard-view') &&
                !document.getElementById('dashboard-view').classList.contains('hidden')) {
                this.loadActiveSessions();
            }
        }, 5000);
    }

    async loadActiveSessions() {
        try {
            const data = await this.api('/active-sessions');
            const card = document.getElementById('active-sessions-card');
            const table = document.querySelector('#active-sessions-table tbody');
            const countBadge = document.getElementById('active-session-count');
            const pagination = document.getElementById('active-sessions-pagination');
            const pageInfo = document.getElementById('sessions-page-info');

            // Initialize pagination state if not exists
            if (this.sessionsPage === undefined) {
                this.sessionsPage = 0;
                this.sessionsPerPage = 30;
                // Setup pagination event handlers
                document.getElementById('sessions-prev').addEventListener('click', () => {
                    if (this.sessionsPage > 0) {
                        this.sessionsPage--;
                        this.loadActiveSessions();
                    }
                });
                document.getElementById('sessions-next').addEventListener('click', () => {
                    this.sessionsPage++;
                    this.loadActiveSessions();
                });
            }

            countBadge.textContent = data.count;

            if (data.sessions && data.sessions.length > 0) {
                card.classList.add('has-sessions');

                // Paginate sessions
                const totalPages = Math.ceil(data.sessions.length / this.sessionsPerPage);
                // Reset to last valid page if current page is out of bounds
                if (this.sessionsPage >= totalPages) {
                    this.sessionsPage = Math.max(0, totalPages - 1);
                }
                const start = this.sessionsPage * this.sessionsPerPage;
                const end = start + this.sessionsPerPage;
                const pageSessions = data.sessions.slice(start, end);

                table.innerHTML = pageSessions.map(session => {
                    // Calculate progress
                    let progress, progressText;
                    if (session.phase === 'ringing') {
                        progress = Math.round((session.ring_count / session.total_rings) * 100);
                        progressText = `${session.ring_count}/${session.total_rings} rings`;
                    } else {
                        progress = Math.round((session.call_elapsed / session.call_duration_planned) * 100);
                        const elapsed = Math.floor(session.call_elapsed / 60);
                        const planned = Math.floor(session.call_duration_planned / 60);
                        progressText = `${elapsed}/${planned} min`;
                    }

                    // Use server-calculated duration to avoid clock mismatch
                    const durationStr = this.formatDuration(session.duration || 0);

                    return `
                        <tr>
                            <td><span class="ip-address">${this.escapeHtml(session.ip)}</span>:${session.port}</td>
                            <td>${this.escapeHtml(session.target)}</td>
                            <td><span class="badge badge-${session.phase}">${session.phase}</span></td>
                            <td>
                                <div class="progress-bar">
                                    <div class="progress-bar-fill" style="width: ${progress}%">${progressText}</div>
                                </div>
                            </td>
                            <td>${durationStr}</td>
                        </tr>
                    `;
                }).join('');

                // Update pagination info
                pageInfo.textContent = `Page ${this.sessionsPage + 1} of ${totalPages} (${data.count} total)`;
                document.getElementById('sessions-prev').disabled = this.sessionsPage === 0;
                document.getElementById('sessions-next').disabled = this.sessionsPage >= totalPages - 1;
                pagination.style.display = totalPages > 1 ? 'flex' : 'none';
            } else {
                card.classList.remove('has-sessions');
                table.innerHTML = '';
                pagination.style.display = 'none';
            }
        } catch (error) {
            console.error('Failed to load active sessions:', error);
        }
    }

    formatDuration(seconds) {
        if (seconds < 60) return `${seconds}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${mins}m`;
    }

    formatTimeWasted(seconds) {
        if (seconds < 60) return `${seconds} sec`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)} min`;
        if (seconds < 86400) {
            const hours = Math.floor(seconds / 3600);
            const mins = Math.floor((seconds % 3600) / 60);
            return `${hours}h ${mins}m`;
        }
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        return `${days}d ${hours}h`;
    }

    async loadAnalytics() {
        try {
            // Load country stats
            const countryData = await this.api('/analytics/countries');
            const countryTable = document.querySelector('#country-table tbody');
            if (countryData.countries && countryData.countries.length > 0) {
                countryTable.innerHTML = countryData.countries.map(row => `
                    <tr>
                        <td><span class="country-flag">${this.getCountryFlag(row.country_code)}</span> ${this.escapeHtml(row.country || row.country_code || 'Unknown')}</td>
                        <td>${row.unique_ips}</td>
                        <td>${row.total_attacks}</td>
                    </tr>
                `).join('');
            } else {
                countryTable.innerHTML = '<tr><td colspan="3" class="no-data">No geo data yet. Click "Refresh Geo Data" to populate.</td></tr>';
            }

            // Load ASN stats
            const asnData = await this.api('/analytics/asn');
            const asnTable = document.querySelector('#asn-table tbody');
            if (asnData.asns && asnData.asns.length > 0) {
                asnTable.innerHTML = asnData.asns.map(row => `
                    <tr>
                        <td><span class="asn-badge">${this.escapeHtml(row.asn || 'N/A')}</span></td>
                        <td title="${this.escapeHtml(row.isp || '')}">${this.truncate(row.asn_name || row.isp || 'Unknown', 30)}</td>
                        <td>${row.unique_ips}</td>
                        <td>${row.total_attacks}</td>
                    </tr>
                `).join('');
            } else {
                asnTable.innerHTML = '<tr><td colspan="4" class="no-data">No ASN data yet. Click "Refresh Geo Data" to populate.</td></tr>';
            }
        } catch (error) {
            console.error('Failed to load analytics:', error);
        }
    }

    async refreshGeoData() {
        const statusEl = document.getElementById('geo-status');
        const btn = document.getElementById('refresh-geo-btn');

        btn.disabled = true;
        statusEl.textContent = 'Refreshing...';

        try {
            const result = await this.api('/analytics/refresh-geo', { method: 'POST' });
            statusEl.textContent = result.message;
            this.showToast(result.message, 'success');

            // Reload analytics
            await this.loadAnalytics();
        } catch (error) {
            statusEl.textContent = 'Refresh failed';
            this.showToast('Failed to refresh geo data', 'error');
        } finally {
            btn.disabled = false;
        }
    }

    getCountryFlag(countryCode) {
        if (!countryCode) return '';
        // Convert country code to flag emoji
        const codePoints = countryCode
            .toUpperCase()
            .split('')
            .map(char => 127397 + char.charCodeAt(0));
        return String.fromCodePoint(...codePoints);
    }

    // Blocklist
    async loadBlocklist() {
        try {
            // Load external blocklists for admins
            if (this.user?.role === 'admin') {
                this.loadExternalBlocklists();
                document.getElementById('external-blocklists-card')?.classList.remove('hidden');
            } else {
                document.getElementById('external-blocklists-card')?.classList.add('hidden');
            }

            const search = document.getElementById('blocklist-search').value;
            const sourceFilter = document.getElementById('blocklist-source-filter').value;
            let url = `/blocklist?limit=${this.pageSize}&offset=${this.blocklistOffset}`;
            if (sourceFilter) url += `&source=${sourceFilter}`;
            const data = await this.api(url);

            const tbody = document.querySelector('#blocklist-table tbody');
            tbody.innerHTML = data.ips.map(ip => {
                const isExternal = ip.added_by === 'apiban';
                const isInApiban = ip.in_apiban === true;
                let sourceLabel;
                if (!isExternal && isInApiban) {
                    sourceLabel = '<span class="badge badge-both">Both</span>';
                } else if (isExternal) {
                    sourceLabel = '<span class="badge badge-external">External</span>';
                } else {
                    sourceLabel = '<span class="badge badge-internal">Internal</span>';
                }
                return `
                <tr>
                    <td><span class="ip-address">${this.escapeHtml(ip.ip_address)}</span></td>
                    <td>${sourceLabel}</td>
                    <td>${this.escapeHtml(ip.reason || '-')}</td>
                    <td>${this.formatDate(ip.first_seen)}</td>
                    <td>${this.formatDate(ip.last_seen)}</td>
                    <td>${ip.hit_count}</td>
                    <td>
                        <button class="btn btn-small action-btn"
                                onclick="app.showIPDetails('${ip.ip_address}')">Details</button>
                        <button class="btn btn-small btn-danger action-btn"
                                onclick="app.unblockIP('${ip.ip_address}')">Remove</button>
                    </td>
                </tr>
            `}).join('');

            const start = this.blocklistOffset + 1;
            const end = Math.min(this.blocklistOffset + this.pageSize, data.total);
            document.getElementById('blocklist-page-info').textContent =
                `${start}-${end} of ${data.total}`;
        } catch (error) {
            this.showToast('Failed to load blocklist', 'error');
        }
    }

    blocklistPrevPage() {
        if (this.blocklistOffset >= this.pageSize) {
            this.blocklistOffset -= this.pageSize;
            this.loadBlocklist();
        }
    }

    blocklistNextPage() {
        this.blocklistOffset += this.pageSize;
        this.loadBlocklist();
    }

    async blockIP(ip, reason = 'Manually blocked from dashboard') {
        try {
            await this.api('/blocklist', {
                method: 'POST',
                body: JSON.stringify({ ip, reason })
            });
            this.showToast(`IP ${ip} blocked`, 'success');
            this.loadDashboard();
            this.loadBlocklist();
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    async unblockIP(ip) {
        if (!confirm(`Remove ${ip} from blocklist?`)) return;

        try {
            await this.api(`/blocklist/${encodeURIComponent(ip)}`, { method: 'DELETE' });
            this.showToast(`IP ${ip} removed from blocklist`, 'success');
            this.loadBlocklist();
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    showAddIPModal() {
        this.showModal(`
            <h2>Add IP to Blocklist</h2>
            <form id="add-ip-form">
                <div class="form-group">
                    <label>IP Address</label>
                    <input type="text" id="modal-ip" required placeholder="e.g., 192.168.1.1">
                </div>
                <div class="form-group">
                    <label>Reason</label>
                    <input type="text" id="modal-reason" placeholder="Optional reason">
                </div>
                <div class="form-group">
                    <label>Notes</label>
                    <textarea id="modal-notes" placeholder="Optional notes"></textarea>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn" onclick="app.closeModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add IP</button>
                </div>
            </form>
        `);

        document.getElementById('add-ip-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const ip = document.getElementById('modal-ip').value;
            const reason = document.getElementById('modal-reason').value;
            const notes = document.getElementById('modal-notes').value;

            try {
                await this.api('/blocklist', {
                    method: 'POST',
                    body: JSON.stringify({ ip, reason, notes })
                });
                this.closeModal();
                this.showToast('IP added to blocklist', 'success');
                this.loadBlocklist();
            } catch (error) {
                this.showToast(error.message, 'error');
            }
        });
    }

    showBulkAddModal() {
        this.showModal(`
            <h2>Bulk Import IPs</h2>
            <form id="bulk-add-form">
                <div class="form-group">
                    <label>IP Addresses (one per line)</label>
                    <textarea id="modal-ips" rows="10" placeholder="192.168.1.1&#10;192.168.1.2&#10;10.0.0.1"></textarea>
                </div>
                <div class="form-group">
                    <label>Reason</label>
                    <input type="text" id="modal-bulk-reason" placeholder="Bulk import reason">
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn" onclick="app.closeModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Import</button>
                </div>
            </form>
        `);

        document.getElementById('bulk-add-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const ipsText = document.getElementById('modal-ips').value;
            const reason = document.getElementById('modal-bulk-reason').value || 'Bulk import';

            const ips = ipsText.split('\n')
                .map(ip => ip.trim())
                .filter(ip => ip && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip));

            if (ips.length === 0) {
                this.showToast('No valid IPs found', 'error');
                return;
            }

            try {
                const result = await this.api('/blocklist/bulk', {
                    method: 'POST',
                    body: JSON.stringify({ ips, reason })
                });
                this.closeModal();
                this.showToast(`Added ${result.added} IPs, ${result.failed} failed`, 'success');
                this.loadBlocklist();
            } catch (error) {
                this.showToast(error.message, 'error');
            }
        });
    }

    // External Blocklists (APIBAN, etc)
    async loadExternalBlocklists() {
        try {
            const data = await this.api('/public-blocklists');
            const container = document.getElementById('external-blocklists-container');

            if (!data.lists || data.lists.length === 0) {
                container.innerHTML = '<p>No external blocklists available.</p>';
                return;
            }

            container.innerHTML = data.lists.map(list => `
                <div class="external-list-item" data-list-id="${list.list_id}">
                    <div class="external-list-header">
                        <div class="external-list-info">
                            <strong>${this.escapeHtml(list.name)}</strong>
                            <span class="help-text">${this.escapeHtml(list.description)}</span>
                            <a href="${this.escapeHtml(list.url)}" target="_blank" class="external-link">${this.escapeHtml(list.url)}</a>
                        </div>
                        <div class="external-list-status">
                            ${list.enabled
                                ? '<span class="badge badge-success">Enabled</span>'
                                : '<span class="badge badge-default">Disabled</span>'}
                            ${list.ips_imported > 0
                                ? `<span class="stat-small">${list.ips_imported} IPs imported</span>`
                                : ''}
                        </div>
                    </div>
                    <div class="external-list-config">
                        <div class="form-row">
                            <div class="form-group">
                                <label>API Key ${list.requires_key ? '(required)' : '(optional)'}</label>
                                <input type="password" class="external-list-apikey"
                                       placeholder="${list.has_key ? '••••••••' : 'Enter API key'}"
                                       data-list-id="${list.list_id}">
                            </div>
                            <div class="form-group checkbox-group">
                                <label>
                                    <input type="checkbox" class="external-list-enabled"
                                           ${list.enabled ? 'checked' : ''}
                                           data-list-id="${list.list_id}">
                                    Enable auto-sync
                                </label>
                            </div>
                        </div>
                        <div class="button-group">
                            <button class="btn btn-small" onclick="app.saveExternalBlocklist('${list.list_id}')">Save</button>
                            <button class="btn btn-small btn-primary" onclick="app.syncExternalBlocklist('${list.list_id}')"
                                    ${!list.enabled ? 'disabled' : ''}>Sync Now</button>
                        </div>
                        ${list.last_sync
                            ? `<span class="sync-info">Last sync: ${this.formatDate(list.last_sync)}</span>`
                            : ''}
                        ${list.last_error
                            ? `<span class="sync-error">Error: ${this.escapeHtml(list.last_error)}</span>`
                            : ''}
                    </div>
                </div>
            `).join('');
        } catch (error) {
            console.error('Failed to load external blocklists:', error);
        }
    }

    async saveExternalBlocklist(listId) {
        const container = document.querySelector(`[data-list-id="${listId}"]`);
        const apiKey = container.querySelector('.external-list-apikey').value;
        const enabled = container.querySelector('.external-list-enabled').checked;

        try {
            await this.api(`/public-blocklists/${listId}`, {
                method: 'PUT',
                body: JSON.stringify({ api_key: apiKey, enabled })
            });
            this.showToast('Configuration saved', 'success');
            this.loadExternalBlocklists();
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    async syncExternalBlocklist(listId) {
        try {
            this.showToast('Syncing...', 'info');
            const result = await this.api(`/public-blocklists/${listId}/sync`, {
                method: 'POST'
            });

            if (result.success) {
                this.showToast(`Synced ${result.imported || 0} new IPs`, 'success');
                this.loadExternalBlocklists();
                this.loadBlocklist();
            } else {
                this.showToast(result.error || 'Sync failed', 'error');
            }
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    // Whitelist
    async loadWhitelist() {
        try {
            const data = await this.api('/whitelist');

            const tbody = document.querySelector('#whitelist-table tbody');
            tbody.innerHTML = data.whitelist.map(entry => `
                <tr>
                    <td><span class="ip-address">${this.escapeHtml(entry.ip_address)}</span></td>
                    <td>${this.escapeHtml(entry.description || '-')}</td>
                    <td>${this.escapeHtml(entry.added_by || '-')}</td>
                    <td>${this.formatDate(entry.created_at)}</td>
                    <td>
                        <button class="btn btn-small btn-danger action-btn"
                                onclick="app.removeWhitelist('${entry.ip_address}')">Remove</button>
                    </td>
                </tr>
            `).join('') || '<tr><td colspan="5">No whitelisted IPs</td></tr>';
        } catch (error) {
            this.showToast('Failed to load whitelist', 'error');
        }
    }

    showAddWhitelistModal() {
        this.showModal(`
            <h2>Add IP to Whitelist</h2>
            <form id="add-whitelist-form">
                <div class="form-group">
                    <label>IP Address</label>
                    <input type="text" id="modal-whitelist-ip" required placeholder="e.g., 192.168.1.1">
                </div>
                <div class="form-group">
                    <label>Description</label>
                    <input type="text" id="modal-whitelist-desc" placeholder="e.g., Office NAT IP">
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn" onclick="app.closeModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add to Whitelist</button>
                </div>
            </form>
        `);

        document.getElementById('add-whitelist-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const ip = document.getElementById('modal-whitelist-ip').value;
            const description = document.getElementById('modal-whitelist-desc').value;

            try {
                await this.api('/whitelist', {
                    method: 'POST',
                    body: JSON.stringify({ ip, description })
                });
                this.closeModal();
                this.showToast('IP added to whitelist', 'success');
                this.loadWhitelist();
            } catch (error) {
                this.showToast(error.message, 'error');
            }
        });
    }

    async removeWhitelist(ip) {
        if (!confirm(`Remove ${ip} from whitelist?`)) return;

        try {
            await this.api(`/whitelist/${encodeURIComponent(ip)}`, { method: 'DELETE' });
            this.showToast(`IP ${ip} removed from whitelist`, 'success');
            this.loadWhitelist();
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    // Logs
    async loadLogs() {
        try {
            const ipFilter = document.getElementById('logs-ip-filter').value;
            const methodFilter = document.getElementById('logs-method-filter').value;

            let url = `/logs?limit=${this.pageSize}&offset=${this.logsOffset}`;
            if (ipFilter) url += `&ip=${encodeURIComponent(ipFilter)}`;
            if (methodFilter) url += `&method=${encodeURIComponent(methodFilter)}`;

            const data = await this.api(url);

            const tbody = document.querySelector('#logs-table tbody');
            tbody.innerHTML = data.logs.map(log => `
                <tr>
                    <td>${this.formatDate(log.timestamp)}</td>
                    <td><span class="ip-address">${this.escapeHtml(log.source_ip)}</span></td>
                    <td>${log.source_port || '-'}</td>
                    <td><span class="badge badge-${this.getProtocolClass(log.honeypot_type)}">${this.escapeHtml(log.honeypot_type || 'unknown').toUpperCase()}</span></td>
                    <td><span class="badge ${log.method === 'CREDENTIAL_CAPTURE' ? 'badge-warning' : ''}">${this.escapeHtml(log.method)}</span></td>
                    <td>${this.truncate(log.uri, 40)}</td>
                    <td>${this.truncate(log.user_agent, 30)}</td>
                    <td>
                        <button class="btn btn-small action-btn"
                                onclick='app.showLogDetails(${JSON.stringify(log)})'>View</button>
                        <button class="btn btn-small btn-danger action-btn"
                                onclick="app.blockIP('${log.source_ip}')">Block</button>
                    </td>
                </tr>
            `).join('') || '<tr><td colspan="8">No logs found</td></tr>';

            document.getElementById('logs-page-info').textContent =
                `Showing ${data.logs.length} records`;
        } catch (error) {
            this.showToast('Failed to load logs', 'error');
        }
    }

    logsPrevPage() {
        if (this.logsOffset >= this.pageSize) {
            this.logsOffset -= this.pageSize;
            this.loadLogs();
        }
    }

    logsNextPage() {
        this.logsOffset += this.pageSize;
        this.loadLogs();
    }

    showLogDetails(log) {
        const details = JSON.stringify(log, null, 2);
        this.showModal(`
            <h2>Log Details</h2>
            <div class="log-details">${this.escapeHtml(details)}</div>
            <div class="modal-footer">
                <button class="btn" onclick="app.closeModal()">Close</button>
                <button class="btn btn-danger" onclick="app.blockIP('${log.source_ip}'); app.closeModal();">Block IP</button>
            </div>
        `);
    }

    async showIPDetails(ip) {
        this.showModal(`
            <h2>IP Details: ${this.escapeHtml(ip)}</h2>
            <div class="ip-details-loading">Loading ARIN/RDAP data...</div>
        `);

        try {
            const data = await this.api(`/ip/${encodeURIComponent(ip)}/lookup`);

            let html = `<h2>IP Details: ${this.escapeHtml(ip)}</h2>`;

            if (data.error) {
                html += `<div class="ip-details-error">Lookup failed: ${this.escapeHtml(data.error)}</div>`;
            } else {
                html += `
                    <table class="ip-details-table">
                        <tr><td><strong>IP Address</strong></td><td>${this.escapeHtml(data.ip)}</td></tr>
                        <tr><td><strong>Network</strong></td><td>${this.escapeHtml(data.network || 'N/A')}</td></tr>
                        <tr><td><strong>CIDR</strong></td><td>${this.escapeHtml(data.cidr || 'N/A')}</td></tr>
                        <tr><td><strong>Name</strong></td><td>${this.escapeHtml(data.name || 'N/A')}</td></tr>
                        <tr><td><strong>Organization</strong></td><td>${this.escapeHtml(data.organization || 'N/A')}</td></tr>
                        <tr><td><strong>Country</strong></td><td>${this.escapeHtml(data.country || 'N/A')}</td></tr>
                        <tr><td><strong>RIR</strong></td><td>${this.escapeHtml(data.rir || 'N/A')}</td></tr>
                        <tr><td><strong>Abuse Contact</strong></td><td>${this.escapeHtml(data.abuse_contact || 'N/A')}</td></tr>
                    </table>
                `;
            }

            html += `
                <div class="modal-footer">
                    <button class="btn" onclick="app.closeModal()">Close</button>
                </div>
            `;

            document.getElementById('modal-content').innerHTML = html;
        } catch (error) {
            document.getElementById('modal-content').innerHTML = `
                <h2>IP Details: ${this.escapeHtml(ip)}</h2>
                <div class="ip-details-error">Failed to load IP details: ${this.escapeHtml(error.message)}</div>
                <div class="modal-footer">
                    <button class="btn" onclick="app.closeModal()">Close</button>
                </div>
            `;
        }
    }

    // Export
    async previewExport() {
        try {
            const format = document.getElementById('export-format').value;
            const prefixName = document.getElementById('prefix-name').value;
            const filterName = document.getElementById('filter-name').value;

            const data = await this.api(
                `/export/juniper?format=${format}&prefix_name=${prefixName}&filter_name=${filterName}`
            );

            document.getElementById('export-output').textContent = data.config;
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    downloadExport() {
        const format = document.getElementById('export-format').value;
        const prefixName = document.getElementById('prefix-name').value;
        const filterName = document.getElementById('filter-name').value;

        window.location.href =
            `/api/export/download?format=${format}&prefix_name=${prefixName}&filter_name=${filterName}`;
    }

    async copyExport() {
        const output = document.getElementById('export-output').textContent;
        if (!output) {
            this.showToast('Generate preview first', 'warning');
            return;
        }

        try {
            await navigator.clipboard.writeText(output);
            this.showToast('Copied to clipboard', 'success');
        } catch {
            this.showToast('Failed to copy', 'error');
        }
    }

    // Abuse Reports
    async loadAbuseHistory() {
        try {
            const data = await this.api('/abuse/history');
            const tbody = document.querySelector('#abuse-history-table tbody');

            if (!data.reports || data.reports.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7">No abuse reports sent yet</td></tr>';
                return;
            }

            tbody.innerHTML = data.reports.map(report => `
                <tr>
                    <td>${this.formatDate(report.sent_at)}</td>
                    <td><span class="ip-address">${this.escapeHtml(report.ip_address)}</span></td>
                    <td>${this.escapeHtml(report.abuse_email)}</td>
                    <td>${this.escapeHtml(report.organization || '-')}</td>
                    <td>${report.attack_count}</td>
                    <td><span class="badge ${report.status === 'sent' ? 'badge-success' : 'badge-danger'}">${report.status}</span></td>
                    <td>
                        <button class="btn btn-small" onclick="app.viewAbuseReport(${report.id})">View</button>
                    </td>
                </tr>
            `).join('');
        } catch (error) {
            this.showToast('Failed to load abuse history', 'error');
        }
    }

    async checkAbuseContact() {
        const ip = document.getElementById('abuse-ip-input').value.trim();
        if (!ip) {
            this.showToast('Please enter an IP address', 'error');
            return;
        }

        const infoDiv = document.getElementById('abuse-contact-info');
        infoDiv.classList.remove('hidden');
        infoDiv.innerHTML = '<p>Looking up abuse contact...</p>';

        try {
            const data = await this.api(`/abuse/check/${encodeURIComponent(ip)}`);

            if (data.error) {
                infoDiv.innerHTML = `<div class="abuse-error">${this.escapeHtml(data.error)}</div>`;
                return;
            }

            if (!data.has_contact) {
                infoDiv.innerHTML = `
                    <div class="abuse-error">No abuse contact found for this IP</div>
                    <p>Organization: ${this.escapeHtml(data.organization || 'Unknown')}</p>
                `;
                return;
            }

            let actionHtml = '';
            if (data.can_send) {
                actionHtml = `<button class="btn btn-primary" onclick="app.sendAbuseReport('${ip}')">Send Abuse Report</button>`;
            } else {
                actionHtml = `<div class="cooldown-notice">${this.escapeHtml(data.cooldown_reason)}</div>
                    <button class="btn btn-small" onclick="app.sendAbuseReport('${ip}', true)">Force Send Anyway</button>`;
            }

            infoDiv.innerHTML = `
                <div class="abuse-contact-details">
                    <table>
                        <tr><td><strong>IP Address</strong></td><td>${this.escapeHtml(ip)}</td></tr>
                        <tr><td><strong>Abuse Email</strong></td><td><a href="mailto:${this.escapeHtml(data.abuse_email)}">${this.escapeHtml(data.abuse_email)}</a></td></tr>
                        <tr><td><strong>Organization</strong></td><td>${this.escapeHtml(data.organization || 'Unknown')}</td></tr>
                        <tr><td><strong>Network</strong></td><td>${this.escapeHtml(data.network || 'Unknown')}</td></tr>
                        <tr><td><strong>Attack Count</strong></td><td>${data.attack_count}</td></tr>
                    </table>
                    <div class="abuse-actions">${actionHtml}</div>
                </div>
            `;
        } catch (error) {
            infoDiv.innerHTML = `<div class="abuse-error">Failed to check abuse contact: ${this.escapeHtml(error.message)}</div>`;
        }
    }

    async sendAbuseReport(ip, force = false) {
        try {
            const result = await this.api(`/abuse/report/${encodeURIComponent(ip)}`, {
                method: 'POST',
                body: JSON.stringify({ force })
            });

            if (result.success) {
                this.showToast(`Abuse report sent to ${result.abuse_email}`, 'success');
                this.loadAbuseHistory();
                document.getElementById('abuse-contact-info').classList.add('hidden');
                document.getElementById('abuse-ip-input').value = '';
            } else {
                this.showToast(result.error || 'Failed to send report', 'error');
            }
        } catch (error) {
            this.showToast('Failed to send abuse report', 'error');
        }
    }

    async viewAbuseReport(reportId) {
        try {
            const data = await this.api(`/abuse/history/${reportId}`);
            const report = data.report;

            if (!report) {
                this.showToast('Report not found', 'error');
                return;
            }

            const emailBody = report.email_body || 'Email content not available';
            const statusBadge = report.status === 'sent'
                ? '<span class="badge badge-success">Sent</span>'
                : '<span class="badge badge-danger">Failed</span>';

            this.showModal(`
                <h2>Abuse Report Details</h2>
                <div class="report-details">
                    <div class="report-meta">
                        <p><strong>IP Address:</strong> ${this.escapeHtml(report.ip_address)}</p>
                        <p><strong>Sent To:</strong> ${this.escapeHtml(report.abuse_email)}</p>
                        <p><strong>Organization:</strong> ${this.escapeHtml(report.organization || 'N/A')}</p>
                        <p><strong>Date:</strong> ${this.formatDate(report.sent_at)}</p>
                        <p><strong>Status:</strong> ${statusBadge}</p>
                        ${report.error_message ? `<p><strong>Error:</strong> ${this.escapeHtml(report.error_message)}</p>` : ''}
                    </div>
                    <h3>Email Content</h3>
                    <pre class="email-preview">${this.escapeHtml(emailBody)}</pre>
                </div>
                <div class="modal-actions">
                    <button class="btn" onclick="app.closeModal()">Close</button>
                </div>
            `);
        } catch (error) {
            this.showToast('Failed to load report details', 'error');
        }
    }

    // Email Blocklist
    async loadEmailBlocklist() {
        if (this.user?.role !== 'admin') return;

        try {
            const data = await this.api('/abuse/email-blocklist');
            const tbody = document.querySelector('#email-blocklist-table tbody');

            if (!data.blocklist || data.blocklist.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5">No blocked emails</td></tr>';
                return;
            }

            tbody.innerHTML = data.blocklist.map(item => `
                <tr>
                    <td>${this.escapeHtml(item.email)}</td>
                    <td>${this.escapeHtml(item.reason || '-')}</td>
                    <td>${this.escapeHtml(item.added_by || '-')}</td>
                    <td>${this.formatDate(item.created_at)}</td>
                    <td>
                        <button class="btn btn-small btn-danger" onclick="app.removeEmailBlock('${this.escapeHtml(item.email)}')">Remove</button>
                    </td>
                </tr>
            `).join('');
        } catch (error) {
            console.error('Failed to load email blocklist:', error);
        }
    }

    async addEmailBlock() {
        const email = document.getElementById('block-email-input').value.trim();
        const reason = document.getElementById('block-email-reason').value.trim();

        if (!email) {
            this.showToast('Please enter an email address', 'error');
            return;
        }

        try {
            const result = await this.api('/abuse/email-blocklist', {
                method: 'POST',
                body: JSON.stringify({ email, reason })
            });

            if (result.success) {
                this.showToast(`${email} added to blocklist`, 'success');
                document.getElementById('block-email-input').value = '';
                document.getElementById('block-email-reason').value = '';
                this.loadEmailBlocklist();
            } else {
                this.showToast(result.error || 'Failed to add email', 'error');
            }
        } catch (error) {
            this.showToast('Failed to add email to blocklist', 'error');
        }
    }

    async removeEmailBlock(email) {
        if (!confirm(`Remove ${email} from blocklist?`)) return;

        try {
            const result = await this.api(`/abuse/email-blocklist/${encodeURIComponent(email)}`, {
                method: 'DELETE'
            });

            if (result.success) {
                this.showToast(`${email} removed from blocklist`, 'success');
                this.loadEmailBlocklist();
            } else {
                this.showToast(result.error || 'Failed to remove email', 'error');
            }
        } catch (error) {
            this.showToast('Failed to remove email from blocklist', 'error');
        }
    }

    // Settings
    async loadSettings() {
        if (this.user?.role !== 'admin') return;

        try {
            const data = await this.api('/settings');
            const settings = data.settings || {};

            // Populate form fields
            document.getElementById('smtp_host').value = settings.smtp_host || '';
            document.getElementById('smtp_port').value = settings.smtp_port || '587';
            document.getElementById('smtp_user').value = settings.smtp_user || '';
            document.getElementById('smtp_pass').value = '';  // Don't populate password
            document.getElementById('smtp_from').value = settings.smtp_from || '';
            document.getElementById('abuse_report_from_name').value = settings.abuse_report_from_name || '';
            document.getElementById('abuse_report_cooldown_days').value = settings.abuse_report_cooldown_days || '7';
            document.getElementById('auto_block_threshold').value = settings.auto_block_threshold || '3';
            document.getElementById('blocklist_expiry_days').value = settings.blocklist_expiry_days || '60';

            // Tarpit settings
            document.getElementById('tarpit_enabled').checked = settings.tarpit_enabled === 'true';
            document.getElementById('tarpit_blocklist_only').checked = settings.tarpit_blocklist_only !== 'false';
            document.getElementById('tarpit_delay_ms').value = settings.tarpit_delay_ms || '20000';
            document.getElementById('tarpit_ringing_count').value = settings.tarpit_ringing_count || '30';

            // Throttle settings
            document.getElementById('throttle_enabled').checked = settings.throttle_enabled !== 'false';
            document.getElementById('throttle_requests_per_minute').value = settings.throttle_requests_per_minute || '30';
            document.getElementById('throttle_log_enabled').checked = settings.throttle_log_enabled !== 'false';
            document.getElementById('throttle_logs_per_minute').value = settings.throttle_logs_per_minute || '10';

            // Show password placeholder if set
            if (settings.smtp_pass === '********') {
                document.getElementById('smtp_pass').placeholder = 'Password is set (leave blank to keep)';
            }
        } catch (error) {
            this.showToast('Failed to load settings', 'error');
        }
    }

    async saveSettings() {
        const settings = {
            smtp_host: document.getElementById('smtp_host').value,
            smtp_port: document.getElementById('smtp_port').value,
            smtp_user: document.getElementById('smtp_user').value,
            smtp_pass: document.getElementById('smtp_pass').value,
            smtp_from: document.getElementById('smtp_from').value,
            abuse_report_from_name: document.getElementById('abuse_report_from_name').value,
            abuse_report_cooldown_days: document.getElementById('abuse_report_cooldown_days').value,
            auto_block_threshold: document.getElementById('auto_block_threshold').value,
            blocklist_expiry_days: document.getElementById('blocklist_expiry_days').value,
            // Tarpit settings
            tarpit_enabled: document.getElementById('tarpit_enabled').checked ? 'true' : 'false',
            tarpit_blocklist_only: document.getElementById('tarpit_blocklist_only').checked ? 'true' : 'false',
            tarpit_delay_ms: document.getElementById('tarpit_delay_ms').value,
            tarpit_ringing_count: document.getElementById('tarpit_ringing_count').value,
            // Throttle settings
            throttle_enabled: document.getElementById('throttle_enabled').checked ? 'true' : 'false',
            throttle_requests_per_minute: document.getElementById('throttle_requests_per_minute').value,
            throttle_log_enabled: document.getElementById('throttle_log_enabled').checked ? 'true' : 'false',
            throttle_logs_per_minute: document.getElementById('throttle_logs_per_minute').value
        };

        const resultSpan = document.getElementById('settings-save-result');
        resultSpan.textContent = 'Saving...';
        resultSpan.className = 'save-result';

        try {
            const result = await this.api('/settings', {
                method: 'PUT',
                body: JSON.stringify({ settings })
            });

            if (result.success) {
                resultSpan.textContent = 'Settings saved successfully';
                resultSpan.className = 'save-result success';
                this.showToast('Settings saved', 'success');
            } else {
                resultSpan.textContent = result.error || 'Failed to save';
                resultSpan.className = 'save-result error';
            }
        } catch (error) {
            resultSpan.textContent = 'Failed to save settings';
            resultSpan.className = 'save-result error';
            this.showToast('Failed to save settings', 'error');
        }

        setTimeout(() => { resultSpan.textContent = ''; }, 5000);
    }

    async testSmtp() {
        const resultSpan = document.getElementById('smtp-test-result');
        resultSpan.textContent = 'Testing...';
        resultSpan.className = 'test-result';

        // First save current settings
        await this.saveSettings();

        try {
            const result = await this.api('/settings/test-smtp', { method: 'POST' });

            if (result.success) {
                resultSpan.textContent = 'Connection successful!';
                resultSpan.className = 'test-result success';
            } else {
                resultSpan.textContent = result.error || 'Connection failed';
                resultSpan.className = 'test-result error';
            }
        } catch (error) {
            resultSpan.textContent = 'Test failed: ' + error.message;
            resultSpan.className = 'test-result error';
        }
    }

    // Users
    async loadUsers() {
        if (this.user?.role !== 'admin') return;

        try {
            const data = await this.api('/users');

            const tbody = document.querySelector('#users-table tbody');
            tbody.innerHTML = data.users.map(user => `
                <tr>
                    <td>${this.escapeHtml(user.username)}</td>
                    <td>${this.escapeHtml(user.email || '-')}</td>
                    <td><span class="badge ${user.role === 'admin' ? 'badge-warning' : 'badge-success'}">${user.role}</span></td>
                    <td>${this.formatDate(user.last_login)}</td>
                    <td><span class="badge ${user.active ? 'badge-success' : 'badge-danger'}">${user.active ? 'Active' : 'Inactive'}</span></td>
                    <td>
                        <button class="btn btn-small action-btn"
                                onclick="app.showEditUserModal(${user.id}, '${user.username}', '${user.email || ''}', '${user.role}')">Edit</button>
                        ${user.id !== this.user.id ? `
                        <button class="btn btn-small btn-danger action-btn"
                                onclick="app.deleteUser(${user.id})">Delete</button>
                        ` : ''}
                    </td>
                </tr>
            `).join('');
        } catch (error) {
            this.showToast('Failed to load users', 'error');
        }
    }

    showAddUserModal() {
        this.showModal(`
            <h2>Add User</h2>
            <form id="add-user-form">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="modal-username" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="modal-password" required>
                </div>
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" id="modal-email">
                </div>
                <div class="form-group">
                    <label>Role</label>
                    <select id="modal-role">
                        <option value="viewer">Viewer</option>
                        <option value="admin">Admin</option>
                    </select>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn" onclick="app.closeModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create User</button>
                </div>
            </form>
        `);

        document.getElementById('add-user-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('modal-username').value;
            const password = document.getElementById('modal-password').value;
            const email = document.getElementById('modal-email').value;
            const role = document.getElementById('modal-role').value;

            try {
                await this.api('/users', {
                    method: 'POST',
                    body: JSON.stringify({ username, password, email, role })
                });
                this.closeModal();
                this.showToast('User created', 'success');
                this.loadUsers();
            } catch (error) {
                this.showToast(error.message, 'error');
            }
        });
    }

    showEditUserModal(id, username, email, role) {
        this.showModal(`
            <h2>Edit User: ${this.escapeHtml(username)}</h2>
            <form id="edit-user-form">
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" id="modal-edit-email" value="${this.escapeHtml(email)}">
                </div>
                <div class="form-group">
                    <label>Role</label>
                    <select id="modal-edit-role">
                        <option value="viewer" ${role === 'viewer' ? 'selected' : ''}>Viewer</option>
                        <option value="admin" ${role === 'admin' ? 'selected' : ''}>Admin</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>New Password (leave blank to keep current)</label>
                    <input type="password" id="modal-edit-password">
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn" onclick="app.closeModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                </div>
            </form>
        `);

        document.getElementById('edit-user-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const data = {
                email: document.getElementById('modal-edit-email').value,
                role: document.getElementById('modal-edit-role').value
            };
            const password = document.getElementById('modal-edit-password').value;
            if (password) data.password = password;

            try {
                await this.api(`/users/${id}`, {
                    method: 'PUT',
                    body: JSON.stringify(data)
                });
                this.closeModal();
                this.showToast('User updated', 'success');
                this.loadUsers();
            } catch (error) {
                this.showToast(error.message, 'error');
            }
        });
    }

    async deleteUser(id) {
        if (!confirm('Are you sure you want to delete this user?')) return;

        try {
            await this.api(`/users/${id}`, { method: 'DELETE' });
            this.showToast('User deleted', 'success');
            this.loadUsers();
        } catch (error) {
            this.showToast(error.message, 'error');
        }
    }

    // Modal
    showModal(content) {
        document.getElementById('modal-content').innerHTML = content;
        document.getElementById('modal-overlay').classList.remove('hidden');
    }

    closeModal() {
        document.getElementById('modal-overlay').classList.add('hidden');
    }

    // Toast notifications
    showToast(message, type = 'info') {
        let container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        container.appendChild(toast);

        setTimeout(() => toast.remove(), 4000);
    }

    // Helpers
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    formatDate(dateStr) {
        if (!dateStr) return '-';
        const date = new Date(dateStr);
        return date.toLocaleString();
    }

    formatNumber(num) {
        return num?.toLocaleString() || '0';
    }

    truncate(str, len) {
        if (!str) return '-';
        return str.length > len ? str.substring(0, len) + '...' : str;
    }

    getProtocolClass(honeypotType) {
        const classes = {
            'sip': 'sip',
            'http': 'http',
            'tftp': 'tftp',
            'provisioning': 'http'
        };
        return classes[honeypotType?.toLowerCase()] || 'default';
    }

    debounce(fn, delay) {
        let timeout;
        return (...args) => {
            clearTimeout(timeout);
            timeout = setTimeout(() => fn.apply(this, args), delay);
        };
    }
}

// Initialize app
const app = new HoneypotDashboard();
