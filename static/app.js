/**
 * IPスキャナー v2 ダッシュボード フロントエンドロジック
 * WebSocket接続、スキャン制御、結果表示、脆弱性表示、統計更新を担当
 */

// ========== 状態管理 ==========
let ws = null;
let isScanning = false;
let currentPage = 1;
const PAGE_SIZE = 50;
let searchTimeout = null;
let elapsedTimer = null;
let scanStartTime = null;
let currentMode = 'random';  // 'random' or 'target'
let currentResults = []; // 現在画面に表示中のデータ保持用

// ========== WebSocket ==========

function connectWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${location.host}/ws`);

    ws.onopen = () => {
        console.log('WebSocket 接続完了');
    };

    ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        handleWSMessage(message);
    };

    ws.onclose = () => {
        console.log('WebSocket 切断 - 3秒後に再接続');
        setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = (error) => {
        console.error('WebSocket エラー:', error);
    };
}

function handleWSMessage(message) {
    switch (message.type) {
        case 'result':
            addResultToTable(message.data);
            break;
        case 'status':
            updateScanStatus(message.data);
            break;
    }
}

// ========== モード切替 ==========

function switchMode(mode) {
    currentMode = mode;
    document.getElementById('modeRandom').classList.toggle('active', mode === 'random');
    document.getElementById('modeTarget').classList.toggle('active', mode === 'target');
    document.getElementById('targetInputArea').style.display = mode === 'target' ? 'block' : 'none';
    const subdomainToggle = document.getElementById('subdomainToggleWrapper');
    if (subdomainToggle) {
        subdomainToggle.style.display = mode === 'target' ? 'inline-flex' : 'none';
    }
}

// ========== スキャン制御 ==========

async function startScan() {
    const ports = [];
    if (document.getElementById('port80').checked) ports.push(80);
    if (document.getElementById('port443').checked) ports.push(443);
    if (document.getElementById('port8080').checked) ports.push(8080);
    if (document.getElementById('port8443').checked) ports.push(8443);

    if (ports.length === 0) {
        alert('少なくとも1つのポートを選択してください');
        return;
    }

    const takeScreenshots = document.getElementById('takeScreenshots').checked;
    const runVulnCheck = document.getElementById('runVulnCheck').checked;
    const searchRegex = document.getElementById('searchRegex') ? document.getElementById('searchRegex').value.trim() : "";
    const enumerateSubdomains = document.getElementById('enumerateSubdomains') ? document.getElementById('enumerateSubdomains').checked : false;

    try {
        let response;
        if (currentMode === 'target') {
            // 指定IPスキャン
            const targets = document.getElementById('targetIps').value.trim();
            if (!targets) {
                alert('スキャン対象のIPアドレスを入力してください');
                return;
            }
            response = await fetch('/api/scan/target', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    targets,
                    ports,
                    take_screenshots: takeScreenshots,
                    run_vuln_check: runVulnCheck,
                    search_regex: searchRegex || null,
                    enumerate_subdomains: enumerateSubdomains
                })
            });
        } else {
            // ランダムスキャン
            response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ports,
                    take_screenshots: takeScreenshots,
                    run_vuln_check: runVulnCheck,
                    search_regex: searchRegex || null
                })
            });
        }

        if (response.ok) {
            const data = await response.json();
            isScanning = true;
            scanStartTime = Date.now();
            updateUIForScanning(true);
            startElapsedTimer();
            // 指定IPモードのプログレス表示
            if (data.mode === 'target') {
                document.getElementById('targetProgress').style.display = 'flex';
                document.getElementById('progressText').textContent =
                    `0 / ${data.total_scans}`;
            }
        } else {
            const error = await response.json();
            alert(error.error || 'スキャン開始に失敗しました');
        }
    } catch (e) {
        alert('サーバーに接続できません');
    }
}

async function stopScan() {
    try {
        const response = await fetch('/api/scan/stop', { method: 'POST' });
        if (response.ok) {
            isScanning = false;
            updateUIForScanning(false);
            stopElapsedTimer();
        }
    } catch (e) {
        alert('停止に失敗しました');
    }
}

async function clearResults() {
    if (!confirm('全てのスキャン結果を削除しますか？')) return;

    try {
        await fetch('/api/results', { method: 'DELETE' });
        document.getElementById('resultsBody').innerHTML = `
            <tr class="empty-row">
                <td colspan="11">
                    <div class="empty-state">
                        <span class="empty-icon">🛰️</span>
                        <p>スキャンを開始すると、発見されたWebサービスがここに表示されます</p>
                    </div>
                </td>
            </tr>
        `;
        document.getElementById('resultCount').textContent = '0 件';
        document.getElementById('totalScanned').textContent = '0';
        document.getElementById('totalFound').textContent = '0';
        document.getElementById('vulnCount').textContent = '0';
        currentPage = 1;
        updatePagination();
    } catch (e) {
        alert('クリアに失敗しました');
    }
}

// ========== UI更新 ==========

function updateUIForScanning(scanning) {
    const btnStart = document.getElementById('btnStart');
    const btnStop = document.getElementById('btnStop');
    const indicator = document.getElementById('statusIndicator');
    const animation = document.getElementById('scanAnimation');
    const statusText = indicator.querySelector('.status-text');

    btnStart.disabled = scanning;
    btnStop.disabled = !scanning;

    if (scanning) {
        indicator.classList.add('scanning');
        animation.classList.add('active');
        const modeText = currentMode === 'target' ? '指定IPスキャン中...' : 'ランダムスキャン中...';
        statusText.textContent = modeText;
    } else {
        indicator.classList.remove('scanning');
        animation.classList.remove('active');
        statusText.textContent = '待機中';
        document.getElementById('targetProgress').style.display = 'none';
    }
}

function updateScanStatus(data) {
    document.getElementById('totalScanned').textContent = formatNumber(data.total_scanned);
    document.getElementById('totalFound').textContent = formatNumber(data.total_found);
    document.getElementById('scanRate').textContent = formatNumber(data.current_rate);

    // 指定IPモードの進捗バー
    if (data.mode === 'target' && data.target_total > 0) {
        const progress = document.getElementById('targetProgress');
        progress.style.display = 'flex';
        const pct = Math.round((data.target_done / data.target_total) * 100);
        document.getElementById('progressFill').style.width = `${pct}%`;
        document.getElementById('progressText').textContent =
            `${data.target_done} / ${data.target_total} (${pct}%)`;
    }

    if (!data.running && isScanning) {
        isScanning = false;
        updateUIForScanning(false);
        stopElapsedTimer();
    }
}

function addResultToTable(result) {
    const tbody = document.getElementById('resultsBody');

    const emptyRow = tbody.querySelector('.empty-row');
    if (emptyRow) emptyRow.remove();

    const row = document.createElement('tr');
    row.classList.add('new-row');
    row.innerHTML = createResultRow(result);

    tbody.insertBefore(row, tbody.firstChild);

    while (tbody.children.length > PAGE_SIZE) {
        tbody.removeChild(tbody.lastChild);
    }

    currentResults.unshift(result);
    if (currentResults.length > PAGE_SIZE) {
        currentResults.pop();
    }

    // ギャラリービュー表示中の場合はギャラリーも更新
    if (currentView === 'gallery') {
        renderResults(currentResults);
    }

    // 脆弱性カウント更新
    if (result.vuln_count > 0) {
        const el = document.getElementById('vulnCount');
        const current = parseInt(el.textContent.replace(/,/g, '')) || 0;
        el.textContent = formatNumber(current + result.vuln_count);
    }

    updateResultCount();
}

function createResultRow(r) {
    const statusClass = getStatusClass(r.status_code);
    const statusBadge = `<span class="status-badge ${statusClass}">${r.status_code}</span>`;

    // 脆弱性バッジ
    let vulnHtml = '<span class="vuln-none">✓</span>';
    if (r.vuln_count > 0) {
        const riskClass = `vuln-${r.vuln_max_risk || 'info'}`;
        const riskIcon = getRiskIcon(r.vuln_max_risk);
        vulnHtml = `<span class="vuln-badge ${riskClass}" onclick="showDetails(${r.id})" title="クリックで詳細表示">
            ${riskIcon} ${r.vuln_count}件
        </span>`;
    }

    // SSL表示
    let sslHtml = '<span class="ssl-none">-</span>';
    if (r.ssl_issuer || r.ssl_domain) {
        const domain = r.ssl_domain || '-';
        const issuer = r.ssl_issuer || '-';
        sslHtml = `<span class="ssl-icon">🔒</span> <span title="発行者: ${escapeHtml(issuer)}">${escapeHtml(truncate(domain, 20))}</span>`;
    }

    // 応答時間
    const timeClass = r.response_time_ms < 500 ? 'time-fast' :
        r.response_time_ms < 2000 ? 'time-medium' : 'time-slow';
    const timeHtml = `<span class="response-time ${timeClass}">${r.response_time_ms}ms</span>`;

    // テクスタック
    let techHtml = '<span class="text-muted">-</span>';
    if (r.tech_stack) {
        const techs = r.tech_stack.split(',').map(t => t.trim()).filter(Boolean);
        techHtml = `<div style="display:flex; flex-wrap:wrap; gap:4px; max-width:120px;">
            ${techs.slice(0, 2).map(t => `<span class="tech-badge" title="${escapeHtml(t)}">${escapeHtml(t)}</span>`).join('')}
            ${techs.length > 2 ? `<span class="tech-badge" title="${escapeHtml(r.tech_stack)}">+${techs.length - 2}</span>` : ''}
        </div>`;
    }

    // スクリーンショット
    let screenshotHtml = '<span class="no-screenshot">-</span>';
    if (r.screenshot_path) {
        screenshotHtml = `<img class="screenshot-thumb"
            src="/screenshots/${r.screenshot_path}"
            alt="SS"
            onclick="showDetails(${r.id})"
            loading="lazy">`;
    }

    // 時刻
    const time = r.scanned_at ? new Date(r.scanned_at).toLocaleTimeString('ja-JP') : '-';
    const url = `${r.protocol}://${r.ip}:${r.port}`;

    // ホスト名
    const hostnameHtml = r.hostname
        ? `<span class="hostname-cell" title="${escapeHtml(r.hostname)}">${escapeHtml(truncate(r.hostname, 25))}</span>`
        : '<span class="text-muted">-</span>';

    // 国旗 + 国名
    let countryHtml = '<span class="text-muted">-</span>';
    if (r.country_code) {
        const flag = countryCodeToFlag(r.country_code);
        countryHtml = `<span class="country-cell" title="${escapeHtml(r.country || '')}">${flag} ${escapeHtml(r.country_code)}</span>`;
    }

    return `
        <td class="ip-cell"><a href="${url}" target="_blank" rel="noopener">${r.ip}:${r.port}</a></td>
        <td>${statusBadge}</td>
        <td class="hostname-col" title="${escapeHtml(r.hostname || '')}">${hostnameHtml}</td>
        <td>${countryHtml}</td>
        <td class="title-cell" title="${escapeHtml(r.title || '')}">${escapeHtml(r.title || '-')}</td>
        <td class="server-cell" title="${escapeHtml(r.server || '')}">${escapeHtml(r.server || '-')}</td>
        <td>${techHtml}</td>
        <td>${vulnHtml}</td>
        <td class="ssl-cell">${sslHtml}</td>
        <td>${timeHtml}</td>
        <td>${screenshotHtml}</td>
        <td class="time-cell">${time}</td>
    `;
}

function getStatusClass(code) {
    if (code >= 200 && code < 300) return 'status-2xx';
    if (code >= 300 && code < 400) return 'status-3xx';
    if (code >= 400 && code < 500) return 'status-4xx';
    if (code >= 500) return 'status-5xx';
    return '';
}

function getRiskIcon(risk) {
    switch (risk) {
        case 'critical': return '⛔';
        case 'high': return '🔴';
        case 'medium': return '🟡';
        case 'low': return '🔵';
        default: return 'ℹ️';
    }
}

function countryCodeToFlag(code) {
    // 国コード（2文字）をemoji国旗に変換
    if (!code || code.length !== 2) return '🌐';
    const codePoints = [...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65);
    return String.fromCodePoint(...codePoints);
}

// ========== 結果読み込み ==========

async function loadResults() {
    const search = document.getElementById('searchInput').value;
    const statusFilter = document.getElementById('statusFilter').value;
    const riskFilter = document.getElementById('riskFilter').value;
    const offset = (currentPage - 1) * PAGE_SIZE;

    try {
        const params = new URLSearchParams({ limit: PAGE_SIZE, offset });
        if (search) params.append('search', search);
        if (statusFilter) params.append('status_filter', statusFilter);
        if (riskFilter) params.append('risk_filter', riskFilter);

        const response = await fetch(`/api/results?${params}`);
        const data = await response.json();

        currentResults = data.results;
        renderResults(currentResults);
        updateResultCount(data.count);
        updatePagination();
    } catch (e) {
        console.error('結果の取得に失敗:', e);
    }
}

function exportResults(format) {
    if (!format) return;

    // セレクトボックスを元に戻す
    document.getElementById('exportSelect').value = '';

    const search = document.getElementById('searchInput').value;
    const statusFilter = document.getElementById('statusFilter').value;
    const riskFilter = document.getElementById('riskFilter').value;

    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (statusFilter) params.append('status_filter', statusFilter);
    if (riskFilter) params.append('risk_filter', riskFilter);

    // ファイルダウンロードのエンドポイントを開く
    const url = `/api/export/${format}?${params.toString()}`;
    window.open(url, '_blank');
}

let currentView = 'table';

function switchView(viewMode) {
    currentView = viewMode;
    document.getElementById('btnTableView').classList.toggle('active', viewMode === 'table');
    document.getElementById('btnGalleryView').classList.toggle('active', viewMode === 'gallery');
    document.getElementById('tableWrapper').style.display = viewMode === 'table' ? 'block' : 'none';
    document.getElementById('galleryWrapper').style.display = viewMode === 'gallery' ? 'block' : 'none';

    // 現在の結果で再描画
    if (currentResults.length > 0) {
        renderResults(currentResults);
    }
}

function renderResults(results) {
    const tbody = document.getElementById('resultsBody');
    const galleryGrid = document.getElementById('galleryGrid');

    if (results.length === 0) {
        const emptyHtml = `
            <div class="empty-state">
                <span class="empty-icon">🛰️</span>
                <p>条件に一致する結果がありません</p>
            </div>
        `;
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="12">
                    ${emptyHtml}
                </td>
            </tr>
        `;
        galleryGrid.innerHTML = emptyHtml;
        return;
    }

    if (currentView === 'table') {
        tbody.innerHTML = results.map(r => `<tr>${createResultRow(r)}</tr>`).join('');
    } else {
        galleryGrid.innerHTML = results.map(r => createGalleryCard(r)).join('');
    }
}

function createGalleryCard(r) {
    const statusClass = getStatusClass(r.status_code);
    const time = r.scanned_at ? new Date(r.scanned_at).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }) : '-';

    // スクリーンショット部分
    let imgHtml = '';
    if (r.screenshot_path) {
        imgHtml = `<img src="/screenshots/${r.screenshot_path}" alt="Screenshot" onclick="showDetails(${r.id})">`;
    } else {
        imgHtml = `
            <div class="gallery-card-noimg" onclick="showDetails(${r.id})">
                <span>NO IMAGE</span>
                <div style="font-size: 14px; color: var(--accent-primary);">${r.status_code}</div>
            </div>
        `;
    }

    // 脆弱性表示
    let vulnIconHtml = '';
    if (r.vuln_count > 0) {
        const riskIcon = getRiskIcon(r.vuln_max_risk);
        vulnIconHtml = `<span title="脆弱性 ${r.vuln_count}件" style="color: var(--risk-${r.vuln_max_risk || 'info'}); cursor: pointer;" onclick="showDetails(${r.id})">${riskIcon} ${r.vuln_count}</span>`;
    }

    // 国旗
    let flagHtml = '';
    if (r.country_code) {
        flagHtml = `<span title="${escapeHtml(r.country || '')}">${countryCodeToFlag(r.country_code)}</span>`;
    }

    const titleText = r.title ? escapeHtml(r.title) : escapeHtml(r.server || 'Unknown Service');

    // TechStack
    let techHtml = '';
    if (r.tech_stack) {
        const techs = r.tech_stack.split(',').map(t => t.trim()).filter(Boolean);
        techHtml = `
            <div class="gallery-card-tech">
                ${techs.slice(0, 3).map(t => `<span class="tech-badge">${escapeHtml(t)}</span>`).join('')}
                ${techs.length > 3 ? `<span class="tech-badge">+${techs.length - 3}</span>` : ''}
            </div>
        `;
    }

    return `
        <div class="gallery-card">
            <div class="gallery-card-img">
                ${imgHtml}
            </div>
            <div class="gallery-card-content">
                <div class="gallery-card-header">
                    <a href="${r.protocol}://${r.ip}:${r.port}" target="_blank" class="gallery-card-ip" style="text-decoration:none;">
                        ${r.ip}:${r.port}
                    </a>
                    <span class="status-badge ${statusClass}" style="transform: scale(0.85); transform-origin: right;">${r.status_code}</span>
                </div>
                
                <div class="gallery-card-title" title="${titleText}">
                    ${titleText}
                </div>
                
                <div class="gallery-card-meta">
                    <div>
                        <span class="icon">🌍</span>
                        <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                            ${flagHtml} ${escapeHtml(r.hostname || '-')}
                        </span>
                    </div>
                    ${techHtml}
                </div>
                
                <div class="gallery-card-footer">
                    <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">
                        ${time}
                    </div>
                    <div style="display:flex; gap: 8px; font-size: 12px;">
                        ${vulnIconHtml}
                    </div>
                </div>
            </div>
        </div>
    `;
}

function updateResultCount(count) {
    if (count !== undefined) {
        document.getElementById('resultCount').textContent = `${count} 件`;
    } else {
        const tbody = document.getElementById('resultsBody');
        const rows = tbody.querySelectorAll('tr:not(.empty-row)').length;
        document.getElementById('resultCount').textContent = `${rows} 件+`;
    }
}

// ========== ページネーション ==========

function prevPage() {
    if (currentPage > 1) { currentPage--; loadResults(); }
}
function nextPage() {
    currentPage++; loadResults();
}
function updatePagination() {
    document.getElementById('btnPrev').disabled = currentPage <= 1;
    document.getElementById('pageInfo').textContent = `${currentPage} ページ`;
}

// ========== 検索デバウンス ==========

function debounceSearch() {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => { currentPage = 1; loadResults(); }, 400);
}

// ========== 経過時間タイマー ==========

function startElapsedTimer() {
    stopElapsedTimer();
    elapsedTimer = setInterval(() => {
        if (scanStartTime) {
            const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
            document.getElementById('elapsedTime').textContent = formatTime(elapsed);
        }
    }, 1000);
}

function stopElapsedTimer() {
    if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
}

// ========== 詳細モーダル（スクリーンショット＋脆弱性） ==========

async function showDetails(resultId) {
    try {
        const response = await fetch(`/api/results/${resultId}`);
        const result = await response.json();

        document.getElementById('modalTitle').textContent = result.title || '(タイトルなし)';
        document.getElementById('modalUrl').textContent = `${result.protocol}://${result.ip}:${result.port}`;

        // スクリーンショット
        const img = document.getElementById('modalImage');
        if (result.screenshot_path) {
            img.src = `/screenshots/${result.screenshot_path}`;
            img.style.display = 'block';
        } else {
            img.style.display = 'none';
        }

        // 基本情報
        let headersHtml = '';
        if (result.headers) {
            try {
                const headers = JSON.parse(result.headers);
                headersHtml = Object.entries(headers)
                    .map(([k, v]) => `<strong>${escapeHtml(k)}:</strong> ${escapeHtml(v)}`)
                    .join('<br>');
            } catch (e) { }
        }

        document.getElementById('modalDetails').innerHTML = `
            <div class="detail-item">
                <div class="detail-label">ステータスコード</div>
                <div class="detail-value">${result.status_code}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">サーバー</div>
                <div class="detail-value">${escapeHtml(result.server || '-')}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">応答時間</div>
                <div class="detail-value">${result.response_time_ms}ms</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">SSL発行者</div>
                <div class="detail-value">${escapeHtml(result.ssl_issuer || '-')}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">SSL有効期限</div>
                <div class="detail-value">${escapeHtml(result.ssl_expiry || '-')}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">SSLドメイン</div>
                <div class="detail-value">${escapeHtml(result.ssl_domain || '-')}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">ホスト名（逆引きDNS）</div>
                <div class="detail-value">${escapeHtml(result.hostname || '-')}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">国籍</div>
                <div class="detail-value">${result.country_code ? countryCodeToFlag(result.country_code) + ' ' : ''}${escapeHtml(result.country || '-')} ${result.country_code ? '(' + escapeHtml(result.country_code) + ')' : ''}</div>
            </div>
            ${headersHtml ? `
            <div class="detail-item" style="grid-column: span 2">
                <div class="detail-label">レスポンスヘッダー</div>
                <div class="detail-value">${headersHtml}</div>
            </div>
            ` : ''}
        `;

        // 脆弱性詳細
        const vulnsDiv = document.getElementById('modalVulns');
        if (result.vulnerabilities) {
            try {
                const vulns = JSON.parse(result.vulnerabilities);
                if (vulns.length > 0) {
                    vulnsDiv.innerHTML = `
                        <div class="vuln-section-title">🛡️ 脆弱性診断結果（${vulns.length}件）</div>
                        <div class="vuln-list">
                            ${vulns.map(v => `
                                <div class="vuln-item risk-${v.risk}">
                                    <div class="vuln-item-header">
                                        <span class="vuln-item-name">${escapeHtml(v.name)}</span>
                                        <span class="vuln-risk-tag ${v.risk}">${v.risk.toUpperCase()}</span>
                                    </div>
                                    <div class="vuln-item-desc">${escapeHtml(v.description)}</div>
                                </div>
                            `).join('')}
                        </div>
                    `;
                } else {
                    vulnsDiv.innerHTML = '';
                }
            } catch (e) {
                vulnsDiv.innerHTML = '';
            }
        } else {
            vulnsDiv.innerHTML = '';
        }

        document.getElementById('screenshotModal').classList.add('active');
    } catch (e) {
        console.error('詳細取得に失敗:', e);
    }
}

// showScreenshot を showDetails に統合（後方互換）
function showScreenshot(resultId) {
    showDetails(resultId);
}

function closeModal(event) {
    if (event && event.target !== event.currentTarget) return;
    document.getElementById('screenshotModal').classList.remove('active');
}

// ========== ユーティリティ ==========

function formatNumber(num) {
    return num.toLocaleString('ja-JP');
}

function formatTime(seconds) {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

function truncate(str, max) {
    if (!str) return '';
    return str.length > max ? str.substring(0, max) + '...' : str;
}

// ========== 初期化 ==========

document.addEventListener('DOMContentLoaded', () => {
    connectWebSocket();
    loadResults();
    checkScanStatus();
    loadVulnStats();
});

async function checkScanStatus() {
    try {
        const response = await fetch('/api/scan/status');
        const data = await response.json();
        if (data.running) {
            isScanning = true;
            currentMode = data.mode || 'random';
            scanStartTime = Date.now() - (data.elapsed_seconds * 1000);
            updateUIForScanning(true);
            startElapsedTimer();
            updateScanStatus(data);
        }
    } catch (e) { }
}

async function loadVulnStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        if (stats.vuln_stats) {
            document.getElementById('vulnCount').textContent =
                formatNumber(stats.vuln_stats.total_findings || 0);
        }
    } catch (e) { }
}

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
});
