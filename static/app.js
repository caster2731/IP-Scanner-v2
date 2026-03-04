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
let threatMap = null;
let mapMarkers = [];

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
    document.getElementById('modeCamera').classList.toggle('active', mode === 'camera');
    document.getElementById('targetInputArea').style.display = mode === 'target' ? 'block' : 'none';
    const subdomainToggle = document.getElementById('subdomainToggleWrapper');
    if (subdomainToggle) {
        subdomainToggle.style.display = mode === 'target' ? 'inline-flex' : 'none';
    }
    // カメラモード時はカメラ用ポート選択を表示、通常ポート選択を非表示
    const cameraPortsArea = document.getElementById('cameraPortsArea');
    if (cameraPortsArea) {
        cameraPortsArea.style.display = mode === 'camera' ? 'block' : 'none';
    }
    // 通常ポート選択とオプションの表示切替
    const normalControls = document.querySelectorAll('.control-group:not(.camera-ports-area):not(.actions)');
    normalControls.forEach(el => {
        // カメラモード時はポート選択と正規表現検索、脆弱性スキャン等のコントロールは非表示
        // ただしスクリーンショットトグルはそのまま
    });
}

// ========== スキャン制御 ==========

async function startScan() {
    if (currentMode === 'camera') {
        // カメラスキャンモード
        const cameraPorts = [];
        document.querySelectorAll('.cam-port:checked').forEach(cb => {
            cameraPorts.push(parseInt(cb.value));
        });
        if (cameraPorts.length === 0) {
            alert('少なくとも1つのカメラ用ポートを選択してください');
            return;
        }
        const takeScreenshots = document.getElementById('takeScreenshots').checked;
        try {
            const response = await fetch('/api/scan/camera', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ports: cameraPorts,
                    take_screenshots: takeScreenshots
                })
            });
            if (response.ok) {
                isScanning = true;
                scanStartTime = Date.now();
                updateUIForScanning(true);
                startElapsedTimer();
            } else {
                const error = await response.json();
                alert(error.error || 'カメラスキャン開始に失敗しました');
            }
        } catch (e) {
            alert('サーバーに接続できません');
        }
        return;
    }

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
        const modeTexts = {
            'target': '指定IPスキャン中...',
            'camera': '📹 カメラスキャン中...',
            'random': 'ランダムスキャン中...'
        };
        statusText.textContent = modeTexts[currentMode] || 'スキャン中...';
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

    // ギャラリービューやマップ表示中の場合はそちらも更新
    if (currentView === 'gallery') {
        renderResults(currentResults);
    } else if (currentView === 'map') {
        renderMapMarkers(currentResults);
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
    if (r.cve_list) {
        const cveCount = r.cve_list.split(',').length;
        vulnHtml += `<div style="margin-top: 4px;"><span class="vuln-badge vuln-critical" style="font-size: 10px; padding: 2px 4px; opacity: 0.9;" onclick="showDetails(${r.id})" title="${escapeHtml(r.cve_list)}">👾 CVE (${cveCount})</span></div>`;
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

    let honeypotBadge = '';
    if (r.is_honeypot) {
        honeypotBadge = `<div style="color: var(--accent-orange); font-size: 10px; font-weight: bold; margin-bottom: 2px;" title="ハニーポットの疑い">⚠️ 罠サーバー</div>`;
    }

    // カメラ情報バッジ
    let cameraBadge = '';
    if (r.camera_vendor) {
        const confClass = r.camera_confidence === 'high' ? 'camera-high' : r.camera_confidence === 'medium' ? 'camera-medium' : 'camera-low';
        cameraBadge = `<div class="camera-badge ${confClass}" title="カメラタイプ: ${escapeHtml(r.camera_type || 'IP Camera')}">📹 ${escapeHtml(r.camera_vendor)}</div>`;
    }

    return `
        <td class="ip-cell">${honeypotBadge}${cameraBadge}<a href="${url}" target="_blank" rel="noopener">${r.ip}:${r.port}</a></td>
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
    document.getElementById('btnMapView').classList.toggle('active', viewMode === 'map');
    document.getElementById('tableWrapper').style.display = viewMode === 'table' ? 'block' : 'none';
    document.getElementById('galleryWrapper').style.display = viewMode === 'gallery' ? 'block' : 'none';
    document.getElementById('mapWrapper').style.display = viewMode === 'map' ? 'block' : 'none';

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
        if (typeof renderMapMarkers === 'function') renderMapMarkers([]);
        return;
    }

    if (currentView === 'table') {
        tbody.innerHTML = results.map(r => `<tr>${createResultRow(r)}</tr>`).join('');
    } else if (currentView === 'gallery') {
        galleryGrid.innerHTML = results.map(r => createGalleryCard(r)).join('');
    } else if (currentView === 'map') {
        renderMapMarkers(results);
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
    if (r.cve_list) {
        const cveCount = r.cve_list.split(',').length;
        vulnIconHtml += `<span title="${escapeHtml(r.cve_list)}" style="color: var(--accent-red); margin-left: 8px; font-weight: bold; cursor: pointer;" onclick="showDetails(${r.id})">👾 CVE (${cveCount})</span>`;
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

    let honeypotBadge = '';
    if (r.is_honeypot) {
        honeypotBadge = `<span style="color: var(--accent-orange); font-size: 11px; margin-right: 4px;" title="ハニーポットの疑い">⚠️</span>`;
    }

    let cameraBadgeGallery = '';
    if (r.camera_vendor) {
        const confClass = r.camera_confidence === 'high' ? 'camera-high' : r.camera_confidence === 'medium' ? 'camera-medium' : 'camera-low';
        cameraBadgeGallery = `<span class="camera-badge ${confClass}" style="font-size: 10px; margin-right: 4px;">📹 ${escapeHtml(r.camera_vendor)}</span>`;
    }

    return `
        <div class="gallery-card">
            <div class="gallery-card-img">
                ${imgHtml}
            </div>
            <div class="gallery-card-content">
                <div class="gallery-card-header">
                    <a href="${r.protocol}://${r.ip}:${r.port}" target="_blank" class="gallery-card-ip" style="text-decoration:none;">
                        ${honeypotBadge}${cameraBadgeGallery}${r.ip}:${r.port}
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

        const titleEl = document.getElementById('modalTitle');
        titleEl.textContent = result.title || '(タイトルなし)';
        titleEl.style.color = result.is_honeypot ? 'var(--accent-orange)' : '';
        if (result.is_honeypot) {
            titleEl.textContent = '⚠️ 罠サーバー (Honeypot) - ' + titleEl.textContent;
        }

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
                                        <span class="vuln-item-name">${v.type === 'cve_match' ? '👾 ' : ''}${escapeHtml(v.name)}</span>
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

// ========== Threat Map (Leaflet) ==========

function initMap() {
    if (threatMap) return;
    threatMap = L.map('threatMap').setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; CARTO',
        subdomains: 'abcd',
        maxZoom: 20
    }).addTo(threatMap);
}

function renderMapMarkers(results) {
    if (!threatMap) initMap();

    // 既存のマーカーをクリア
    mapMarkers.forEach(m => threatMap.removeLayer(m));
    mapMarkers = [];

    results.forEach(r => {
        if (r.latitude && r.longitude) {
            let color = '#3b82f6'; // default low (ブルー)
            if (r.vuln_max_risk === 'critical') color = '#dc2626';
            else if (r.vuln_max_risk === 'high') color = '#ef4444';
            else if (r.vuln_max_risk === 'medium') color = '#f59e0b';

            const circle = L.circleMarker([r.latitude, r.longitude], {
                radius: 6,
                fillColor: color,
                color: '#fff',
                weight: 1,
                opacity: 0.8,
                fillOpacity: 0.8
            }).addTo(threatMap);

            circle.bindPopup(`
                <div style="font-family: var(--font-sans); color: var(--text-primary); font-size: 13px;">
                    <b style="color: var(--accent-primary);">${r.ip}:${r.port}</b><br>
                    ${r.status_code} ${escapeHtml(r.title || '')}<br>
                    <button onclick="showDetails(${r.id})" style="margin-top: 8px; cursor: pointer; padding: 4px 8px; background: var(--bg-input); border: 1px solid var(--border-subtle); color: var(--text-primary); border-radius: 4px;">詳細を見る</button>
                </div>
            `);
            mapMarkers.push(circle);
        }
    });

    // コンテナが表示されたときにサイズを再計算
    setTimeout(() => {
        threatMap.invalidateSize();
    }, 100);
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

// ========== ステルスモード制御 ==========

/**
 * ステルスモードのON/OFF切替
 * トグルスイッチ操作時に呼ばれる
 */
function toggleStealth() {
    const enabled = document.getElementById('stealthEnabled').checked;
    const body = document.getElementById('stealthBody');
    const dot = document.getElementById('stealthStatusDot');
    const panel = document.getElementById('stealthPanel');

    body.style.display = enabled ? 'block' : 'none';
    dot.className = 'stealth-status-dot' + (enabled ? ' stealth-active' : '');
    dot.title = enabled ? '有効' : '無効';
    panel.classList.toggle('stealth-enabled', enabled);

    // ON/OFF変更を即座にサーバーに送信
    applyStealth();

    // ステルスモニターのポーリング連動
    if (enabled) {
        // ステルスON → ポーリング開始（設定適用後に少し遅延して検証）
        setTimeout(() => startStealthMonitorPolling(), 1500);
    } else {
        // ステルスOFF → ポーリング停止＋インジケーターリセット
        stopStealthMonitorPolling();
        document.querySelectorAll('.stealth-ind').forEach(el => {
            el.className = 'stealth-ind';
            const s = el.querySelector('.ind-status');
            if (s) { s.textContent = '—'; s.className = 'ind-status ind-unknown'; }
        });
    }
}

/**
 * ステルス設定をサーバーに送信・適用
 */
async function applyStealth() {
    const enabled = document.getElementById('stealthEnabled').checked;
    const proxyUrl = document.getElementById('stealthProxyUrl').value.trim();
    const delayMin = parseFloat(document.getElementById('stealthDelayMin').value);
    const delayMax = parseFloat(document.getElementById('stealthDelayMax').value);
    const randomizeUA = document.getElementById('stealthRandomizeUA').checked;

    try {
        const response = await fetch('/api/stealth/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                enabled,
                proxy_url: proxyUrl,
                delay_min: delayMin,
                delay_max: delayMax,
                randomize_ua: randomizeUA
            })
        });
        if (response.ok) {
            const status = await response.json();
            updateStealthUI(status);
        }
    } catch (e) {
        console.error('ステルス設定エラー:', e);
    }
}

/**
 * 遅延レンジスライダーのラベルを更新
 */
function updateDelayLabel() {
    const min = parseFloat(document.getElementById('stealthDelayMin').value);
    const max = parseFloat(document.getElementById('stealthDelayMax').value);
    document.getElementById('delayLabel').textContent = `${min.toFixed(1)}s 〜 ${max.toFixed(1)}s`;
}

/**
 * ステルスUIの状態をサーバーレスポンスで更新
 */
function updateStealthUI(status) {
    const dot = document.getElementById('stealthStatusDot');

    if (status.enabled) {
        dot.className = 'stealth-status-dot stealth-active';
        dot.title = status.proxy_connected ? 'プロキシ接続済み' : '有効（プロキシ未接続）';
    } else {
        dot.className = 'stealth-status-dot';
        dot.title = '無効';
    }
}

/**
 * 起動時にサーバーのステルス設定を取得してUIに反映
 */
async function loadStealthStatus() {
    try {
        const response = await fetch('/api/stealth/status');
        if (response.ok) {
            const status = await response.json();
            document.getElementById('stealthEnabled').checked = status.enabled;
            document.getElementById('stealthProxyUrl').value = status.proxy_url;
            document.getElementById('stealthDelayMin').value = status.delay_min;
            document.getElementById('stealthDelayMax').value = status.delay_max;
            document.getElementById('stealthRandomizeUA').checked = status.randomize_ua;

            // UIの表示を更新
            const body = document.getElementById('stealthBody');
            const panel = document.getElementById('stealthPanel');
            body.style.display = status.enabled ? 'block' : 'none';
            panel.classList.toggle('stealth-enabled', status.enabled);
            updateStealthUI(status);
            updateDelayLabel();
        }
    } catch (e) { }
}

// ページ読み込み時にステルス設定を取得
loadStealthStatus();

// ========== ステルス実効性モニター ==========

let stealthVerifyTimer = null;

/**
 * 「検証」ボタンクリック時に手動で検証を実行
 */
async function verifyStealthNow() {
    const btn = document.getElementById('stealthVerifyBtn');
    btn.classList.add('verifying');
    btn.innerHTML = '<span class="verify-spinner">🔄</span> 検証中...';

    try {
        const response = await fetch('/api/stealth/verify');
        if (response.ok) {
            const data = await response.json();
            updateStealthMonitor(data);
        }
    } catch (e) {
        console.error('ステルス検証エラー:', e);
    } finally {
        btn.classList.remove('verifying');
        btn.innerHTML = '🔍 検証';
    }
}

/**
 * ステルスモニターのインジケーターとフル詳細を更新する
 */
function updateStealthMonitor(data) {
    // --- シンプルインジケーター更新 ---

    // プロキシ接続
    updateIndicator('indProxy', data.proxy_reachable, '接続OK', '未接続');

    // IP秘匿
    updateIndicator('indExitIp', data.ip_hidden,
        data.exit_ip ? data.exit_ip.substring(0, 12) + (data.exit_ip.length > 12 ? '…' : '') : 'OK',
        '露出'
    );

    // User-Agent
    const uaShort = data.current_ua ? data.current_ua.substring(0, 15) + '…' : '—';
    const indUA = document.getElementById('indUA');
    if (indUA) {
        const statusEl = indUA.querySelector('.ind-status');
        statusEl.textContent = uaShort;
        statusEl.className = 'ind-status ind-ok';
        indUA.className = 'stealth-ind ind-state-ok';
        indUA.title = 'User-Agent: ' + (data.current_ua || '—');
    }

    // リクエスト遅延
    const indDelay = document.getElementById('indDelay');
    if (indDelay) {
        const statusEl = indDelay.querySelector('.ind-status');
        statusEl.textContent = data.delay_range || '—';
        statusEl.className = 'ind-status ind-ok';
        indDelay.className = 'stealth-ind ind-state-ok';
    }

    // DNS保護
    updateIndicator('indDNS', data.dns_protected, '有効', '無効');

    // --- フル詳細パネル更新 ---
    setText('detailProxy', data.proxy_reachable ? '✅ 接続成功' : '❌ 未接続');
    setColor('detailProxy', data.proxy_reachable);

    setText('detailExitIp', data.exit_ip || '取得失敗');
    setColor('detailExitIp', !!data.exit_ip);

    setText('detailDirectIp', data.direct_ip || '取得失敗');

    setText('detailUA', data.current_ua || '—');

    setText('detailDelay', data.delay_range || '—');

    setText('detailDNS', data.dns_protected ? '✅ 有効（rdns=True）' : '❌ 無効');
    setColor('detailDNS', data.dns_protected);

    // 検証時刻
    if (data.checked_at) {
        const t = new Date(data.checked_at);
        setText('detailCheckedAt', t.toLocaleTimeString('ja-JP'));
    }

    // エラー表示
    const errorEl = document.getElementById('monitorError');
    if (data.error) {
        errorEl.style.display = 'block';
        errorEl.textContent = '⚠️ ' + data.error;
    } else {
        errorEl.style.display = 'none';
    }
}

/**
 * 個別インジケーターを更新するヘルパー関数
 */
function updateIndicator(id, isOk, okText, failText) {
    const el = document.getElementById(id);
    if (!el) return;
    const statusEl = el.querySelector('.ind-status');
    if (isOk) {
        statusEl.textContent = okText;
        statusEl.className = 'ind-status ind-ok';
        el.className = 'stealth-ind ind-state-ok';
    } else {
        statusEl.textContent = failText;
        statusEl.className = 'ind-status ind-fail';
        el.className = 'stealth-ind ind-state-fail';
    }
}

/**
 * テキスト設定ヘルパー
 */
function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

/**
 * 色設定ヘルパー（OK=緑 / NG=赤）
 */
function setColor(id, isOk) {
    const el = document.getElementById(id);
    if (el) {
        el.style.color = isOk ? 'var(--accent-primary)' : 'var(--accent-red)';
    }
}

/**
 * フル詳細パネルの表示/非表示を切り替える
 */
function toggleStealthMonitorDetail() {
    const detail = document.getElementById('stealthMonitorDetail');
    if (detail) {
        detail.style.display = detail.style.display === 'none' ? 'flex' : 'none';
    }
}

/**
 * ステルスモード有効時に自動ポーリングを開始（30秒間隔）
 */
function startStealthMonitorPolling() {
    stopStealthMonitorPolling();
    // 初回検証
    verifyStealthNow();
    // 30秒ごとにポーリング
    stealthVerifyTimer = setInterval(verifyStealthNow, 30000);
}

/**
 * ポーリングを停止する
 */
function stopStealthMonitorPolling() {
    if (stealthVerifyTimer) {
        clearInterval(stealthVerifyTimer);
        stealthVerifyTimer = null;
    }
}

// ========== テーマ切り替え（ダークモード/ライトモード） ==========

/**
 * テーマの初期化（ページ読み込み時に呼ばれる）
 * localStorageに保存されたテーマを復元するか、デフォルト（dark）を適用
 */
function initTheme() {
    const savedTheme = localStorage.getItem('ipscan-theme') || 'dark';
    applyTheme(savedTheme, false); // 初回はアニメーションなし
}

/**
 * テーマのトグル（ボタンクリック時に呼ばれる）
 */
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    applyTheme(newTheme, true); // アニメーションあり
}

/**
 * テーマを実際に適用する
 * @param {string} theme - 'dark' または 'light'
 * @param {boolean} animate - トランジションアニメーションを有効にするか
 */
function applyTheme(theme, animate) {
    const html = document.documentElement;

    // アニメーション有効時はトランジションクラスを付与
    if (animate) {
        html.classList.add('theme-transitioning');
        setTimeout(() => {
            html.classList.remove('theme-transitioning');
        }, 500);
    }

    // data-theme属性を設定
    html.setAttribute('data-theme', theme);

    // アイコンを更新（ダーク→月、ライト→太陽）
    const themeIcon = document.getElementById('themeIcon');
    if (themeIcon) {
        themeIcon.textContent = theme === 'dark' ? '🌙' : '☀️';
    }

    // タイトル属性を更新
    const themeBtn = document.getElementById('themeToggleBtn');
    if (themeBtn) {
        themeBtn.title = theme === 'dark' ? 'ライトモードに切り替え' : 'ダークモードに切り替え';
    }

    // Leafletマップのタイルレイヤーをテーマに合わせて切り替え
    updateMapTileLayer(theme);

    // localStorageに保存
    localStorage.setItem('ipscan-theme', theme);
}

/**
 * Leafletマップのタイルレイヤーをテーマに応じて切り替え
 * @param {string} theme - 'dark' または 'light'
 */
let currentTileLayer = null;

function updateMapTileLayer(theme) {
    if (!threatMap) return;

    // 既存タイルレイヤーを削除
    if (currentTileLayer) {
        threatMap.removeLayer(currentTileLayer);
    }

    // テーマに応じたタイルURLを選択
    const tileUrl = theme === 'light'
        ? 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'
        : 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';

    currentTileLayer = L.tileLayer(tileUrl, {
        attribution: '&copy; CARTO',
        subdomains: 'abcd',
        maxZoom: 20
    }).addTo(threatMap);
}

// ページ読み込み時にテーマを初期化
initTheme();
