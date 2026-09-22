// Preset Raw Logs from Perimeter Devices
const PRESETS = {
    palo_alto: '<134>1,2026/09/22 18:00:15,001801000001,TRAFFIC,drop,1,2026/09/22 18:00:15,198.51.100.42,10.0.1.50,198.51.100.42,10.0.1.50,BLOCK_SUSPICIOUS,,,web-browsing,vsys1,untrust,trust,ethernet1/1,ethernet1/2,default,2026/09/22 18:00:15,14205,1,54123,80,54123,80,0x0,tcp,deny,64,64,0,1,2026/09/22 18:00:15,0,any',
    cisco_built: '<166>Sep 22 18:01:05 firewall-edge-01 %ASA-6-302013: Built outbound TCP connection 987654 for outside:198.51.100.20/443 (198.51.100.20/443) to inside:192.168.1.100/54321 (192.168.1.100/54321)',
    cisco_deny: '<164>Sep 22 18:01:10 firewall-edge-01 %ASA-4-106023: Deny tcp src outside:203.0.113.50/51234 dst inside:192.168.1.10/22 by access-group "OUTSIDE_IN" [0x0, 0x0]',
    fortinet: '<189>date=2026-09-22 time=18:02:22 devname="FGT-EDGE-01" devid="FG60E12345" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.45 srcport=49823 srcintf="port1" dstip=104.16.24.1 dstport=443 dstintf="wan1" proto=6 action="accept" policyid=1 app="HTTPS" sentbyte=2450 rcvdbyte=8120 duration=45',
    suricata: '{"timestamp":"2026-09-22T18:03:00.000123+0000","flow_id":981273412,"event_type":"alert","src_ip":"194.26.29.112","src_port":44122,"dest_ip":"10.0.0.15","dest_port":23,"proto":"TCP","app_proto":"telnet","alert":{"action":"blocked","gid":1,"signature_id":2010935,"rev":2,"signature":"ET SCAN Mirai Botnet Telnet Scan","category":"Attempted Information Leak","severity":1},"flow":{"pkts_toserver":3,"pkts_toclient":0,"bytes_toserver":180,"bytes_toclient":0}}',
    pfsense: '<134>Sep 22 18:04:12 pfsense filterlog: 4,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,45.33.32.156,192.168.1.1,51234,443',
    zeek: '1727028252.123456\tC7xK891mNk8\t192.168.1.120\t49200\t8.8.8.8\t53\tudp\tdns\t0.012\t64\t128\tSF\tT\tF\t0\tDd\t1\t92\t1\t156\t-',
    cef: 'CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|drop|Drop packet|High|src=185.220.101.5 dst=10.0.0.22 spt=44123 dpt=22 proto=6 act=drop in=0 out=0 app=ssh',
    leef: 'LEEF:2.0|Imperva|SecureSphere|14.0|SECURITY_ALERT|src=203.0.113.19 srcPort=50122 dst=10.0.2.10 dstPort=80 proto=TCP action=block sev=Critical totalBytes=3200'
};

let cachedStreamRecords = [];
let currentEventData = null;

// ==========================================
// Theme Management (Light & Dark)
// ==========================================
function initTheme() {
    const savedTheme = localStorage.getItem('ulpf-theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    } else {
        const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
    }
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('ulpf-theme', newTheme);
}

// ==========================================
// Preset & Input Handling
// ==========================================
function selectPreset(presetKey) {
    // Highlight chip
    document.querySelectorAll('.preset-chips .chip').forEach(btn => btn.classList.remove('active'));
    const clickedBtn = event && event.target;
    if (clickedBtn && clickedBtn.classList.contains('chip')) {
        clickedBtn.classList.add('active');
    }

    const raw = PRESETS[presetKey];
    if (raw) {
        document.getElementById('raw-log-input').value = raw;
        processCurrentLog();
    }
}

function clearInput() {
    document.getElementById('raw-log-input').value = '';
    document.getElementById('raw-log-input').focus();
}

// ==========================================
// Tab Switching
// ==========================================
function switchTab(tabId) {
    document.querySelectorAll('.tab-item').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(content => content.classList.remove('active'));

    const tabButtons = document.querySelectorAll('.tab-item');
    if (tabId === 'tab-summary') tabButtons[0].classList.add('active');
    if (tabId === 'tab-ocsf') tabButtons[1].classList.add('active');
    if (tabId === 'tab-lineage') tabButtons[2].classList.add('active');
    if (tabId === 'tab-ml') tabButtons[3].classList.add('active');
    if (tabId === 'tab-unmapped') tabButtons[4].classList.add('active');

    const pane = document.getElementById(tabId);
    if (pane) pane.classList.add('active');
}

// ==========================================
// API Interaction & Normalization
// ==========================================
async function processCurrentLog() {
    const input = document.getElementById('raw-log-input').value.trim();
    if (!input) return;

    const btn = document.getElementById('btn-process');
    btn.disabled = true;
    btn.innerHTML = `<span class="detect-pulse"></span> Processing...`;

    try {
        const response = await fetch('/api/v1/process', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ raw_log: input })
        });

        if (!response.ok) {
            showToast('Error processing event: ' + (await response.text()));
            return;
        }

        const data = await response.json();
        currentEventData = data;
        renderResults(data);
        fetchTelemetry();
        fetchRecentEvents();

    } catch (err) {
        console.error('Processing failed', err);
        showToast('Network error processing event');
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
            Normalize &amp; Process Log
        `;
    }
}

// ==========================================
// Render Visual & Standardized Results
// ==========================================
function renderResults(data) {
    const event = data.event;

    // 1. Auto-Detection Pill
    const pill = document.getElementById('detection-pill');
    const parserName = document.getElementById('detected-parser-name');
    pill.style.display = 'inline-flex';
    parserName.innerText = `Detected: ${event.product.vendor_name} (${event.lineage.parser_id})`;

    // 2. Tab 1: Human-Friendly Visual Summary
    document.getElementById('summary-empty').style.display = 'none';
    document.getElementById('summary-content').style.display = 'block';

    const action = event.disposition || 'Unknown';
    const isAllowed = action === 'Allowed';
    const verdictAction = document.getElementById('verdict-action');
    verdictAction.innerText = action;
    verdictAction.className = `verdict-tag ${isAllowed ? 'act-allowed' : 'act-blocked'}`;

    // Direction & Scope
    const dir = event.connection_info.direction || 'Unknown';
    document.getElementById('verdict-direction').innerText = `Flow Direction: ${dir}`;

    const sev = event.severity || 'Informational';
    document.getElementById('verdict-severity').innerText = `${sev} Severity`;

    // Endpoints
    document.getElementById('summary-src-ip').innerText = event.src_endpoint.ip || '0.0.0.0';
    document.getElementById('summary-src-port').innerText = event.src_endpoint.port || '—';
    const srcScope = event.src_endpoint.is_internal ? 'Internal LAN' : (event.src_endpoint.country || 'Public');
    document.getElementById('summary-src-scope').innerText = srcScope;

    document.getElementById('summary-dst-ip').innerText = event.dst_endpoint.ip || '0.0.0.0';
    document.getElementById('summary-dst-port').innerText = event.dst_endpoint.port || '—';
    const dstScope = event.dst_endpoint.is_internal ? 'Internal LAN' : (event.dst_endpoint.country || 'Public');
    const dstBadge = document.getElementById('summary-dst-scope');
    dstBadge.innerText = dstScope;
    dstBadge.className = `flow-badge ${event.dst_endpoint.is_internal ? '' : 'flow-badge-public'}`;

    document.getElementById('summary-proto').innerText = (event.connection_info.protocol_name || 'IP').toUpperCase();
    
    // Bytes formatting
    const totalBytes = event.traffic.total_bytes || (event.traffic.bytes_in + event.traffic.bytes_out) || 0;
    const bytesFormatted = totalBytes > 1024 ? `${(totalBytes / 1024).toFixed(1)} KB` : `${totalBytes} B`;
    document.getElementById('summary-bytes').innerText = bytesFormatted;

    document.getElementById('summary-vendor').innerText = `${event.product.vendor_name} (${event.product.product_name})`;
    document.getElementById('summary-app').innerText = event.app_name || 'Standard Network Traffic';
    
    const durationMs = event.traffic.duration_ms || 0;
    document.getElementById('summary-duration').innerText = `${(durationMs / 1000).toFixed(2)} seconds (${durationMs} ms)`;

    const threatEl = document.getElementById('summary-threat');
    if (event.threat && event.threat.signature_name) {
        threatEl.innerHTML = `<span style="color:var(--danger); font-weight:700;">🚨 ${event.threat.signature_name}</span>`;
    } else {
        threatEl.innerHTML = `<span style="color:var(--success); font-weight:600;">Clean (No Threats Detected)</span>`;
    }

    // 3. Tab 2: OCSF JSON
    document.getElementById('code-ocsf').innerText = JSON.stringify(event, null, 2);

    // 4. Tab 3: Forensic Lineage & SHA-256
    const verified = data.integrity_verified;
    document.getElementById('lineage-summary').innerHTML = `
        <div class="lineage-card">
            <div class="lineage-title">Cryptographic SHA-256 Fingerprint (Forensic Hash)</div>
            <div class="lineage-hash">${event.lineage.raw_hash}</div>
            <div class="verified-seal" style="background:${verified ? 'var(--success-bg)' : 'var(--danger-bg)'}; color:${verified ? 'var(--success)' : 'var(--danger)'};">
                ${verified ? '✔ VERIFIED: Raw payload perfectly matches cryptographic checksum (Tamper-Evident)' : '✖ TAMPER WARNING'}
            </div>
        </div>
        <div class="lineage-card">
            <div class="lineage-title">Lineage Metadata &amp; Provenance</div>
            <p style="font-size:0.8rem; color:var(--text-secondary); margin-bottom:0.25rem;">
                <strong>Event UUID:</strong> <code>${event.lineage.event_id}</code>
            </p>
            <p style="font-size:0.8rem; color:var(--text-secondary); margin-bottom:0.25rem;">
                <strong>Schema Spec:</strong> <code>${event.lineage.schema_version}</code> &bull; <strong>Parser:</strong> <code>${event.lineage.parser_id} (v${event.lineage.parser_version})</code>
            </p>
            <p style="font-size:0.8rem; color:var(--text-secondary);">
                <strong>Processing Latency:</strong> <code>${event.lineage.processing_latency_ms} ms</code>
            </p>
        </div>
    `;

    // 5. Tab 4: AI/ML Feature Vector
    const feats = data.features;
    let mlCards = '<div class="ml-grid-layout">';
    for (const [k, v] of Object.entries(feats)) {
        mlCards += `
            <div class="ml-metric-pill">
                <span class="ml-k">${k}</span>
                <span class="ml-v">${v}</span>
            </div>
        `;
    }
    mlCards += '</div>';
    mlCards += `
        <div style="margin-top: 1rem;">
            <span style="font-size:0.75rem; color:var(--text-muted); display:block; margin-bottom:0.35rem;">
                Numerical Feature Vector [${data.ml_vector.length} dimensions ready for XGBoost / Isolation Forests]:
            </span>
            <pre class="code-box"><code>${JSON.stringify(data.ml_vector)}</code></pre>
        </div>
    `;
    document.getElementById('ml-container').innerHTML = mlCards;

    // 6. Tab 5: Unmapped Attributes (0% Data Loss)
    const unmappedCode = document.getElementById('code-unmapped');
    const unmappedKeys = Object.keys(event.unmapped || {});
    if (unmappedKeys.length === 0) {
        unmappedCode.innerText = '// All extracted vendor fields mapped 100% cleanly into the canonical OCSF v1.2 standard schema!';
    } else {
        unmappedCode.innerText = JSON.stringify(event.unmapped, null, 2);
    }
}

// ==========================================
// Copy to Clipboard with Toast
// ==========================================
function copyActiveOutput() {
    if (!currentEventData) {
        showToast('No processed event to copy yet');
        return;
    }

    const activeTab = document.querySelector('.tab-pane.active');
    let textToCopy = '';
    if (activeTab.id === 'tab-ocsf') {
        textToCopy = JSON.stringify(currentEventData.event, null, 2);
    } else if (activeTab.id === 'tab-ml') {
        textToCopy = JSON.stringify(currentEventData.ml_vector);
    } else if (activeTab.id === 'tab-unmapped') {
        textToCopy = JSON.stringify(currentEventData.event.unmapped, null, 2);
    } else if (activeTab.id === 'tab-lineage') {
        textToCopy = currentEventData.event.lineage.raw_hash;
    } else {
        textToCopy = JSON.stringify(currentEventData.event, null, 2);
    }

    navigator.clipboard.writeText(textToCopy).then(() => {
        showToast('Copied to clipboard!');
    }).catch(() => {
        showToast('Failed to copy');
    });
}

function showToast(msg) {
    const toast = document.getElementById('toast');
    toast.innerText = msg;
    toast.style.display = 'block';
    setTimeout(() => { toast.style.display = 'none'; }, 2200);
}

// ==========================================
// Educational Modal Toggle
// ==========================================
function toggleHelpModal() {
    const modal = document.getElementById('help-modal');
    modal.style.display = modal.style.display === 'none' ? 'flex' : 'none';
}

// ==========================================
// Data Lake & Live Feed Management
// ==========================================
async function loadSampleDataset() {
    try {
        const res = await fetch('/api/v1/load-samples', { method: 'POST' });
        const data = await res.json();
        showToast(`Loaded ${data.ingested_events} multi-vendor fleet events!`);
        fetchTelemetry();
        fetchRecentEvents();
    } catch (err) {
        showToast('Failed to load sample dataset');
    }
}

async function fetchTelemetry() {
    try {
        const res = await fetch('/api/v1/telemetry');
        const data = await res.json();
        document.getElementById('stat-total').innerText = data.total_processed.toLocaleString();
        document.getElementById('stat-latency').innerText = `${data.average_latency_ms} ms`;
    } catch (e) {}

    try {
        const res2 = await fetch('/api/v1/parsers');
        const data2 = await res2.json();
        document.getElementById('stat-parsers').innerText = `${data2.count} Available`;
    } catch (e) {}
}

async function fetchRecentEvents() {
    try {
        const res = await fetch('/api/v1/events?limit=40');
        const data = await res.json();
        cachedStreamRecords = data.records || [];
        renderStreamTable(cachedStreamRecords);
    } catch (e) {
        console.error('Error fetching stream', e);
    }
}

function filterStreamTable() {
    const q = document.getElementById('stream-search').value.toLowerCase().trim();
    if (!q) {
        renderStreamTable(cachedStreamRecords);
        return;
    }
    const filtered = cachedStreamRecords.filter(r => 
        (r.vendor && r.vendor.toLowerCase().includes(q)) ||
        (r.action && r.action.toLowerCase().includes(q)) ||
        (r.src_ip && r.src_ip.includes(q)) ||
        (r.dst_ip && r.dst_ip.includes(q)) ||
        (r.protocol && r.protocol.toLowerCase().includes(q))
    );
    renderStreamTable(filtered);
}

function renderStreamTable(records) {
    const tbody = document.getElementById('stream-tbody');
    if (!records || records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-table">No logs matching filter.</td></tr>`;
        return;
    }

    tbody.innerHTML = records.map(r => {
        const isAllowed = r.action === 'Allowed';
        const badgeClass = isAllowed ? 'status-allowed' : 'status-blocked';
        const shortHash = (r.raw_hash || '').substring(0, 12) + '...';
        return `
            <tr>
                <td><span class="badge-status ${badgeClass}">${r.action || 'Unknown'}</span></td>
                <td><span style="color:var(--text-secondary);">${r.severity || 'Informational'}</span></td>
                <td><strong>${r.vendor || 'Generic'}</strong> <span style="color:var(--text-muted);">${r.product || ''}</span></td>
                <td>${r.src_ip || '—'}:${r.src_port || '—'}</td>
                <td>${r.dst_ip || '—'}:${r.dst_port || '—'}</td>
                <td><span style="color:var(--primary); font-weight:700;">${r.protocol || '—'}</span></td>
                <td title="${r.raw_hash}"><span style="color:var(--text-muted);">${shortHash}</span></td>
            </tr>
        `;
    }).join('');
}

// Initial Boot
window.addEventListener('DOMContentLoaded', () => {
    initTheme();
    fetchTelemetry();
    fetchRecentEvents();
    selectPreset('palo_alto');
    setInterval(fetchTelemetry, 6000);
});
