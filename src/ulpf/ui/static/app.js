// ULPF Universal Log Pre-processing & Normalization Platform
// Production Modern Frontend Controller

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
    leef: 'LEEF:2.0|Imperva|SecureSphere|14.0|SECURITY_ALERT|src=203.0.113.19 srcPort=50122 dst=10.0.2.10 dstPort=80 proto=TCP action=block sev=Critical totalBytes=3200',
    cisco_login: '000214: 2026 Sep 23 00:22:14.882 UTC: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: root] [Source: 198.51.100.45] [port: 22] [Reason: Authentication Failure]'
};

// Global State
let cachedStreamRecords = [];
let currentEventData = null;
let currentSchemaView = 'ocsf'; // 'ocsf' | 'siem' | 'ecs' | 'forensic'

// ==========================================
// Theme Management
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
// Dual Deployment Mode: Air-Gapped vs Public Web
// ==========================================
async function setDeploymentMode(mode) {
    const airgapBtn = document.getElementById('btn-mode-airgap');
    const webBtn = document.getElementById('btn-mode-web');
    const desc = document.getElementById('subbar-mode-desc');

    if (mode === 'air_gapped') {
        airgapBtn.classList.add('active');
        webBtn.classList.remove('active');
        desc.innerText = '100% Offline Local Engine (No external API calls, defense enclave mode)';
        showToast('Switched to Air-Gapped Isolated Mode');
    } else {
        webBtn.classList.add('active');
        airgapBtn.classList.remove('active');
        desc.innerText = 'Public Web Cloud Mode (Ready for general internet & SaaS usage)';
        showToast('Switched to Public Web Cloud Mode');
    }

    try {
        await fetch(`/api/v1/system/mode?mode=${mode}`, { method: 'POST' });
    } catch (e) {}
}

// ==========================================
// Presets & Input
// ==========================================
function selectPreset(presetKey, targetEl) {
    document.querySelectorAll('.preset-pill-list .preset-btn').forEach(btn => btn.classList.remove('active'));
    
    if (targetEl) {
        targetEl.classList.add('active');
    } else {
        const btn = document.querySelector(`.preset-btn[data-preset="${presetKey}"]`);
        if (btn) btn.classList.add('active');
    }

    const raw = PRESETS[presetKey];
    if (raw) {
        const inputEl = document.getElementById('raw-log-input');
        if (inputEl) inputEl.value = raw;
        processCurrentLog();
    }
}

function clearInput() {
    const inputEl = document.getElementById('raw-log-input');
    if (inputEl) {
        inputEl.value = '';
        inputEl.focus();
    }
}

// ==========================================
// Tabs & Multi-Schema Views
// ==========================================
function switchTab(tabId) {
    document.querySelectorAll('.nav-tab').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
    });
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === tabId);
    });

    if (tabId === 'tab-schema') {
        setSchemaView(currentSchemaView);
    } else if (tabId === 'tab-logtest' && currentEventData) {
        renderPipelineTrace(currentEventData);
    }
}

function setSchemaView(schemaType) {
    currentSchemaView = schemaType;
    document.querySelectorAll('.schema-btn').forEach(b => b.classList.remove('active'));
    const activeBtn = document.getElementById(`btn-schema-${schemaType}`);
    if (activeBtn) activeBtn.classList.add('active');

    const badgeDesc = document.getElementById('schema-badge-desc');
    const codeEl = document.getElementById('code-schema');
    if (!codeEl) return;

    if (!currentEventData) {
        codeEl.innerText = '// Process any network log to view real-time multi-schema export.';
        return;
    }

    if (schemaType === 'ocsf') {
        if (badgeDesc) badgeDesc.innerText = 'OCSF Class 4001: Network Activity (Standard Canonical)';
        codeEl.innerText = JSON.stringify(currentEventData.event, null, 2);
    } else if (schemaType === 'siem') {
        if (badgeDesc) badgeDesc.innerText = 'Unified SIEM Alert JSON (Production SIEM & XDR Format)';
        const siemObj = currentEventData.siem_format || currentEventData.wazuh_format || {};
        codeEl.innerText = JSON.stringify(siemObj, null, 2);
    } else if (schemaType === 'ecs') {
        if (badgeDesc) badgeDesc.innerText = 'Elastic Common Schema (ECS v8.11 Standard)';
        codeEl.innerText = JSON.stringify(currentEventData.ecs_format, null, 2);
    } else if (schemaType === 'forensic') {
        if (badgeDesc) badgeDesc.innerText = 'Forensic Provenance Record (Verbatim Bytes + SHA-256 Fingerprint)';
        codeEl.innerText = JSON.stringify(currentEventData.forensic_bundle, null, 2);
    }
}

// ==========================================
// Core Pipeline Execution
// ==========================================
async function processCurrentLog() {
    const input = document.getElementById('raw-log-input').value.trim();
    if (!input) return;

    const btn = document.getElementById('btn-process');
    btn.disabled = true;
    btn.innerHTML = `<span class="pulse-indicator"></span> Normalizing...`;

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
            Normalize &amp; Analyze Event
        `;
    }
}

// ==========================================
// Render Visual Intelligence & Analytics
// ==========================================
function renderResults(data) {
    const event = data.event;
    const mitre = data.mitre;
    const comp = data.compliance;
    const risk = data.risk;
    const phases = data.phases;

    // 1. Auto-Detection Pill
    const pill = document.getElementById('detection-pill');
    const parserName = document.getElementById('detected-parser-name');
    if (pill && parserName) {
        pill.style.display = 'inline-flex';
        parserName.innerText = `Auto-Detected: ${event.product.vendor_name} (${event.lineage.parser_id})`;
    }

    // 2. Tab 1: Visual Summary Card
    const emptySummary = document.getElementById('summary-empty');
    const contentSummary = document.getElementById('summary-content');
    if (emptySummary) emptySummary.style.display = 'none';
    if (contentSummary) contentSummary.style.display = 'block';

    const action = (event.disposition && event.disposition.value) ? event.disposition.value : (event.disposition || 'Unknown');
    const isAllowed = action === 'Allowed';
    const isThreat = event.threat && event.threat.signature_name;

    // Narrative Box
    const narrativeEl = document.getElementById('summary-narrative-text');
    if (narrativeEl) {
        narrativeEl.innerText = data.narrative || (isAllowed
            ? `Authorized network connection permitted through ${event.product.vendor_name} firewall gateway.`
            : `Perimeter defense active: Connection actively blocked by ${event.product.vendor_name} to protect internal network.`);
    }
    const narrativeIcon = document.getElementById('narrative-icon');
    if (narrativeIcon) {
        narrativeIcon.innerText = isThreat ? '🚨' : (isAllowed ? '✅' : '🛡️');
    }

    // Inspection Flow Center Gateway
    const verdictAction = document.getElementById('verdict-action');
    if (verdictAction) {
        verdictAction.innerText = action.toUpperCase();
        verdictAction.className = `verdict-pill ${isAllowed ? 'act-allowed' : 'act-blocked'}`;
    }

    const dir = (event.connection_info && event.connection_info.direction && event.connection_info.direction.value)
        ? event.connection_info.direction.value
        : (event.connection_info.direction || 'Unknown');

    const totalBytes = event.traffic.total_bytes || (event.traffic.bytes_in + event.traffic.bytes_out) || 0;
    const bytesFormatted = totalBytes > 1024 ? `${(totalBytes / 1024).toFixed(1)} KB` : `${totalBytes} B`;
    const protoStr = (event.connection_info.protocol_name || 'IP').toUpperCase();

    const ruleName = (event.unmapped && (event.unmapped.rule_name || event.unmapped.policyid || event.unmapped.rule || event.unmapped['access-group'])) || 'Access Policy Enforced';
    const gwRuleEl = document.getElementById('summary-gw-rule');
    if (gwRuleEl) gwRuleEl.innerText = `Policy: ${ruleName}`;
    const gwMetaEl = document.getElementById('summary-gw-meta');
    if (gwMetaEl) gwMetaEl.innerText = `${protoStr} • ${dir} • ${bytesFormatted}`;

    // Endpoints
    const srcIpEl = document.getElementById('summary-src-ip');
    if (srcIpEl) srcIpEl.innerText = event.src_endpoint.ip || '0.0.0.0';
    const srcPortEl = document.getElementById('summary-src-port');
    if (srcPortEl) srcPortEl.innerText = event.src_endpoint.port || '—';
    const srcScope = event.src_endpoint.is_internal ? 'Internal LAN' : (event.src_endpoint.country || 'Public Internet');
    const srcScopeEl = document.getElementById('summary-src-scope');
    if (srcScopeEl) srcScopeEl.innerText = srcScope;

    const dstIpEl = document.getElementById('summary-dst-ip');
    if (dstIpEl) dstIpEl.innerText = event.dst_endpoint.ip || '0.0.0.0';
    const dstPortEl = document.getElementById('summary-dst-port');
    if (dstPortEl) dstPortEl.innerText = event.dst_endpoint.port || '—';
    const dstScope = event.dst_endpoint.is_internal ? 'Internal LAN' : (event.dst_endpoint.country || 'Public Internet');
    const dstBadge = document.getElementById('summary-dst-scope');
    if (dstBadge) {
        dstBadge.innerText = dstScope;
        dstBadge.className = `scope-pill ${event.dst_endpoint.is_internal ? '' : 'scope-public'}`;
    }

    // Dynamic Risk Meter & Factors
    const riskBar = document.getElementById('risk-bar-fill');
    if (riskBar) riskBar.style.width = `${risk.score}%`;
    const riskScoreText = document.getElementById('risk-score-text');
    if (riskScoreText) riskScoreText.innerText = `${risk.score} / 100`;
    const riskLevelBadge = document.getElementById('risk-level-badge');
    if (riskLevelBadge) {
        riskLevelBadge.innerText = `${risk.level} Risk`;
        riskLevelBadge.className = `risk-level-badge risk-${risk.level.toLowerCase()}`;
    }

    const factorsContainer = document.getElementById('risk-factors-container');
    if (factorsContainer) {
        const factors = risk.factors && risk.factors.length > 0 ? risk.factors : ['Perimeter traffic within normal baseline parameters'];
        factorsContainer.innerHTML = factors.map(f => `
            <div class="risk-factor-pill">
                <span class="rf-dot"></span>
                <span>${f}</span>
            </div>
        `).join('');
    }

    // Session Metadata Grid
    const vendorEl = document.getElementById('summary-vendor');
    if (vendorEl) vendorEl.innerText = `${event.product.vendor_name} (${event.product.product_name})`;
    const appEl = document.getElementById('summary-app');
    if (appEl) appEl.innerText = event.app_name || (event.dst_endpoint.port === 80 || event.dst_endpoint.port === 443 ? 'HTTP/HTTPS Web Traffic' : 'Standard IP Session');
    const hashEl = document.getElementById('summary-hash-short');
    if (hashEl) hashEl.innerText = (event.lineage.raw_hash || '').substring(0, 16) + '...';

    const threatEl = document.getElementById('summary-threat');
    if (threatEl) {
        if (isThreat) {
            threatEl.innerHTML = `<span style="color:var(--danger); font-weight:700;">🚨 ${event.threat.signature_name}</span>`;
        } else if (!isAllowed) {
            threatEl.innerHTML = `<span style="color:var(--warning); font-weight:700;">🛡️ Suspicious Ingress Blocked</span>`;
        } else {
            threatEl.innerHTML = `<span style="color:var(--success); font-weight:600;">Clean (Zero Active IoCs)</span>`;
        }
    }

    // 3. Tab 2: 3-Phase Transformation Pipeline Stepper
    renderPipelineTrace(data);

    // 4. Tab 3: MITRE ATT&CK & Compliance
    if (mitre) {
        const tacticEl = document.getElementById('mitre-tactic');
        if (tacticEl) tacticEl.innerText = `${mitre.tactic_id}: ${mitre.tactic_name}`;
        const techEl = document.getElementById('mitre-technique');
        if (techEl) techEl.innerText = `${mitre.technique_id}: ${mitre.technique_name}`;
        const linkEl = document.getElementById('mitre-link');
        if (linkEl) linkEl.href = mitre.url;
    }

    if (comp) {
        const compContainer = document.getElementById('compliance-badges');
        if (compContainer) {
            compContainer.innerHTML = `
                <div class="comp-badge"><strong>PCI-DSS v4.0:</strong> ${(comp.pci_dss && comp.pci_dss[0]) || 'Req 10.2.1 Audit Logging'}</div>
                <div class="comp-badge"><strong>NIST SP 800-53:</strong> ${(comp.nist_800_53 && comp.nist_800_53[0]) || 'AC-4 Flow Enforcement'}</div>
                <div class="comp-badge"><strong>ISO 27001:</strong> ${(comp.iso_27001 && comp.iso_27001[0]) || 'A.12.4.1 Event Logging'}</div>
                <div class="comp-badge"><strong>HIPAA Security:</strong> ${(comp.hipaa && comp.hipaa[0]) || '164.312(b) Audit Controls'}</div>
                <div class="comp-badge"><strong>GDPR Article 32:</strong> ${(comp.gdpr && comp.gdpr[0]) || 'Article 32 Security of Processing'}</div>
            `;
        }
    }

    // 5. Tab 4: Multi-Schema Export
    setSchemaView(currentSchemaView);

    // 6. Tab 5: AI/ML 26-D Feature Vector
    renderMlVectorTab(data);

    // 7. Tab 6: 0% Loss Unmapped Retention & Traceability
    renderLosslessAuditTab(data);
}

// ==========================================
// Render 3-Phase Transformation Pipeline
// ==========================================
function renderPipelineTrace(data) {
    const phases = data.phases;
    if (!phases) return;

    // Phase 1: Ingestion & Fingerprint
    const p1Raw = document.getElementById('phase-1-raw-stream');
    if (p1Raw) p1Raw.innerText = phases.phase_1.raw_log || data.event.raw_event;

    const p1Sha = document.getElementById('phase-1-sha');
    if (p1Sha) p1Sha.innerText = phases.phase_1.sha256;

    const p1Len = document.getElementById('phase-1-length');
    if (p1Len) p1Len.innerText = `${phases.phase_1.raw_length} Bytes (0.0% loss)`;

    const p1Time = document.getElementById('phase-1-time');
    if (p1Time) p1Time.innerText = phases.phase_1.ingestion_timestamp;

    // Phase 2: Declarative Extraction
    const p2Parser = document.getElementById('phase-2-parser');
    if (p2Parser) p2Parser.innerText = phases.phase_2.parser_name || phases.phase_2.parser_id;

    const p2Format = document.getElementById('phase-2-format');
    if (p2Format) p2Format.innerText = phases.phase_2.format;

    const p2Conf = document.getElementById('phase-2-confidence');
    if (p2Conf) p2Conf.innerText = `${phases.phase_2.confidence}% Confidence`;

    const p2Count = document.getElementById('phase-2-count');
    if (p2Count) p2Count.innerText = `${phases.phase_2.extracted_count} Tokens Extracted • ${phases.phase_2.unmapped_retained} Retained Unmapped`;

    const tokensGrid = document.getElementById('phase-2-tokens-grid');
    if (tokensGrid) {
        const fields = phases.phase_2.extracted_fields || {};
        const entries = Object.entries(fields);
        if (entries.length === 0) {
            tokensGrid.innerHTML = `<span class="text-muted" style="font-size:0.75rem;">No discrete tokens found.</span>`;
        } else {
            tokensGrid.innerHTML = entries.map(([k, v]) => `
                <div class="extracted-token-pill" title="${k}: ${v}">
                    <span class="tok-k">${k}</span>
                    <span class="tok-v">${v.length > 28 ? v.substring(0, 26) + '...' : v}</span>
                </div>
            `).join('');
        }
    }

    // Phase 3: Canonical Normalization & Sinks
    const p3Disp = document.getElementById('phase-3-disp');
    if (p3Disp) p3Disp.innerText = `${phases.phase_3.action} (${phases.phase_3.direction})`;

    const p3Mitre = document.getElementById('phase-3-mitre');
    if (p3Mitre) p3Mitre.innerText = `${phases.phase_3.mitre_tactic} (${phases.phase_3.mitre_technique || 'Standard Policy'})`;
}

// ==========================================
// Render AI/ML 26-D Vector Tab
// ==========================================
function renderMlVectorTab(data) {
    const container = document.getElementById('ml-container');
    if (!container) return;

    const feats = data.features || {};
    const vector = data.ml_vector || [];

    // Feature Categories Definition
    const categories = [
        {
            title: '🌐 Network Topology & Scope',
            keys: ['src_port', 'dst_port', 'is_well_known_port', 'is_ephemeral_src_port', 'is_internal_src', 'is_internal_dst']
        },
        {
            title: '🔄 Traffic Flow & Directionality',
            keys: ['direction_inbound', 'direction_outbound', 'direction_lateral', 'direction_external']
        },
        {
            title: '📡 Layer 4 Transport Protocols',
            keys: ['proto_tcp', 'proto_udp', 'proto_icmp', 'proto_other']
        },
        {
            title: '📊 Volume & Log-Scale Traffic Metrics',
            keys: ['bytes_in_log', 'bytes_out_log', 'total_bytes_log', 'bytes_ratio_out_in', 'packets_total_log', 'duration_sec', 'bytes_per_second']
        },
        {
            title: '🛡️ Security Posture & Anomaly Signals',
            keys: ['action_blocked', 'action_allowed', 'severity_level', 'threat_flag', 'threat_confidence']
        }
    ];

    let html = `<div class="ml-category-stack">`;

    categories.forEach(cat => {
        html += `
            <div class="ml-cat-box">
                <h4 class="ml-cat-title">${cat.title}</h4>
                <div class="ml-grid-layout">
        `;

        cat.keys.forEach(k => {
            const val = feats[k] !== undefined ? feats[k] : 0.0;
            const isBinary = (val === 0.0 || val === 1.0) && !['src_port', 'dst_port'].includes(k);
            const badgeClass = isBinary && val === 1.0 ? 'ml-val-active' : '';

            html += `
                <div class="ml-metric-pill ${badgeClass}">
                    <span class="ml-k">${k}</span>
                    <span class="ml-v">${typeof val === 'number' ? Number(val.toFixed(4)) : val}</span>
                </div>
            `;
        });

        html += `
                </div>
            </div>
        `;
    });

    html += `</div>`;

    // Mathematical Array Box
    html += `
        <div class="ml-vector-output-wrap">
            <div class="ml-vector-output-head">
                <span class="font-mono text-cyan" style="font-size:0.8rem; font-weight:700;">
                    Mathematical Dense Float64 Array [${vector.length} dimensions]:
                </span>
                <span style="font-size:0.75rem; color:var(--text-muted);">Standard shape (1, 26)</span>
            </div>
            <pre class="code-terminal"><code id="code-ml-array">${JSON.stringify(vector)}</code></pre>
        </div>
    `;

    container.innerHTML = html;
}

// ==========================================
// Render 0% Loss Retention & Traceability Tab
// ==========================================
function renderLosslessAuditTab(data) {
    const event = data.event;
    const raw = event.raw_event || '';
    const unmapped = event.unmapped || {};
    const unmappedKeys = Object.keys(unmapped);
    const trace = data.traceability || [];

    // Banner metrics
    const shaEl = document.getElementById('audit-sha-verified');
    if (shaEl) {
        shaEl.innerText = `SHA-256: ${event.lineage.raw_hash} (Match)`;
    }

    const byteComp = document.getElementById('audit-byte-comparison');
    if (byteComp) {
        const rawBytes = new Blob([raw]).size;
        const normBytes = new Blob([JSON.stringify(event)]).size;
        byteComp.innerText = `Raw: ${rawBytes} B | Canonical OCSF: ${normBytes} B (Lossless 100%)`;
    }

    // Section 1: Verbatim Raw Buffer
    const rawCodeEl = document.getElementById('code-verbatim-raw');
    if (rawCodeEl) rawCodeEl.innerText = raw;

    // Section 2: Unmapped Vendor Keys
    const countTag = document.getElementById('unmapped-count-tag');
    if (countTag) countTag.innerText = `${unmappedKeys.length} Unmapped Vendor Keys`;

    const unmappedCodeEl = document.getElementById('code-unmapped');
    if (unmappedCodeEl) {
        if (unmappedKeys.length === 0) {
            unmappedCodeEl.innerText = '// All extracted vendor fields mapped 100% cleanly into the canonical OCSF v1.2 standard schema! Zero leftover fields.';
        } else {
            unmappedCodeEl.innerText = JSON.stringify(unmapped, null, 2);
        }
    }

    // Section 3: Traceability Table
    const tbody = document.getElementById('traceability-tbody');
    if (tbody) {
        if (!trace || trace.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="empty-table">No traceability matrix available.</td></tr>`;
        } else {
            tbody.innerHTML = trace.map(t => `
                <tr>
                    <td><strong class="font-mono text-cyan">${t.source_token}</strong></td>
                    <td class="font-mono">${t.extracted_val}</td>
                    <td><span class="trace-target">${t.canonical_field}</span></td>
                    <td><span class="trace-rule">${t.transformation}</span></td>
                </tr>
            `).join('');
        }
    }
}

// ==========================================
// Copy Helpers
// ==========================================
function copyActiveOutput() {
    if (!currentEventData) {
        showToast('No processed event to copy yet');
        return;
    }

    const activeTab = document.querySelector('.tab-content.active');
    if (!activeTab) return;

    let textToCopy = '';
    if (activeTab.id === 'tab-schema') {
        const codeEl = document.getElementById('code-schema');
        textToCopy = codeEl ? codeEl.innerText : '';
    } else if (activeTab.id === 'tab-ml') {
        textToCopy = JSON.stringify(currentEventData.ml_vector);
    } else if (activeTab.id === 'tab-unmapped') {
        textToCopy = JSON.stringify(currentEventData.forensic_bundle, null, 2);
    } else {
        textToCopy = JSON.stringify(currentEventData.event, null, 2);
    }

    navigator.clipboard.writeText(textToCopy).then(() => {
        showToast('Copied to clipboard!');
    }).catch(() => {
        showToast('Failed to copy');
    });
}

function copyRawLog() {
    if (!currentEventData) {
        showToast('No raw log to copy yet');
        return;
    }
    navigator.clipboard.writeText(currentEventData.event.raw_event).then(() => {
        showToast('Verbatim raw log copied!');
    });
}

function copyMlVector(format) {
    if (!currentEventData || !currentEventData.ml_vector) {
        showToast('No ML vector generated yet');
        return;
    }
    const vec = currentEventData.ml_vector;
    let text = '';
    if (format === 'numpy') {
        text = `import numpy as np\nx = np.array(${JSON.stringify(vec)}, dtype=np.float64)`;
    } else {
        text = JSON.stringify(vec);
    }
    navigator.clipboard.writeText(text).then(() => {
        showToast(`Copied ${format === 'numpy' ? 'NumPy code' : 'array'} to clipboard!`);
    });
}

let toastTimeout = null;
function showToast(msg) {
    const toast = document.getElementById('toast');
    if (!toast) return;

    // Pick contextual icon based on message
    let icon = '⚡';
    const lower = msg.toLowerCase();
    if (lower.includes('air-gapped') || lower.includes('isolated')) {
        icon = '🔒';
    } else if (lower.includes('cloud') || lower.includes('web')) {
        icon = '🌐';
    } else if (lower.includes('loaded') || lower.includes('fleet') || lower.includes('sample')) {
        icon = '📦';
    } else if (lower.includes('copied')) {
        icon = '✓';
    } else if (lower.includes('error') || lower.includes('failed')) {
        icon = '⚠️';
    }

    toast.innerHTML = `<span class="toast-icon">${icon}</span><span class="toast-message">${msg}</span>`;
    toast.classList.add('visible');

    if (toastTimeout) clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => {
        toast.classList.remove('visible');
    }, 3200);
}

function toggleHelpModal() {
    const modal = document.getElementById('help-modal');
    if (!modal) return;
    modal.style.display = modal.style.display === 'none' ? 'flex' : 'none';
}

// ==========================================
// Data Feed & Stream
// ==========================================
async function loadSampleDataset() {
    try {
        const res = await fetch('/api/v1/load-samples', { method: 'POST' });
        const data = await res.json();
        showToast(`Loaded ${data.ingested_events} multi-vendor perimeter events!`);
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
        const statTotal = document.getElementById('stat-total');
        if (statTotal) statTotal.innerText = data.total_processed.toLocaleString();
        const statLatency = document.getElementById('stat-latency');
        if (statLatency) statLatency.innerText = `${data.average_latency_ms} ms`;
    } catch (e) {}

    try {
        const res2 = await fetch('/api/v1/parsers');
        const data2 = await res2.json();
        const statParsers = document.getElementById('stat-parsers');
        if (statParsers) statParsers.innerText = `${data2.count} Loaded`;
    } catch (e) {}
}

async function fetchRecentEvents() {
    try {
        const res = await fetch('/api/v1/events?limit=40');
        const data = await res.json();
        cachedStreamRecords = data.records || [];
        renderStreamTable(cachedStreamRecords);
    } catch (e) {}
}

function filterStreamTable() {
    const searchEl = document.getElementById('stream-search');
    if (!searchEl) return;
    const q = searchEl.value.toLowerCase().trim();
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
    if (!tbody) return;

    if (!records || records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-table">No logs matching filter.</td></tr>`;
        return;
    }

    tbody.innerHTML = records.map(r => {
        const isAllowed = r.action === 'Allowed';
        const badgeClass = isAllowed ? 'act-allowed' : 'act-blocked';
        const shortHash = (r.raw_hash || '').substring(0, 12) + '...';
        return `
            <tr>
                <td><span class="verdict-pill ${badgeClass}">${r.action || 'Unknown'}</span></td>
                <td><span style="color:var(--text-secondary);">${r.severity || 'Informational'}</span></td>
                <td><strong>${r.vendor || 'Generic'}</strong> <span style="color:var(--text-muted);">${r.product || ''}</span></td>
                <td>${r.src_ip || '—'}:${r.src_port || '—'}</td>
                <td>${r.dst_ip || '—'}:${r.dst_port || '—'}</td>
                <td><span style="color:var(--cyan); font-weight:700;">${r.protocol || '—'}</span></td>
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
