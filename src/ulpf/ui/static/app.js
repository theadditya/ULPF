// Preset Log Examples for All Perimeter Network Devices
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

function selectPreset(name) {
    const raw = PRESETS[name];
    if (raw) {
        document.getElementById("raw-log-input").value = raw;
        processCurrentLog();
    }
}

function switchTab(tabId) {
    document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(content => content.classList.remove("active"));
    
    // Find active button corresponding to tabId
    const buttons = document.querySelectorAll(".tab-btn");
    if (tabId === 'tab-ocsf') buttons[0].classList.add("active");
    if (tabId === 'tab-lineage') buttons[1].classList.add("active");
    if (tabId === 'tab-ml') buttons[2].classList.add("active");
    if (tabId === 'tab-unmapped') buttons[3].classList.add("active");

    const activeContent = document.getElementById(tabId);
    if (activeContent) activeContent.classList.add("active");
}

async function processCurrentLog() {
    const input = document.getElementById("raw-log-input").value.trim();
    if (!input) return;

    const btn = document.getElementById("btn-process");
    btn.innerText = "Processing...";
    btn.disabled = true;

    try {
        const response = await fetch("/api/v1/process", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ raw_log: input })
        });

        if (!response.ok) {
            alert("Error processing event: " + (await response.text()));
            return;
        }

        const data = await response.json();
        renderResults(data);
        fetchTelemetry();
        fetchRecentEvents();

    } catch (err) {
        console.error("Processing failed", err);
    } finally {
        btn.innerText = "▶ Parse & Normalize Event";
        btn.disabled = false;
    }
}

function renderResults(data) {
    const event = data.event;
    
    // 1. Detection pill
    const pill = document.getElementById("detection-pill");
    const parserName = document.getElementById("detected-parser-name");
    pill.style.display = "inline-flex";
    parserName.innerText = `${event.product.vendor_name} (${event.lineage.parser_id})`;

    // 2. Tab 1: OCSF JSON
    document.getElementById("code-ocsf").innerText = JSON.stringify(event, null, 2);

    // 3. Tab 2: Lineage
    const lineageContainer = document.getElementById("lineage-summary");
    const verified = data.integrity_verified;
    lineageContainer.innerHTML = `
        <div class="lineage-item">
            <div class="lineage-k">Cryptographic Raw Hash (SHA-256)</div>
            <div class="lineage-v">${event.lineage.raw_hash}</div>
        </div>
        <div class="lineage-item">
            <div class="lineage-k">Forensic Integrity Verification</div>
            <div class="lineage-v" style="color: ${verified ? '#10b981' : '#ef4444'}">
                ${verified ? "✔ VERIFIED: Raw payload perfectly matches cryptographic checksum" : "✖ TAMPER DETECTED"}
            </div>
        </div>
        <div class="lineage-item">
            <div class="lineage-k">Universal Event ID (UUID)</div>
            <div class="lineage-v">${event.lineage.event_id}</div>
        </div>
        <div class="lineage-item">
            <div class="lineage-k">Schema Specification</div>
            <div class="lineage-v">${event.lineage.schema_version}</div>
        </div>
        <div class="lineage-item">
            <div class="lineage-k">Parser &amp; Latency</div>
            <div class="lineage-v">${event.lineage.parser_id} (v${event.lineage.parser_version}) &bull; Execution time: ${event.lineage.processing_latency_ms} ms</div>
        </div>
    `;

    // 4. Tab 3: AI/ML Feature Vector
    const mlContainer = document.getElementById("ml-container");
    const feats = data.features;
    let featCards = '<div class="ml-grid">';
    for (const [k, v] of Object.entries(feats)) {
        featCards += `
            <div class="ml-card">
                <span class="ml-name">${k}</span>
                <span class="ml-val">${v}</span>
            </div>
        `;
    }
    featCards += '</div>';
    featCards += `
        <div style="margin-top: 1rem;">
            <div style="font-size:0.75rem; color:#94a3b8; margin-bottom:0.25rem;">Tabular ML Array [${data.ml_vector.length} dimensions]:</div>
            <pre style="background:#131b2e; padding:0.5rem; border-radius:4px;"><code>${JSON.stringify(data.ml_vector)}</code></pre>
        </div>
    `;
    mlContainer.innerHTML = featCards;

    // 5. Tab 4: Unmapped
    const unmappedCode = document.getElementById("code-unmapped");
    const unmappedKeys = Object.keys(event.unmapped || {});
    if (unmappedKeys.length === 0) {
        unmappedCode.innerText = "// All source fields were 100% mapped into the standardized OCSF schema!";
    } else {
        unmappedCode.innerText = JSON.stringify(event.unmapped, null, 2);
    }
}

async function loadSampleDataset() {
    try {
        const res = await fetch("/api/v1/load-samples", { method: "POST" });
        const data = await res.json();
        alert(`Successfully ingested ${data.ingested_events} perimeter device logs!`);
        fetchTelemetry();
        fetchRecentEvents();
    } catch (err) {
        alert("Failed to load sample dataset: " + err);
    }
}

async function fetchTelemetry() {
    try {
        const res = await fetch("/api/v1/telemetry");
        const data = await res.json();
        document.getElementById("stat-total").innerText = data.total_processed.toLocaleString();
        document.getElementById("stat-latency").innerText = `${data.average_latency_ms} ms`;
    } catch (e) {}

    try {
        const res2 = await fetch("/api/v1/parsers");
        const data2 = await res2.json();
        document.getElementById("stat-parsers").innerText = data2.count;
    } catch (e) {}
}

async function fetchRecentEvents() {
    try {
        const res = await fetch("/api/v1/events?limit=25");
        const data = await res.json();
        const tbody = document.getElementById("stream-tbody");
        if (!data.records || data.records.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="empty-row">No events in database. Click "Ingest Perimeter Samples" above to populate.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.records.map(r => {
            const actClass = r.action === 'Allowed' ? 'act-allowed' : 'act-blocked';
            const sevClass = `sev-${(r.severity || 'info').toLowerCase()}`;
            const shortHash = (r.raw_hash || '').substring(0, 12) + '...';
            return `
                <tr>
                    <td><span class="badge-act ${actClass}">${r.action || 'Unknown'}</span></td>
                    <td><span class="${sevClass}">${r.severity || 'Informational'}</span></td>
                    <td><strong>${r.vendor || 'Generic'}</strong> <span style="color:#64748b;">${r.product || ''}</span></td>
                    <td>${r.src_ip || '-'}:${r.src_port || '-'}</td>
                    <td>${r.dst_ip || '-'}:${r.dst_port || '-'}</td>
                    <td>${r.protocol || '-'}</td>
                    <td title="${r.raw_hash}"><span style="color:#38bdf8;">${shortHash}</span></td>
                </tr>
            `;
        }).join("");
    } catch (e) {
        console.error("Error fetching stream", e);
    }
}

// Initial Boot
window.addEventListener("DOMContentLoaded", () => {
    fetchTelemetry();
    fetchRecentEvents();
    // Default preset load
    selectPreset('palo_alto');
    setInterval(fetchTelemetry, 5000);
});
