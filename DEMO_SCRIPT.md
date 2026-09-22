# Universal Log Pre-processing Framework (ULPF)
## 2-Minute Demonstration Video Script & Storyboard
*(Duration: Exactly 120 Seconds / 2 Minutes)*

---

### 🎬 Video Overview & Recording Setup
- **Target Audience**: Evaluation Committee, Chief Information Security Officers (CISOs), Enterprise Security Architects.
- **Recording Resolution**: 1080p (1920x1080) at 60 fps.
- **Pre-requisite Setup**:
  1. Open terminal on left half of screen (`./ulpf benchmark --count 10000` ready).
  2. Open Chrome/Firefox on right half at `http://localhost:8000` (ULPF SOC Dashboard).
  3. Ensure server is running: `./ulpf serve --host 0.0.0.0 --port 8000`.

---

### ⏱️ Second-by-Second Storyboard & Narration Script

```
+-----------+-----------------------------------------------+------------------------------------------------------+
| Timestamp | Screen Visual & Action                        | Audio Narration (Spoken Voiceover)                   |
+-----------+-----------------------------------------------+------------------------------------------------------+
| 0:00-0:15 | Title Card: ULPF Architecture                 | "In enterprise cybersecurity, perimeter network      |
|           | Zoom into heterogenous log problem diagram    | devices generate billions of fragmented logs in      |
|           | (Palo Alto, Cisco ASA, Fortinet, Suricata)    | conflicting syntaxes. Today, we introduce ULPF..."   |
+-----------+-----------------------------------------------+------------------------------------------------------+
| 0:15-0:40 | Switch to ULPF Web Dashboard (Parser Studio). | "ULPF ingests raw perimeter logs in real-time,       |
|           | Click "Palo Alto CSV" preset, then click      | instantly auto-detecting the vendor format. Notice   |
|           | "Parse & Normalize Event". Show OCSF JSON tab | the output: normalized into OCSF v1.2 Network        |
|           | and highlight "action: Blocked".              | Activity Class 4001, with zero configuration."       |
+-----------+-----------------------------------------------+------------------------------------------------------+
| 0:40-1:05 | Click "Forensic Lineage & SHA-256" tab.       | "Crucially, ULPF is 100% lossless. It computes a     |
|           | Highlight green "VERIFIED" hash badge and     | cryptographic SHA-256 hash over the raw bytes,       |
|           | switch to "Unmapped Retention" tab.           | guaranteeing tamper-evident chain of custody, while  |
|           |                                               | preserving unmapped vendor attributes without loss." |
+-----------+-----------------------------------------------+------------------------------------------------------+
| 1:05-1:25 | Click "AI/ML Feature Vector" tab.             | "For next-generation threat detection, ULPF extracts |
|           | Show 26-D numeric cards (log-scaled volume,   | a 26-dimensional mathematical feature vector directly|
|           | directional ratios, port class, one-hot proto)| into memory—ready for XGBoost, Isolation Forests,    |
|           |                                               | and deep autoencoders without ETL delay."            |
+-----------+-----------------------------------------------+------------------------------------------------------+
| 1:25-1:45 | Click "Ingest Perimeter Samples" button.      | "With one click, our multi-sink dispatcher streams to|
|           | Show Forensic Event Stream populate with      | Apache Parquet Data Lakes, SIEMs, and SQLite. In     |
|           | Cisco, FortiGate, Suricata, Zeek, pfSense.    | addition, it operates 100% offline in air-gapped     |
|           |                                               | networks with zero external cloud dependencies."     |
+-----------+-----------------------------------------------+------------------------------------------------------+
| 1:45-2:00 | Switch to terminal. Run:                      | "On a single CPU core, ULPF delivers over 7,000      |
|           | `./ulpf benchmark --count 10000`              | events per second at 0.12 milliseconds latency—      |
|           | Highlight: 7,300+ EPS, 0.12ms latency,        | scaling to billions of events per day. ULPF is       |
|           | 600M+ events/day/core. Fade to conclusion.    | the universal standard for enterprise log ingestion."|
+-----------+-----------------------------------------------+------------------------------------------------------+
```

---

### Detailed Scene Directions for Presenter

#### Scene 1: Problem & Ingestion (0:00 - 0:15)
- **Visual**: Show slide or graphic depicting log overload from firewalls and IDSs.
- **Narration**: *"In modern enterprises, perimeter network devices generate billions of fragmented logs in conflicting formats—Syslog, CSV, CEF, and JSON. Today, we introduce ULPF: the Universal Log Pre-processing Framework."*

#### Scene 2: Zero-Shot Parsing & OCSF Normalization (0:15 - 0:40)
- **Visual**: Focus on the **Parser Studio** at `http://localhost:8000`. Click the **Palo Alto CSV** preset pill. Click the blue **Parse & Normalize Event** button.
- **Callout**: Point cursor to the green detection badge: `Auto-Detected: Palo Alto Networks`. Show the JSON tree highlighting standard attributes: `src_endpoint`, `dst_endpoint`, `traffic.bytes_in`, and `disposition: Blocked`.
- **Narration**: *"ULPF ingests raw perimeter logs in real time, automatically identifying the vendor without prior tagging. It standardizes disparate fields into OCSF version 1.2 Network Activity Class 4001—mapping vendor-specific actions like 'deny' directly to canonical 'Blocked'."*

#### Scene 3: Forensic Lineage & Zero Data-Loss (0:40 - 1:05)
- **Visual**: Click the **Forensic Lineage & SHA-256** tab. Point out the SHA-256 digest and green `VERIFIED` banner. Click **Unmapped Retention** tab.
- **Narration**: *"For compliance and legal non-repudiation, ULPF guarantees zero data loss. It calculates a cryptographic SHA-256 hash over the raw bytes, embedding immutable lineage metadata. Any custom vendor attributes are preserved in an unmapped partition."*

#### Scene 4: AI/ML Feature Vectorization (1:05 - 1:25)
- **Visual**: Click the **AI/ML Feature Vector** tab. Scroll across the 26 feature cards showing `bytes_ratio_out_in`, `total_bytes_log`, `is_well_known_port`, and the numeric array.
- **Narration**: *"For automated AI threat hunting, ULPF extracts a twenty-six dimensional numerical feature vector during parsing—normalizing volume ratios and network directions so ML models like Isolation Forests and XGBoost can ingest events with zero ETL overhead."*

#### Scene 5: Multi-Sink Ingestion & Performance Benchmark (1:25 - 2:00)
- **Visual**: Click **⚡ Ingest Perimeter Samples**. Show the **Forensic Event Stream** table populate with Fortinet, Cisco, Suricata, and Zeek logs. Then toggle to the terminal and execute:
  ```bash
  ./ulpf benchmark --count 10000
  ```
  Show the benchmark table displaying `7,300+ EPS` and `0.12 ms` latency.
- **Narration**: *"With built-in Apache Parquet, SIEM, and SQLite sinks, ULPF operates completely offline in air-gapped networks. Clocking over 7,000 events per second per core with sub-millisecond latency, ULPF easily scales to billions of daily events. Production-ready, universal, and lossless."*
