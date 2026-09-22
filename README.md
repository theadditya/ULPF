# Universal Log Pre-processing Framework (ULPF)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Schema: OCSF v1.2](https://img.shields.io/badge/Schema-OCSF%20v1.2%20(Network%204001)-green.svg)](https://schema.ocsf.io)
[![Tests: Pytest](https://img.shields.io/badge/Tests-23%2F23%20Passed-brightgreen.svg)]()
[![Air-Gapped: Ready](https://img.shields.io/badge/Air--Gapped-100%25%20Offline-orange.svg)]()

> **Production-Grade Universal Log Pre-processing & Normalization Engine for Perimeter Network Devices**  
> Converts heterogeneous logs (Syslog, CEF, LEEF, Key-Value, CSV, JSON) into lossless, analytics-ready representations for next-generation SIEMs, Big Data Lakes, and AI/ML detection pipelines.

---

## 📑 Table of Contents
- [Executive Overview](#executive-overview)
- [Key Features Aligned with Problem Statement](#key-features-aligned-with-problem-statement)
- [Supported Perimeter Devices Out-of-the-Box](#supported-perimeter-devices-out-of-the-box)
- [System Architecture](#system-architecture)
- [Quick Start Guide](#quick-start-guide)
  - [Prerequisites](#prerequisites)
  - [Local Installation](#local-installation)
  - [Docker & Containerized Deployment](#docker--containerized-deployment)
- [Packaging & Image Creation](#packaging--image-creation)
  - [Building Docker Container Image](#1-building-docker-container-image)
  - [Exporting Image for Offline Air-Gapped Transfer](#2-exporting-image-for-offline-air-gapped-transfer)
  - [Capturing Full-Page Visual Screenshot](#3-capturing-full-page-visual-screenshot)
- [Vercel Cloud Deployment](#vercel-cloud-deployment)
- [CLI Tool Reference](#cli-tool-reference)
- [Web Dashboard & Parser Studio](#web-dashboard--parser-studio)
- [AI/ML Security Feature Extraction](#aiml-security-feature-extraction)
- [Benchmarks & Performance](#benchmarks--performance)
- [Deliverables Checklist](#deliverables-checklist)

---

## Executive Overview

Modern enterprises generate billions of daily events across heterogeneous perimeter security gateways (Palo Alto, Cisco ASA, Fortinet, pfSense, Suricata, Zeek). Normalizing this telemetry traditionally requires fragile, vendor-locked parsing pipelines.

**ULPF** resolves this challenge with an open, high-performance architecture:
- **100% Lossless Guarantee**: Preserves original raw logs verbatim alongside a cryptographic **SHA-256 hash** for tamper-evident chain of custody.
- **Unified Taxonomy (OCSF v1.2 / ECS)**: Standardizes disparate terminology (`permit`, `accept`, `Built`, `allow` $\to$ `Allowed`) into OCSF Network Activity (Class 4001).
- **Plug-and-Play Onboarding**: Zero-code declarative YAML definitions for new log formats with hot-reloading.
- **Air-Gapped Operational Model**: Zero phone-home, embedded RFC 1918 classification, and offline threat/GeoIP databases.
- **Data Lake & SIEM Integration**: Native Apache Parquet columnar sink, streaming JSON-Lines, and indexed SQLite storage.
- **AI/ML-Ready**: Direct extraction of 26-dimensional numerical feature vectors for anomaly detection and tabular ML models.

---

## Key Features Aligned with Problem Statement

| Requirement | Implementation in ULPF |
| :--- | :--- |
| **a) Lossless Raw Data Preservation** | Verbatim payload preservation with cryptographic SHA-256 non-repudiation and verification. |
| **b) Extract Source Attributes** | Multi-engine parser: Syslog RFC 3164/5424, Key-Value, ArcSight CEF, IBM LEEF, CSV/TSV, JSON, Grok/Regex. |
| **c) Normalize into Taxonomy** | Canonical mapping to OCSF v1.2 (Class 4001 Network Activity) and Elastic Common Schema (ECS). |
| **d) Traceability & Lineage** | UUIDv7/v4 `event_id`, parent provenance metadata, parser version, latency (ms), and unmapped retention partition. |
| **e & i) Plug-and-Play Onboarding** | Declarative YAML configurations in `configs/parsers/` with automatic zero-shot heuristic log classification. |
| **f) Unified Visibility** | Modern dark-mode SOC Operations Web Dashboard and real-time Parser Playground. |
| **g) SIEM & Data Lake Integration** | Apache Parquet columnar sink (PyArrow), streaming JSON-L, and SQLite indexed store. |
| **h) AI/ML-Ready Analytics** | Real-time conversion into 26-dimensional numerical feature vectors (log-scaled bytes, ratios, port types). |
| **j) Air-Gapped Network Ready** | Zero external runtime dependencies; offline CIDR/RFC1918 and offline threat IoC caching. |
| **k) Containerized & Scalable** | Multi-stage Docker image, `docker-compose.yml`, non-root user permissions, and sub-millisecond execution. |

---

## Supported Perimeter Devices Out-of-the-Box

1. **Palo Alto Networks PAN-OS** (`palo_alto_traffic.yaml`): Traffic & Threat CSV/Syslog
2. **Cisco ASA / Firepower** (`cisco_asa.yaml`): Built, Deny, and Teardown Syslogs (`%ASA-6-302013`, `%ASA-4-106023`)
3. **Cisco IOS / IOS-XE** (`cisco_ios.yaml`): Security authentication, login failure, and control plane (`%SEC_LOGIN-4-LOGIN_FAILED`)
4. **Fortinet FortiGate FortiOS** (`fortinet_fortios.yaml`): Traffic forward key-value pairs
5. **Suricata Network IDS/IPS** (`suricata_eve.yaml`): EVE JSON alert telemetry
6. **pfSense / OPNsense** (`pfsense_filterlog.yaml`): `filterlog` packet inspection
7. **Zeek / Bro** (`zeek_conn.yaml`): `conn.log` connection records
8. **ArcSight Common Event Format (CEF)** (`generic_cef.yaml`): Generic perimeter CEF standard
9. **IBM QRadar LEEF** (`generic_leef.yaml`): Generic perimeter LEEF 1.0 & 2.0 standard
10. **Generic Key-Value Delimited** (`generic_kv.yaml`): Standard whitespace/tab key-value pairs
11. **Generic Syslog RFC 5424 / 3164** (`generic_syslog.yaml`): Standard Unix/Network relays

---

## System Architecture

```
                    ┌────────────────────────────────────────────────────────┐
                    │               HETEROGENEOUS LOG INGESTION              │
                    │   Syslog UDP/TCP (1514) • REST API • File Reader / S3  │
                    └───────────────────────────┬────────────────────────────┘
                                                │
                                                ▼
                    ┌────────────────────────────────────────────────────────┐
                    │               HEURISTIC AUTO-CLASSIFIER                │
                    │   Zero-Shot Identification of Vendor & Message Syntax   │
                    └───────────────────────────┬────────────────────────────┘
                                                │
                                                ▼
                    ┌────────────────────────────────────────────────────────┐
                    │             DECLARATIVE PARSER ENGINE (YAML)           │
                    │   Key-Value • CEF • LEEF • CSV/TSV • Regex • JSON      │
                    └───────────────────────────┬────────────────────────────┘
                                                │
                                                ▼
                    ┌────────────────────────────────────────────────────────┐
                    │              UNIVERSAL SCHEMA NORMALIZER               │
                    │   OCSF v1.2 Taxonomy • SHA-256 Hash • Lineage Metadata │
                    └───────────────────────────┬────────────────────────────┘
                                                │
                                                ▼
                    ┌────────────────────────────────────────────────────────┐
                    │            AIR-GAPPED ENRICHMENT & ML ENGINE           │
                    │   RFC 1918 • Direction • Offline GeoIP • 26-D Vector   │
                    └───────────────────────────┬────────────────────────────┘
                                                │
                        ┌───────────────────────┴───────────────────────┐
                        ▼                                               ▼
     ┌─────────────────────────────────────┐         ┌─────────────────────────────────────┐
     │         BIG DATA LAKE SINKS         │         │         OPERATIONS & SIEM           │
     │  Apache Parquet (Columnar Storage)  │         │  FastAPI Web Dashboard & REST API   │
     │  Streaming JSON-Lines (Append-Only) │         │  SQLite Forensic Store & Syslog Fwd │
     └─────────────────────────────────────┘         └─────────────────────────────────────┘
```

---

## Quick Start Guide

### Prerequisites
- Python 3.10+ (tested on Python 3.12)
- Optional: Docker & Docker Compose

### Local Installation

```bash
# 1. Clone repository
git clone <repo-url>
cd ulpf-framework

# 2. Set up virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Verify parser validation suite
./ulpf test-parsers

# 4. Run automated unit & integration tests
pytest -v

# 5. Launch the SOC Web Dashboard & REST API
./ulpf serve --host 0.0.0.0 --port 8000
```
Open **`http://localhost:8000`** in your browser to access the Parser Studio!

### Docker & Containerized Deployment

Launch the entire stack with a single command via [`docker-compose.yml`](docker-compose.yml):

```bash
# Build and run container stack in background
docker compose up -d

# Check health and streaming logs
docker compose logs -f
```

---

## 📦 Packaging & Image Creation

ULPF supports both **software container packaging** for production/air-gapped defense enclaves and **visual full-page capture** for executive reports and architectural reviews:

### 1. Building Docker Container Image

The project provides a hardened, multi-stage, non-root [`Dockerfile`](Dockerfile) (`user: ulpf (10001)`) for defense-grade security:

```bash
# Build the production Docker image
docker build -t ulpf:latest .

# Run container with REST API / UI (8000) and Syslog UDP (1514)
docker run -d \
  --name ulpf-app \
  -p 8000:8000 \
  -p 1514:1514/udp \
  ulpf:latest
```
Access the SOC operations dashboard at `http://localhost:8000`.

### 2. Exporting Image for Offline Air-Gapped Transfer

In classified or isolated defense networks (SCADA, SIPRNet, financial data enclaves) without internet access, export the built container image into a single portable archive:

```bash
# Export container image to compressed archive (101 MB)
docker save ulpf:latest | gzip > ulpf-docker-image.tar.gz
```

**To deploy on any target offline machine (via USB flash drive):**
```bash
# Load container image into Docker without internet access
docker load < ulpf-docker-image.tar.gz

# Run container
docker run -d -p 8000:8000 -p 1514:1514/udp ulpf:latest
```

### 3. Capturing Full-Page Visual Screenshot

Capture a high-resolution, full-page visual screenshot of the entire running dashboard (Hero, Parser Studio, and 3-Phase Pipeline):

**Via Headless Chrome (Command Line):**
```bash
google-chrome --headless --disable-gpu --window-size=1600,2400 --screenshot=ulpf-dashboard-full.png http://127.0.0.1:8000
```

**Via Web Browser (Chrome / Edge / Brave):**
1. Open `http://localhost:8000`.
2. Press <kbd>F12</kbd> (or <kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>I</kbd>) to open Developer Tools.
3. Press <kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>P</kbd> to open the Command Palette.
4. Type **`Capture full size screenshot`** and press <kbd>Enter</kbd>.

---

## 🌐 Vercel Cloud Deployment

ULPF includes native support for serverless deployment on [Vercel](https://vercel.com):

1. **Push your code to GitHub**: [`https://github.com/theadditya/ULPF.git`](https://github.com/theadditya/ULPF.git).
2. **Import into Vercel**: Connect your GitHub repository at [vercel.com/new](https://vercel.com/new).
3. **Zero Configuration**:
   - Framework Preset: **Other** (Vercel automatically detects Python via [`api/index.py`](api/index.py) and [`requirements.txt`](requirements.txt)).
   - Asset Bundling: Handled automatically by [`vercel.json`](vercel.json) (bundles all 11 YAML parsers, sample log files, and static UI assets).
   - Serverless Writable Storage: Automatically utilizes `/tmp/ulpf_data` for ephemeral SQLite and Parquet sink operations.
   - Public Cloud Intelligence: Automatically starts in `🌐 Public Web Cloud` mode on Vercel.

---

## CLI Tool Reference

The `ulpf` CLI provides full operational control:

```bash
# 1. Parse a single raw log string
./ulpf parse --log '<166>Sep 22 18:01:05 firewall %ASA-6-302013: Built outbound TCP connection 987654 for outside:198.51.100.20/443 to inside:192.168.1.100/54321'

# 2. Parse and output AI/ML numerical feature vectors
./ulpf parse --features --log 'CEF:0|Check Point|FireWall-1|1.0|drop|Drop packet|High|src=185.220.101.5 dst=10.0.0.22 spt=44123 dpt=22 proto=6 act=drop'

# 3. Ingest a log file in batch mode
./ulpf parse --file sample_logs/perimeter_devices.log

# 4. Run performance benchmark
./ulpf benchmark --count 10000

# 5. Run parser validation across all vendor samples
./ulpf test-parsers
```

---

## Web Dashboard & Parser Studio

The built-in web interface at `http://localhost:8000` provides:
- **Zero-Shot Parser Studio**: Paste any raw perimeter log and click *Parse & Normalize*.
- **Interactive Output Tabs**:
  1. *OCSF v1.2 Standard*: Formatted JSON adhering to Class 4001.
  2. *Forensic Lineage*: Displays UUID, SHA-256 hash, latency, and integrity status.
  3. *AI/ML Feature Vector*: Visualized tabular metrics and raw 26-D float vector.
  4. *Unmapped Retention*: Proves zero information was discarded during parsing.
- **Forensic Event Stream**: Searchable, indexed log records from the local SQLite sink.
- **One-Click Sample Ingestion**: Pre-populates the database with real multi-vendor test logs.

---

## AI/ML Security Feature Extraction

ULPF automatically computes a 26-dimensional numerical feature vector for each log event, structured for direct input into anomaly detection models (Isolation Forest, One-Class SVM, XGBoost, Autoencoders):

- **Network Topology**: `src_port`, `dst_port`, `is_well_known_port`, `is_ephemeral_src_port`, `is_internal_src`, `is_internal_dst`
- **Traffic Direction**: `direction_inbound`, `direction_outbound`, `direction_lateral`, `direction_external`
- **Protocol Encoding**: `proto_tcp`, `proto_udp`, `proto_icmp`, `proto_other`
- **Log-Scaled Volume Metrics**: `bytes_in_log`, `bytes_out_log`, `total_bytes_log`, `bytes_ratio_out_in`, `packets_total_log`, `duration_sec`, `bytes_per_second`
- **Security Context**: `action_blocked`, `action_allowed`, `severity_level`, `threat_flag`, `threat_confidence`

---

## Benchmarks & Performance

Evaluated on single-core Linux x86_64:

```text
==========================================================
      ULPF HIGH-THROUGHPUT PERFORMANCE REPORT
==========================================================
Total Events Ingested        : 15,000
Total Processing Time        : 3.085 s
Throughput                   : 4,861.67 Events / Second (EPS)
Median Latency (p50)         : 0.1360 ms
95th Percentile Latency (p95): 0.1760 ms
99th Percentile Latency (p99): 0.2560 ms
Extrapolated Daily Volume    : 420+ Million events / day / core
==========================================================
```

Scales horizontally across container replicas or multi-worker pipelines to ingest billions of daily events.

---

## Deliverables Checklist

- [x] **Source Code**: Fully modular, typed, production-ready codebase (`src/ulpf/`).
- [x] **README Instructions**: Setup, execution, CLI, Docker, API, and benchmarks.
- [x] **Architecture Document**: [ARCHITECTURE.md](ARCHITECTURE.md) (Max 2 pages, Mermaid pipeline flow, schema mapping).
- [x] **Demo Video Script**: [DEMO_SCRIPT.md](DEMO_SCRIPT.md) (2-minute timestamped recording guide & narration script).
- [x] **Technical Presentation**: [PRESENTATION.md](PRESENTATION.md) (5 concise slides with visuals and speaker notes).
