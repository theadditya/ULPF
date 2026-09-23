# Universal Log Pre-processing Framework (ULPF)
## Release Notes — Version 1.0.0

[![Release: v1.0.0](https://img.shields.io/badge/Release-v1.0.0-blue.svg?logo=github)](https://github.com/theadditya/ULPF/releases/tag/v1.0.0)
[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-theadditya%2Fulpf-2496ED.svg?logo=docker&logoColor=white)](https://hub.docker.com/r/theadditya/ulpf)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Schema: OCSF v1.2](https://img.shields.io/badge/Schema-OCSF%20v1.2%20(Network%204001)-green.svg)](https://schema.ocsf.io)
[![Tests: Pytest](https://img.shields.io/badge/Tests-23%2F23%20Passed-brightgreen.svg)]()
[![Air-Gapped: Ready](https://img.shields.io/badge/Air--Gapped-100%25%20Offline-orange.svg)](https://github.com/theadditya/ULPF/releases/download/v1.0.0/ulpf-docker-image.tar.gz)

---

## 🚀 Executive Overview

We are proud to announce the initial official production release of the **Universal Log Pre-processing Framework (ULPF) v1.0.0**.

Modern enterprise Security Operations Centers (SOCs) and cybersecurity infrastructure teams ingest billions of daily events across heterogeneous perimeter security gateways (Palo Alto Networks, Cisco ASA/Firepower, Fortinet FortiOS, Suricata, pfSense, Zeek). Traditionally, normalizing this data requires brittle regex pipelines, incurs severe data loss through field dropping, and drives astronomical SIEM ingestion costs.

**ULPF v1.0.0** delivers a high-throughput, vendor-neutral normalization engine that transforms unstructured and heterogeneous perimeter telemetry into standardized, lossless, AI-ready representations.

---

## 🌟 What's New & Core Capabilities

### 1. 100% Lossless Dual-Payload Model & Cryptographic Non-Repudiation
- **Verbatim Raw Preservation**: The original raw log payload is preserved without any alteration or string truncation.
- **SHA-256 Integrity Verification**: An automated SHA-256 cryptographic digest is computed on ingestion (`event.verify_integrity()`), providing tamper-evident chain of custody for digital forensics (DFIR) and regulatory compliance audits.
- **Unmapped Vendor Attributes Partition**: Any vendor-specific key-value pairs or metrics not mapped to canonical schemas are retained in an `unmapped` partition—guaranteeing 0% dropped attributes.

### 2. Canonical Open Taxonomy (OCSF v1.2 & Multi-Schema Export)
- **OCSF v1.2 Class 4001 (Network Activity)**: Disparate vendor terminologies (`permit`, `accept`, `Built`, `allow` $\to$ `Allowed`; `deny`, `drop`, `teardown` $\to$ `Blocked`) are mapped directly to open standards.
- **Multi-Schema Exporter**: Seamless on-the-fly export to:
  - **OCSF v1.2** Network Activity
  - **Elastic Common Schema (ECS v8.x)**
  - **Unified SIEM Alert JSON**

### 3. Out-of-the-Box Declarative YAML Parsers (11 Supported Standards)
Declarative, hot-reloading YAML parsers with automatic zero-shot heuristic format classification:
1. **Palo Alto Networks PAN-OS** (`palo_alto_traffic.yaml`): Traffic & Threat CSV/Syslog
2. **Cisco ASA / Firepower** (`cisco_asa.yaml`): Connection Built, Teardown, and Deny syslogs (`%ASA-6-302013`, `%ASA-4-106023`)
3. **Cisco IOS / IOS-XE** (`cisco_ios.yaml`): Security authentication & login telemetry (`%SEC_LOGIN-4-LOGIN_FAILED`)
4. **Fortinet FortiGate FortiOS** (`fortinet_fortios.yaml`): Traffic forward key-value streams
5. **Suricata Network IDS/IPS** (`suricata_eve.yaml`): EVE JSON alerts & network metadata
6. **pfSense / OPNsense** (`pfsense_filterlog.yaml`): `filterlog` packet inspection
7. **Zeek / Bro** (`zeek_conn.yaml`): `conn.log` connection records
8. **ArcSight Common Event Format (CEF)** (`generic_cef.yaml`): Generic perimeter CEF standard
9. **IBM QRadar LEEF** (`generic_leef.yaml`): Generic perimeter LEEF 1.0 & 2.0 standard
10. **Generic Key-Value Delimited** (`generic_kv.yaml`): Standard whitespace/tab key-value pairs
11. **Generic Syslog RFC 5424 / 3164** (`generic_syslog.yaml`): Standard Unix & Network relays

### 4. 26-Dimensional AI/ML Numerical Feature Extraction
ULPF generates a normalized **26-dimensional mathematical feature vector** in-memory for each event, eliminating offline ETL delays for machine learning pipelines:
- **Topology Features**: Source/destination port classes, ephemeral flag, internal RFC 1918 flags.
- **Traffic Dynamics**: Log-scaled volume ($\log_{1p}(\text{bytes})$), directional flow ratios ($\frac{\log_{1p}(\text{bytes\_out})}{\log_{1p}(\text{bytes\_in}) + 1}$), connection duration, and transfer rate ($\text{bytes/sec}$).
- **Security Context**: One-hot protocol encodings (TCP/UDP/ICMP), directional vectors (Inbound, Outbound, Lateral), binary action flags, and threat confidence scores.
- Ready for immediate streaming into **Isolation Forests**, **One-Class SVM**, **XGBoost**, and **Autoencoders**.

### 5. Automated MITRE ATT&CK & Regulatory Compliance Mapping
- Automatically enriches perimeter events with MITRE ATT&CK Tactics (e.g., `TA0043` Network Discovery, `TA0011` Command & Control).
- Automated crosswalk citations for **PCI-DSS v4.0** (Requirement 10.3), **NIST SP 800-53 r5** (AU-2/AU-3), **ISO/IEC 27001:2022** (Control A.8.15), and **HIPAA Security Rule** (§ 164.312(b)).

### 6. High-Throughput Sinks & FinOps Economic Value
- **Apache Parquet Columnar Sink**: Snappy compression and partitioned timestamps for AWS S3, MinIO, Snowflake, and ClickHouse.
- **Streaming JSON-Lines**: Newline-delimited JSON for Cribl, Splunk Forwarders, Vector, and Logstash.
- **SQLite Forensic Store**: Indexed local event store for incident response investigations.
- Reduces SIEM licensing expenditure by 50% to 80% by routing routine allow traffic to data lakes while streaming enriched anomalies to SIEM indexes.

### 7. Modern SOC Operations UI & Parser Studio
- Vector SVG-first UI with dark mode architecture.
- Multi-tier responsive design supporting smartphones, tablets, laptops, and ultra-wide displays.
- Dual operating modes: **Air-Gapped Enclave** (100% offline) and **Public Web Cloud** (serverless-ready).

---

## 🛡️ Distribution & Deployment Channels

ULPF v1.0.0 is distributed across two primary channels:

### Channel 1: Public Docker Hub (Connected Deployments)

Repository: [**`theadditya/ulpf`**](https://hub.docker.com/r/theadditya/ulpf)

```bash
# Pull official image
docker pull theadditya/ulpf:latest
# Or versioned tag
docker pull theadditya/ulpf:v1.0.0

# Run container (Web UI on 8000, Syslog UDP ingestion on 1514)
docker run -d \
  --name ulpf \
  -p 8000:8000 \
  -p 1514:1514/udp \
  theadditya/ulpf:latest
```

---

### Channel 2: GitHub Release Offline Bundle (Air-Gapped Enclaves)

Release: [**GitHub Release v1.0.0**](https://github.com/theadditya/ULPF/releases/tag/v1.0.0)  
Direct Asset Download: [**`ulpf-docker-image.tar.gz`**](https://github.com/theadditya/ULPF/releases/download/v1.0.0/ulpf-docker-image.tar.gz) *(~142 MB compressed)*

For classified, SIPRNet, SCADA, and zero-internet environments:

1. **Download & Verify**:
   ```bash
   # Download the standalone offline release archive
   wget https://github.com/theadditya/ULPF/releases/download/v1.0.0/ulpf-docker-image.tar.gz

   # Verify cryptographic SHA-256 integrity
   sha256sum ulpf-docker-image.tar.gz
   ```
   **Expected SHA-256 Digest**:
   ```text
   d869b7c6d662313628ac6a36b3aed3560b6b495348549fc9bac9cb1e015e712f  ulpf-docker-image.tar.gz
   ```

2. **Transfer to Isolated Network**:
   Transfer the verified archive via approved physical media (USB flash drive or data diode).

3. **Load and Run Without Internet**:
   ```bash
   # Load image into local Docker daemon
   docker load < ulpf-docker-image.tar.gz

   # Launch container in air-gapped mode
   docker run -d \
     --name ulpf \
     -p 8000:8000 \
     -p 1514:1514/udp \
     ulpf:latest
   ```

---

## ⚡ Performance Benchmarks

Evaluated on commodity Linux x86_64 single core:

```text
==========================================================
      ULPF HIGH-THROUGHPUT PERFORMANCE REPORT
==========================================================
Total Events Ingested        : 15,000
Total Processing Time        : 2.034 s
Throughput                   : 7,374.26 Events / Second (EPS)
Median Latency (p50)         : 0.1250 ms
95th Percentile Latency (p95): 0.1760 ms
99th Percentile Latency (p99): 0.2560 ms
Extrapolated Daily Volume    : 637+ Million events / day / core
==========================================================
```

- **Horizontal Scalability**: Stateless pipeline scales linearly across multi-worker processes or Kubernetes pods to ingest billions of daily events.

---

## 🧪 Quality Assurance & Verification

- **Automated Test Suite**: **23 / 23 unit and integration tests passing** (`pytest -v`).
- **Test Coverage**:
  - Declarative parser validation across all vendor log formats
  - RFC 1918 subnet classification & direction determination
  - Offline Geo/ASN and threat IoC lookup (zero network dependencies)
  - 100% Lossless verbatim preservation & SHA-256 verification
  - Unmapped attribute partition retention
  - 26-Dimensional numerical ML feature generation
  - MITRE ATT&CK & Multi-Schema export (OCSF v1.2, ECS, SIEM)
  - Apache Parquet, JSON-L, and SQLite sinks
  - REST API endpoint operations

---

## 📦 Release Artifacts & Checksums

| Asset Name | Description | Size | SHA-256 Checksum |
| :--- | :--- | :--- | :--- |
| **[`ulpf-docker-image.tar.gz`](https://github.com/theadditya/ULPF/releases/download/v1.0.0/ulpf-docker-image.tar.gz)** | Pre-packaged offline container image for air-gapped enclaves | ~142 MB | `d869b7c6d662313628ac6a36b3aed3560b6b495348549fc9bac9cb1e015e712f` |
| **`Source code (zip)`** | Full repository source code archive | — | Standard GitHub Release |
| **`Source code (tar.gz)`** | Full repository source code archive | — | Standard GitHub Release |
| **`theadditya/ulpf:latest`** | Official Docker Hub container image | ~150 MB | Published to Docker Hub |
| **`theadditya/ulpf:v1.0.0`** | Version-pinned Docker Hub container image | ~150 MB | Published to Docker Hub |

---

## 🤝 Getting Involved & Support

- **Repository**: [https://github.com/theadditya/ULPF](https://github.com/theadditya/ULPF)
- **Documentation**: [ARCHITECTURE.md](ARCHITECTURE.md), [DEMO_SCRIPT.md](DEMO_SCRIPT.md), [ULPF_SCOPE_ANALYSIS.md](ULPF_SCOPE_ANALYSIS.md)
- **License**: Apache License 2.0
