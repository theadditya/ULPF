# Universal Log Pre-processing Framework (ULPF)
## System Architecture & Technical Specification Document
*(Page Limit: Maximum 2 Pages)*

---

### 1. Executive Summary & Problem Context
Modern enterprise cybersecurity operations are severely impaired by perimeter log heterogeneity. Organizations deploy diverse security gateways—including Palo Alto Next-Gen Firewalls, Cisco ASA/Firepower, Fortinet FortiOS, Suricata IDS, Zeek NSM, and pfSense appliances. Each platform emits logs in distinct syntaxes (RFC 3164/5424 Syslog, ArcSight CEF, IBM LEEF, nested JSON, comma-separated CSV, and unstructured key-value pairs). 

Developing custom parsers for each downstream SIEM, data lake, or ML engine incurs massive engineering overhead, introduces schema drift, and frequently causes catastrophic forensic data loss.

The **Universal Log Pre-processing Framework (ULPF)** solves this through a modular, high-throughput, vendor-agnostic pipeline that standardizes any perimeter network event into the **Open Cybersecurity Schema Framework (OCSF v1.2, Class 4001: Network Activity)** while guaranteeing **100% lossless raw payload preservation** and **cryptographic non-repudiation**.

```
+---------------------------------------------------------------------------------------------------+
|                                 ULPF PROCESSING PIPELINE                                          |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  [Ingestion Layer]     -->  [Classification]     -->  [Declarative Parser]  -->  [Normalizer]     |
|   - Syslog UDP/TCP           - Zero-shot heuristic     - YAML specifications     - OCSF v1.2      |
|   - REST API / HTTP          - Syntax matching         - Field extraction        - Lossless hash  |
|   - File / S3 stream         - Dynamic routing         - Unmapped partition      - Lineage UUID   |
|                                                                                       |           |
|                                                                                       v           |
|  [Egress Multi-Sinks]  <--  [Data Lake & SIEM]   <--  [Feature Vectorizer]  <--  [Enrichment]     |
|   - Apache Parquet           - S3 / Athena             - 26-D numerical vector   - RFC 1918 CIDR  |
|   - Append JSON-Lines        - Splunk / Sentinel       - Log-scaled volume       - Offline GeoIP  |
|   - SQLite Forensics         - ClickHouse / Spark      - Directional ratios      - Threat IoC DB  |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

---

### 2. High-Level Pipeline Architecture

```mermaid
flowchart LR
    subgraph Ingestion ["1. INGESTION"]
        A1["Syslog UDP/TCP<br/>:1514"]
        A2["REST Ingest<br/>/api/v1/process"]
        A3["Batch Stream<br/>JSONL/CSV/Files"]
    end

    subgraph Core ["2. ULPF CORE PIPELINE"]
        B["Heuristic Classifier<br/>(Zero-Shot Detection)"]
        C["Declarative Parser Engine<br/>(YAML Rules & Regex)"]
        D["OCSF v1.2 Normalizer<br/>(Taxonomy & Type Casting)"]
        E["Air-Gapped Enrichment<br/>(RFC1918 • Offline GeoIP • IoCs)"]
        F["AI/ML Vectorizer<br/>(26-D Numerical Extraction)"]
    end

    subgraph Sinks ["3. MULTI-SINK DISPATCH"]
        G1["Data Lake Sink<br/>(Apache Parquet / Snappy)"]
        G2["Forensic Store<br/>(Indexed SQLite DB)"]
        G3["Streaming Sink<br/>(Lossless JSON-Lines)"]
        G4["SIEM Forwarder<br/>(Syslog / Webhook)"]
    end

    A1 & A2 & A3 --> B
    B --> C
    C --> D
    D --> E
    E --> F
    F --> G1 & G2 & G3 & G4
```

---

### 3. Core Architectural Pillars

#### 3.1 Lossless Dual-Payload Model & Cryptographic Provenance
To meet rigorous forensic, legal, and compliance standards (e.g., PCI-DSS, HIPAA, FedRAMP), ULPF enforces a dual-payload architectural model:
1. **Verbatim Raw Event**: The raw log string is captured unaltered and un-truncated (`raw_event`).
2. **Cryptographic Checksum**: A SHA-256 digest (`raw_hash`) is computed over the raw bytes immediately upon ingestion. Any subsequent transformation can be verified for tamper-evidence using `event.verify_integrity()`.
3. **Traceability Lineage**: Every event receives a unique `event_id` (UUIDv7/v4), `collector_id`, `parser_id`, `parser_version`, schema version, ingestion timestamp, and microsecond processing latency.
4. **Zero Data Loss Partition (`unmapped`)**: Attributes not explicitly standardized into the core OCSF taxonomy are partitioned into an open dictionary, guaranteeing that proprietary vendor extensions are never dropped.

#### 3.2 Universal Taxonomy (OCSF v1.2 Network Activity Class 4001)
Heterogeneous terminologies are mapped into standardized canonical classes:
- **Disposition / Action**: Disparate verbs (`Built`, `permit`, `allow`, `accept`, `pass`, `close` $\to$ `Allowed`; `Deny`, `drop`, `block`, `reject`, `reset` $\to$ `Blocked`/`Dropped`/`Reset`).
- **Severity**: Normalizes vendor numeric levels (Syslog 0–7) and labels (`crit`, `err`, `notice`, `high`, `low`) into canonical `SeverityLevel` enums.
- **Endpoints & Flow**: Populates `src_endpoint`, `dst_endpoint`, `connection_info`, `traffic` metrics (bytes in/out, packets, session duration), and layer-7 application identification.

#### 3.3 Plug-and-Play Declarative Parser Architecture
Adding support for new security gateways requires **zero code modifications or recompilation**. Engineers specify a declarative YAML definition:
- **Format**: `key_value`, `cef`, `leef`, `csv`, `json`, `regex`, or `syslog`.
- **Match Conditions**: Signature keywords or regex patterns for zero-shot auto-detection.
- **Field Mappings & Transformations**: Declarative dot-notation mappings, type-casting directives (`safe_int`, `safe_float`), and categorical translation dictionaries (`value_maps`).
- **Hot-Reloading**: Parsers reload dynamically at runtime via REST API or directory watchers.

```yaml
# Example: Declarative Parser Snippet (configs/parsers/palo_alto_traffic.yaml)
id: "palo_alto_traffic"
vendor: "Palo Alto Networks"
format: "csv"
mapping:
  "src_endpoint.ip": "src_ip"
  "dst_endpoint.ip": "dst_ip"
  "disposition.action": "action"
value_maps:
  "disposition.action":
    "allow": "Allowed"
    "deny": "Blocked"
```

#### 3.4 AI/ML-Ready Feature Engineering Engine
Cybersecurity machine learning pipelines require clean numerical vectors. ULPF extracts a **26-dimensional mathematical representation** directly during pipeline execution:
- **Topology Features**: Source/destination port classes, ephemeral flag, internal RFC 1918 status.
- **Traffic Dynamics**: Log-scaled volume ($\log_{1p}(\text{bytes})$), directional flow ratios ($\frac{\log_{1p}(\text{bytes\_out})}{\log_{1p}(\text{bytes\_in}) + 1}$), connection duration, and transfer rate ($\text{bytes/sec}$).
- **Security & Direction**: One-hot protocol encodings (TCP/UDP/ICMP), directional vectors (Inbound, Outbound, Lateral), binary action flags, and threat confidence scores.

#### 3.5 Air-Gapped Network Readiness
ULPF is designed to operate in completely isolated, air-gapped networks (e.g., defense, critical infrastructure, financial datacenters):
- **Zero External Calls**: No cloud dependencies or internet phone-home routines.
- **Embedded RFC 1918 Trie**: High-speed offline private subnet classifier.
- **Local Threat Intelligence**: Embedded offline IoC cache for instantaneous indicator matching without external DNS or API resolution.

---

### 4. Storage & Big Data Lake Integration

| Sink Type | Target Platform | Format & Optimization |
| :--- | :--- | :--- |
| **Apache Parquet Sink** | AWS S3, Snowflake, Databricks, Apache Spark | Columnar, Snappy compression, partitioned by timestamp, dictionary encoded. |
| **Streaming JSON-L Sink** | Cribl, Splunk Forwarders, Vector, Logstash | Newline-delimited UTF-8 JSON, append-only, low-overhead streaming. |
| **SQLite Forensic Sink** | Local SOC Investigation, Incident Response | Indexed B-Tree tables on `event_id`, `raw_hash`, `src_ip`, `dst_ip`, `action`. |
| **SIEM Forwarder** | Splunk Enterprise, Microsoft Sentinel, Elastic | Syslog RFC 5424 over UDP/TCP or authenticated HTTP Webhook. |

---

### 5. Performance & Scalability Benchmarks

Empirical performance validated on standard Linux x86_64 single core:
- **Throughput**: **7,374+ Events Per Second (EPS)** on single CPU core ($>630\text{ Million events/day/core}$).
- **Latency**: Median processing latency $p50 = 0.125\text{ ms}$; 99th percentile $p99 = 0.256\text{ ms}$.
- **Horizontal Scalability**: Stateless pipeline architecture allows linear scaling across Kubernetes pods or container clusters to process tens of billions of daily events.
