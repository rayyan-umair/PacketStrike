# PacketStrike

**Local-First Network Behavior Intelligence Engine**

The automated forensic sensor that silences the noise and strikes the signal - turning raw packets into **investigative evidence instead of hex dumps**.

Built by Rayyan Umair - *Technology evolves quickly. Responsibility does not.*

---

# What it does

PacketStrike captures live network traffic and inspects it at the payload level, transforming raw packet streams into:

* structured flow records
* behavioral entity profiles
* DPI-powered strike detections
* explainable 5W+H tactical intelligence

Every detection becomes a **human-readable strike narrative**:

### Instead of raw packet data:

```
TCP 10.0.0.5:49201 → 93.184.216.34:80 [PSH, ACK] len=312
```

### You get:

* WHO initiated the session (OS fingerprint, TTL/window analysis)
* WHAT was found (protocol dissection, DLP hits, entropy anomalies)
* WHERE it occurred (interface, VLAN tag, internal vs external)
* WHEN it happened (delta-T within the TCP stream)
* WHY it triggered (exact hex-offset that fired the detection)
* HOW to respond (STRIKE-REPLAY for sandboxed session replication)

No Wireshark complexity. No raw packet noise. No manual inspection.

---

# System Overview

PacketStrike is a single-process intelligence engine with a clean internal pipeline:

## Capture Layer

The ingestion front-end.

Handles:

* live interface capture (pyshark / scapy)
* PCAP file replay mode
* AF_PACKET ring buffer ingestion
* normalization into universal FlowRecord schema
* producer → internal queue → consumer pipeline

No analysis. No storage. No intelligence.

---

## Strike Engine

The intelligence core.

Handles:

* entropy scoring (hidden encryption / DNS tunneling detection)
* cleartext sensitivity scanning (DLP regex on raw buffer)
* protocol anomaly detection (RFC violation flagging)
* flow-level behavioral analysis
* entity tracking (IPs, sessions, behavior profiles)
* 5W+H strike narrative generation
* DuckDB packet spooler + Parquet historical archive
* FastAPI backend + WebSocket real-time streaming

---

# Core Concept

PacketStrike does NOT treat packets as events.

It treats them as:

> **behavioral evidence of hosts and sessions over time**

---

# Universal Flow Schema

Every captured session becomes:

```json
{
  "flow_id": "uuid",
  "timestamp": "UTC ISO8601",
  "interface": "eth0",

  "src_ip": "10.0.0.5",
  "dst_ip": "93.184.216.34",
  "src_port": 49201,
  "dst_port": 80,
  "protocol": "TCP",

  "bytes_sent": 1024,
  "bytes_received": 8192,
  "start_time": "UTC ISO8601",
  "end_time": "UTC ISO8601",
  "duration_ms": 340,

  "dpi": {
    "entropy_score": 3.2,
    "dlp_hits": [],
    "protocol_anomaly": false,
    "dissected_protocol": "HTTP",
    "os_fingerprint": "Linux 4.x"
  },

  "strike": {
    "triggered": false,
    "type": null,
    "severity": 0,
    "hex_offset": null
  },

  "raw_payload": "base64-encoded-bytes"
}
```

---

# Quick Start

## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Requires:

* Python 3.11+
* libpcap (system package)
* Root / CAP_NET_RAW for live capture

---

## 2. Start PacketStrike

```bash
python main.py
```

Runs:

* FastAPI server (default: `http://0.0.0.0:8001`)
* Live capture pipeline
* Strike Engine
* WebSocket stream at `ws://localhost:8001/ws/strikes`

---

## 3. Configure

Copy `.env.example` to `.env` and set your interface:

```bash
CAPTURE_INTERFACE=eth0
```

No cloud required. Fully local.

---

# Detection Suite

## The Five Strikes (v1)

PacketStrike ships with five core detections:

### STRIKE-001 - Port Scan
Detects systematic sweeps across multiple ports from a single source IP within the detection window.

### STRIKE-002 - Beaconing
Identifies suspiciously regular outbound connection intervals - the signature of C2 malware check-ins.

### STRIKE-003 - High Outbound Transfer
Flags sessions where outbound bytes exceed the exfiltration threshold - potential data staging or exfiltration.

### STRIKE-004 - Internal Pivot
Detects a single host authenticating laterally across multiple internal targets - post-exploitation movement.

### STRIKE-005 - Known-Bad Destination
Cross-references destination IPs and domains against the threat intelligence feed. Zero tolerance.

---

# DPI Intelligence

## Entropy Scoring

Monitors high-entropy (random-looking) content in non-encrypted protocol fields.

Catches:

* DNS tunneling
* Encrypted payloads hiding in plaintext protocols
* Obfuscated C2 channels

## Cleartext Sensitivity (DLP)

Active regex scanning on raw payload buffers for:

* Credentials (`PASS`, `USER`, `Authorization:`)
* Database exposure (`SELECT *`, `DROP TABLE`)
* Key material (`BEGIN RSA PRIVATE KEY`)
* PII patterns

## Protocol Anomaly

Flags traffic that violates RFC standards:

* HTTP traffic on port 443 (non-TLS)
* DNS packets exceeding 512 bytes without EDNS
* Unexpected protocol encapsulation

---

# Entity Intelligence

PacketStrike tracks network participants as living objects:

* IP addresses
* TCP/UDP sessions

Each entity maintains:

* traffic timeline
* behavior flags (beaconing, port_scan, internal_pivot, data_exfil, known_bad_ip)
* risk score with time-decay
* OS fingerprint (TTL + window size analysis)

---

# 5W+H Tactical Intelligence

Every strike is transformed into:

| Component | PacketStrike Output |
|-----------|-------------------|
| **WHO**   | Source fingerprint - OS guess via TTL/window size analysis |
| **WHAT**  | Protocol dissection - HTTP headers, SQL queries, raw DLP hits |
| **WHERE** | Interface index, VLAN tag ID, internal vs external classification |
| **WHEN**  | Delta-T - time since last packet in this specific TCP stream |
| **WHY**   | Exact hex-offset that triggered the detection |
| **HOW**   | STRIKE-REPLAY - sandboxed session replication |

---

# Behavior Timeline

The killer feature.

Every entity builds a narrative timeline automatically:

```
10:22:01 → STRIKE-001 Port scan detected (47 ports in 3.2s)
10:24:18 → STRIKE-002 Beaconing observed (interval: 30.0s ±0.4s)
10:31:55 → STRIKE-003 High outbound transfer (142 MB → 185.220.101.34)
```

That sequential narrative is worth more than a thousand packet dumps.

---

# Visual Identity

PacketStrike runs a high-contrast tactical HUD:

* **Primary:** Electric Cyan `#00FFD1`
* **Background:** Matte Black `#0A0A0C`
* **Strike alerts:** Neon Red (flickering on active DLP hits)
* **Idle traffic:** Dim Cyan
* **Hex dump headers:** Dim Grey
* **DLP-matched strings:** Neon Red

### The Waterfall

A real-time traffic spectrogram. High-frequency bursts (DoS) render as bright red strikes. Idle sessions render as dim cyan pulses.

### The Hex-View Matrix

16-byte hex dump with DPI overlay. Sensitive strings found via regex flicker in Neon Red. Standard protocol headers render in Dim Grey.

---

# AI Layer (Optional)

AI is NOT required.

When enabled, it acts as:

> a network forensics assistant - not a detector

It can:

* explain strike narratives in plain English
* summarize session behavior
* generate incident reports
* assist triage decisions

It cannot:

* define detection logic
* replace the Strike Engine
* fabricate packet evidence

Supported providers:

* Local LLMs (Ollama / llama.cpp)
* OpenAI
* Gemini
* Groq
* Disabled mode (fully offline)

---

# Timeline Integrity

All timestamps are normalized to:

```
UTC (RFC3339Nano)
```

Delta-T calculations are computed per TCP stream, not wall clock.

---

# Security Model

* fully local-first capable
* no cloud dependency required
* optional external AI only
* raw payloads preserved as base64 for forensic replay
* capture isolated to nominated interface only
* BPF filters applied at kernel level

---

# Performance Design

PacketStrike is optimized for:

* zero-copy ring buffer ingestion (AF_PACKET mmap)
* producer-consumer pipeline (no drop under burst)
* DuckDB as live packet spooler
* Parquet compression for historical archives
* sub-second strike detection latency

---

# Hard Constraints

* Capture layer performs ingestion only
* Strike Engine performs all analysis
* Internal queue is the transport layer
* No cross-layer business logic
* UTC is mandatory everywhere
* Flows must remain schema-compliant
* BPF filter excludes SSH by default (prevents capture loop)

---

# NetRaptor Ecosystem

PacketStrike is the **network behavior intelligence layer** of the NetRaptor platform.

Its entity profiles and strike detections feed:

* **DNStalon** - DNS behavioral intelligence
* **SIEMulate** - behavior-aware detection engine
* **TalonResponse** - incident response terminal

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

# Legal Notice

PacketStrike is a defensive cybersecurity tool.

Only use it on networks you own or are explicitly authorized to monitor.

Unauthorized packet capture may be illegal in your jurisdiction. The author accepts no liability for misuse.
