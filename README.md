# 📡 URSP Rule Analyzer

A powerful web-based tool for analyzing URSP (UE Route Selection Policy) rules used in 5G network slicing. Built to assist engineers interpreting protocol logs or provisioning rules on real devices.

[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

---

## 💡 Why This Tool?

In protocol engineering, one of the most persistent challenges is dealing with raw hex data found in logs or SIM files that standard tools can't parse. Wireshark decodes NAS-level framing but does not fully interpret URSP rule internals. Manual byte counting across nested TLV structures is error-prone and time-consuming.

This tool bridges that gap by:
- Translating **hex-encoded URSP rules** into human-readable structures — and vice versa
- Supporting all 56 component types defined in 3GPP TS 24.526
- Providing multiple output formats (SIM EF_URSP, DL NAS Transport, Tree, JSON, Bytemap)

---

## ✨ Key Features

- **Encoder** — Build URSP rules via GUI and generate hex for SIM provisioning or NAS messages
- **Decoder** — Paste hex from network traces, SIM dumps, or protocol captures to decode instantly
- **Multiple Views** — Tree, JSON, Bytemap Table, and raw Hex output
- **Excel Export** — Export decoded results for documentation or reporting
- **Round-trip Verified** — All 36 component types (52 cases) tested against Wireshark (tshark 4.6.5)
- **Offline Ready** — Runs as a standalone Windows EXE with no external dependencies

---

## 🌐 Online Demo

**[Try Online Demo](https://huggingface.co/spaces/Joostone/ursp-rule-analyzer)**

---

## 💻 Download

Download the latest exe from [Releases](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/releases).

---

## 📖 How to Use

See the User Guide for detailed instructions:
- [English](manual/user_guide_en_v1.0.0.md)
- [한국어](manual/user_guide_kr_v1.0.0.md)

---

## ✅ Protocol Verification

All 36 URSP component types verified through 52 structural test cases:

**Encoder → Decoder → PCAP Export → Wireshark (tshark 4.6.5)**

| Category | Types (Cases) | ✅ Pass | ℹ️ WS Limitation | ❌ Fail |
|----------|---------------|---------|-------------------|---------|
| TD (Traffic Descriptor) | 23 (35) | 22 | 1 | 0 |
| RSD (Route Selection Descriptor) | 13 (17) | 7 | 6 | 0 |
| **Total** | **36 (52)** | **29 (81%)** | **7 (19%)** | **0** |

- [Verification Report & PCAP Files](pcap/)

---

## 📖 References

### 3GPP Standards
- [TS 24.526](https://www.3gpp.org/ftp/Specs/archive/24_series/24.526/) - UE Policy Container (URSP)
- [TS 24.501](https://www.3gpp.org/ftp/Specs/archive/24_series/24.501/) - NAS Signaling Procedures
- [TS 31.102](https://www.3gpp.org/ftp/Specs/archive/31_series/31.102/) - EF_URSP File Format in USIM Application
- [TS 23.503](https://www.3gpp.org/ftp/Specs/archive/23_series/23.503/) - Policy and Charging Control Framework

---

## 👤 Author

**JUSEOK AHN (안주석)**  
**Email**: ajs3013@lguplus.co.kr  
**Organization**: LG U+  
**Role**: Technical Specialist, Telecommunications Engineer

---

## 📄 License

**© 2026 JUSEOK AHN <ajs3013@lguplus.co.kr> All rights reserved.**

This software is proprietary and confidential.

### Applicable For
- QA teams performing 5G network slicing testing
- Engineers debugging UE-network communication
- Researchers working with modern 5G SA infrastructure
- Network operators validating URSP policies
