# 📡 URSP Rule Analyzer

A powerful web-based tool for analyzing URSP (UE Route Selection Policy) rules used in 5G network slicing. Built to assist engineers interpreting protocol logs or provisioning rules on real devices.

[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

---

## 💡 Why This Tool?

E2E testing of 5G network slicing requires PCF, AMF, SMF, and gNB to be ready simultaneously. In practice, infrastructure readiness varies across entities, making immediate testing difficult.

With a **Rel.16+ SIM card**, you can provision URSP rules directly onto the device and validate slice routing **without waiting for core network readiness**. The UE applies rules from EF_URSP locally.

This tool enables that workflow:
- **Encode** — Build URSP rules visually → generate SIM + NAS hex → write to SIM for immediate device testing
- **Decode** — Paste hex from SIM dumps or NAS traces → get byte-level protocol breakdown (covers URSP rule details that Wireshark doesn't fully decode)
- **Cross-validate** — Compare your PCF/5GC implementation output against this spec-based reference

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

**[Try Online Demo](https://ursp-rule-analyzer.onrender.com/)**

> ⚠️ **Note**: Instance may sleep after inactivity. First access can take 30–60s to wake up.

---

## 💻 Download

Download the latest exe from [Releases](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/releases).

---

## 📖 How to Use

See the User Guide for detailed instructions:
- [English](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/blob/main/manual/user_guide_en_v1.0.1.md)
- [한국어](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/blob/main/manual/user_guide_kr_v1.0.1.md)

---

## ✅ Protocol Verification

All 36 URSP component types verified through 52 structural test cases:

**Encoder → Decoder → PCAP Export → Wireshark (tshark 4.6.5)**

| Category | Types (Cases) | ✅ Pass | ℹ️ WS Limitation | ❌ Fail |
|----------|---------------|---------|-------------------|---------|
| TD (Traffic Descriptor) | 23 (35) | 22 | 1 | 0 |
| RSD (Route Selection Descriptor) | 13 (17) | 7 | 6 | 0 |
| **Total** | **36 (52)** | **29 (81%)** | **7 (19%)** | **0** |

> "WS Limitation" = Wireshark lacks decoding support for these types — this tool covers them.

- [Verification Report](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/blob/main/pcap/verification_report.md)

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
