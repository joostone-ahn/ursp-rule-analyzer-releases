# 📡 URSP Rule Analyzer

A powerful web-based tool for analyzing URSP (UE Route Selection Policy) rules used in 5G network slicing. Built to assist engineers interpreting protocol logs or provisioning rules on real devices.

![License](https://img.shields.io/badge/License-All%20Rights%20Reserved-red)

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
- **PCAP Export** — Download encoded results as .pcap for Wireshark analysis
- **Multiple Views** — Tree, JSON, PCAP (tshark + Lua plugin, requires Wireshark), Bytemap Table, and raw Hex output
- **Round-trip Verified** — All 37 component types (53 cases) tested against Wireshark (tshark 4.6.5)
- **Offline Ready** — Runs as a standalone Windows EXE with no external dependencies

---

## 🌐 Online Demo

**[Try Online Demo](https://ursp-rule-analyzer.onrender.com/)**

> ⚠️ **Note**: Instance may sleep after inactivity. First access can take 30–60s to wake up. PCAP view is not available in the online demo (requires local Wireshark installation).

---

## 💻 Download

Download the latest exe from [Releases](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/releases).

---

## 📖 How to Use

See the User Guide for detailed instructions:
- [English](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/blob/main/manual/user_guide_en_v1.2.1.md)
- [한국어](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/blob/main/manual/user_guide_kr_v1.2.1.md)

---

## 🔌 Wireshark Lua Plugin

Wireshark cannot fully parse several URSP types (Location criteria, Time window, Regular expression, etc.), displaying "IE not dissected yet" and losing all subsequent components. The included Lua plugin resolves all parsing gaps — covering all 37 types (RSD 13 + TD 24). See the [Verification Report](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/blob/main/wireshark/wireshark_protocol_verification.md) for Wireshark native parsing status, Lua plugin resolution, and format consistency verification results.

**How to apply:**
1. Download `ursp_extended_info.lua` from [Releases](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/releases)
2. Copy to Wireshark Personal Lua Plugins folder:
   - Windows: `%APPDATA%\Wireshark\plugins\`
   - macOS: `~/.local/lib/wireshark/plugins/`
   - Linux: `~/.local/lib/wireshark/plugins/`
3. Restart Wireshark — the plugin loads automatically

> The plugin does NOT replace Wireshark's built-in dissection. It adds supplementary annotations as a collapsible tree at the bottom of the packet.

For supported types, PCAP view behavior, and detailed explanation, see "Wireshark Lua Plugin" section in the User Guide.

---

## 📖 References

### 3GPP Standards
- [TS 24.526](https://www.3gpp.org/ftp/Specs/archive/24_series/24.526/) - UE Policy Container (URSP)
- [TS 24.501](https://www.3gpp.org/ftp/Specs/archive/24_series/24.501/) - NAS Signaling Procedures
- [TS 31.102](https://www.3gpp.org/ftp/Specs/archive/31_series/31.102/) - EF_URSP File Format in USIM Application
- [TS 23.503](https://www.3gpp.org/ftp/Specs/archive/23_series/23.503/) - Policy and Charging Control Framework

---

##  Change History

| Version | Date | Description |
|---------|------|-------------|
| v1.0.0 | 2026-05-17 | Initial release |
| v1.0.1 | 2026-05-17 | Encoder: improved empty field validation for IPv4/IPv6 standalone TD (E-TD03–E-TD10), fixed mobile action bar desktop bug |
| v1.0.2 | 2026-05-22 | Encoder: fixed iOS Traffic Category data model retaining stale value |
| v1.0.3 | 2026-05-22 | Added Lite edition (device-compatible types only), TD auto-type selection improvement |
| v1.1.0 | 2026-05-28 | Wireshark Lua plugin (Location criteria, Time window, Conn Cap Rel-18, OS Id/App Id, FQDN), Result tab UI overhaul, Time window UTC+KST, UPSC Edit fix |
| v1.1.1 | 2026-05-29 | Lua full RSD/TD parsing (all 37 types), PCAP view unified output, directory restructure, verification report |
| v1.1.2 | 2026-05-30 | Lua plugin: TAI list Type 2/3 fix, Location criteria field labels aligned with 3GPP TS 24.526 |
| v1.1.3 | 2026-05-30 | Destination FQDN: RFC 1035 label format encoding (TS 23.003 clause 19.4.2.1) |

---

## 👤 Author

**JUSEOK AHN (안주석)**  
**Email**: ajs3013@lguplus.co.kr  
**Organization**: LG U+  
**Role**: Technical Specialist, Telecommunications Engineer

---

## 📄 License

© 2026 JUSEOK AHN <ajs3013@lguplus.co.kr>. All rights reserved.

This software is provided free of charge for personal and internal use.
You may not modify, distribute, sublicense, or sell copies of this software
without explicit written permission from the author.
