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
- **PCAP Export** — Download encoded results as .pcap for Wireshark analysis
- **Multiple Views** — Tree, JSON, PCAP (tshark + Lua plugin), Bytemap Table, and raw Hex output
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

## 🔌 Wireshark Lua Plugin

All 36 URSP component types verified through 52 structural test cases (Encoder → Decoder → PCAP Export → Wireshark tshark 4.6.6). Wireshark natively decodes 81% of cases; the remaining 19% are types Wireshark does not yet dissect. To cover these gaps, a companion Lua plugin (`ursp_extended_info.lua`) is included in each release.

- [Verification Report](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/blob/main/pcap/verification_report.md)

**What the plugin adds:**
| Feature | Wireshark (without plugin) | With plugin |
|---------|---------------------------|-------------|
| Location criteria (0x40) | "IE not dissected yet" | Full parsing (TAI list, Cell IDs, PLMN) |
| Time window (0x80) | "IE not dissected yet" | UTC timestamp display |
| Connection capabilities (0xA1~0xAB) | "Unknown (0xAx)" | Rel-18 names (IoT, streaming, etc.) |
| OS Id + OS App Id (0x08) | Raw hex only | Android/iOS category interpretation |
| OS App Id (0xA0) | Raw hex only | ASCII text display |
| Destination FQDN (0x91) | Off-by-one bug | Corrected FQDN |

**Install:**
1. Download `ursp_extended_info.lua` from [Releases](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/releases)
2. Copy to your Wireshark Personal Lua Plugins folder:
   - Windows: `C:\Users\<username>\AppData\Roaming\Wireshark\plugins\` (create `plugins` folder if it doesn't exist)
   - macOS: `~/.local/lib/wireshark/plugins/` (create folders if they don't exist)
   - To find the exact path: Wireshark → Help → About Wireshark → Folders tab → "Personal Lua Plugins"
3. Restart Wireshark — the plugin loads automatically

> The plugin does NOT replace Wireshark's built-in dissection. It adds supplementary annotations as a collapsible tree at the bottom of the packet, with location references for easy identification:
> ```
> ▼ [Extended Info: decoded by ursp_extended_info.lua]
>     ▼ URSP rule 1 → Traffic descriptor
>         ▼ OS Id + OS App Id
>             OS: Android
>             Slice Category: ENTERPRISE
>     ▼ URSP rule 1 → Route selection descriptor 1
>         ▶ Location criteria
>         ▶ Time window
> ```

---

## 📖 How to Use

See the User Guide for detailed instructions:
- [English](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/blob/main/manual/user_guide_en_v1.1.0.md)
- [한국어](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/blob/main/manual/user_guide_kr_v1.1.0.md)

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
