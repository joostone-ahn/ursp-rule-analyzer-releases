# URSP Rule Analyzer — Wireshark Verification Report

## Overview

Round-trip verification of all TD and RSD component types defined in **3GPP TS 24.526**.

Pipeline: **Encode → Decode → PCAP Export → tshark Verify**

## Test Environment

| Item | Value |
|------|-------|
| Test Date | 2026-05-13 |
| Wireshark | TShark 4.6.5 |
| Spec | 3GPP TS 24.526 v19.3.0 (2025-06) |
| Python | 3.12 |
| Platform | macOS (darwin) |

## Summary

All 36 URSP component types verified through 52 structural test cases.

| Category | Types (Cases) | ✅ PASS | ℹ️ WS Limitation | ❌ Fail |
|----------|---------------|---------|-------------------|---------|
| TD | 23 (35) | 22 | 1 | 0 |
| RSD | 13 (17) | 7 | 6 | 0 |
| **Total** | **36 (52)** | **29 (81%)** | **7 (19%)** | **0** |

All 52 test cases pass encoder/decoder round-trip with zero failures.

---

### TD Summary (23 types)

| # | Type ID | Standard Name | Cases | Wireshark |
|---|---------|---------------|-------|-----------|
| 1 | 0x01 | Match-all | 1 | ✅ |
| 2 | 0x08 | OS Id + OS App Id | 4 | ✅ |
| 3 | 0x10 | IPv4 remote address | 1 | ✅ |
| 4 | 0x21 | IPv6 remote address/prefix length | 1 | ✅ |
| 5 | 0x30 | Protocol identifier/next header | 1 | ✅ |
| 6 | 0x50 | Single remote port | 1 | ✅ |
| 7 | 0x51 | Remote port range | 1 | ✅ |
| 8 | 0x52 | IP 3 tuple | 9 | ✅ |
| 9 | 0x60 | Security parameter index | 1 | ✅ |
| 10 | 0x70 | Type of service/traffic class | 1 | ✅ |
| 11 | 0x80 | Flow label | 1 | ✅ |
| 12 | 0x81 | Destination MAC address | 1 | ✅ |
| 13 | 0x83 | 802.1Q C-TAG VID | 1 | ✅ |
| 14 | 0x84 | 802.1Q S-TAG VID | 1 | ✅ |
| 15 | 0x85 | 802.1Q C-TAG PCP/DEI | 1 | ✅ |
| 16 | 0x86 | 802.1Q S-TAG PCP/DEI | 1 | ✅ |
| 17 | 0x87 | Ethertype | 1 | ✅ |
| 18 | 0x88 | DNN | 1 | ✅ |
| 19 | 0x90 | Connection capabilities | 2 | ✅ |
| 20 | 0x91 | Destination FQDN | 1 | ✅ |
| 21 | 0x92 | Regular expression | 1 | ℹ️ |
| 22 | 0xA0 | OS App Id | 1 | ✅ |
| 23 | 0xA1 | Destination MAC address range | 1 | ✅ |

### RSD Summary (13 types)

| # | Type ID | Standard Name | Cases | Wireshark |
|---|---------|---------------|-------|-----------|
| 1 | 0x01 | SSC mode | 1 | ✅ |
| 2 | 0x02 | S-NSSAI | 2 | ✅ |
| 3 | 0x04 | DNN | 1 | ✅ |
| 4 | 0x08 | PDU session type | 1 | ✅ |
| 5 | 0x10 | Preferred access type | 1 | ✅ |
| 6 | 0x11 | Multi-access preference | 1 | ✅ |
| 7 | 0x20 | Non-seamless non-3GPP offload indication | 1 | ✅ |
| 8 | 0x40 | Location criteria | 4 | ℹ️ |
| 9 | 0x80 | Time window | 1 | ℹ️ |
| 10 | 0x81 | 5G ProSe relay offload | 1 | ⚠️ |
| 11 | 0x82 | PDU session pair ID | 1 | ℹ️ |
| 12 | 0x83 | RSN | 1 | ℹ️ |
| 13 | 0x84 | 5G ProSe multi-path preference | 1 | ⚠️ |

---

## Detailed Results

> 📁 All PCAP files: [pcap/log/](https://github.com/joostone-ahn/ursp-rule-analyzer-releases/tree/main/pcap/log)

### TD Detailed (all 35 cases)

| Case | Type ID | Description | PCAP File | Result |
|------|---------|-------------|-----------|--------|
| 1 | 0x01 | Match-all | `TD_01_match_all.pcap` | ✅ |
| 2-1 | 0x08 | OS Id (Android ENTERPRISE) | `TD_08_1_OS_Id_Android_ENTERPRISE.pcap` | ✅ |
| 2-2 | 0x08 | OS Id (Android CBS) | `TD_08_2_OS_Id_Android_CBS.pcap` | ✅ |
| 2-3 | 0x08 | OS Id (iOS communication) | `TD_08_3_OS_Id_iOS.pcap` | ✅ |
| 2-4 | 0x08 | OS Id (iOS custom) | `TD_08_4_OS_Id_iOS_custom.pcap` | ✅ |
| 3 | 0x10 | IPv4 remote address | `TD_10_IPv4_remote_address.pcap` | ✅ |
| 4 | 0x21 | IPv6 remote address/prefix length | `TD_21_IPv6_remote_address.pcap` | ✅ |
| 5 | 0x30 | Protocol identifier/next header | `TD_30_protocol_id.pcap` | ✅ |
| 6 | 0x50 | Single remote port | `TD_50_single_remote_port.pcap` | ✅ |
| 7 | 0x51 | Remote port range | `TD_51_remote_port_range.pcap` | ✅ |
| 8-1 | 0x52 | IP 3 tuple (IPv4 only) | `TD_52_1_IPv4_only.pcap` | ✅ |
| 8-2 | 0x52 | IP 3 tuple (IPv4 + protocol) | `TD_52_2_IPv4_protocol.pcap` | ✅ |
| 8-3 | 0x52 | IP 3 tuple (IPv4 + proto + port) | `TD_52_3_IPv4_proto_port.pcap` | ✅ |
| 8-4 | 0x52 | IP 3 tuple (IPv4 + proto + port range) | `TD_52_4_IPv4_proto_port_range.pcap` | ✅ |
| 8-5 | 0x52 | IP 3 tuple (IPv6 only) | `TD_52_5_IPv6_only.pcap` | ✅ |
| 8-6 | 0x52 | IP 3 tuple (IPv6 + proto + port) | `TD_52_6_IPv6_proto_port.pcap` | ✅ |
| 8-7 | 0x52 | IP 3 tuple (IPv6 + proto + port range) | `TD_52_7_IPv6_proto_port_range.pcap` | ✅ |
| 8-8 | 0x52 | IP 3 tuple (protocol only) | `TD_52_8_protocol_only.pcap` | ✅ |
| 8-9 | 0x52 | IP 3 tuple (port only) | `TD_52_9_port_only.pcap` | ✅ |
| 9 | 0x60 | Security parameter index | `TD_60_SPI.pcap` | ✅ |
| 10 | 0x70 | Type of service/traffic class | `TD_70_ToS_traffic_class.pcap` | ✅ |
| 11 | 0x80 | Flow label | `TD_80_flow_label.pcap` | ✅ |
| 12 | 0x81 | Destination MAC address | `TD_81_dest_MAC.pcap` | ✅ |
| 13 | 0x83 | 802.1Q C-TAG VID | `TD_83_CTAG_VID.pcap` | ✅ |
| 14 | 0x84 | 802.1Q S-TAG VID | `TD_84_STAG_VID.pcap` | ✅ |
| 15 | 0x85 | 802.1Q C-TAG PCP/DEI | `TD_85_CTAG_PCP_DEI.pcap` | ✅ |
| 16 | 0x86 | 802.1Q S-TAG PCP/DEI | `TD_86_STAG_PCP_DEI.pcap` | ✅ |
| 17 | 0x87 | Ethertype | `TD_87_ethertype.pcap` | ✅ |
| 18 | 0x88 | DNN | `TD_88_DNN.pcap` | ✅ |
| 19-1 | 0x90 | Connection capabilities (single) | `TD_90_1_connection_capabilities_single.pcap` | ✅ |
| 19-2 | 0x90 | Connection capabilities (multi) | `TD_90_2_connection_capabilities_multi.pcap` | ✅ |
| 20 | 0x91 | Destination FQDN | `TD_91_dest_FQDN.pcap` | ✅ |
| 21 | 0x92 | Regular expression | `TD_92_regex.pcap` | ℹ️ |
| 22 | 0xA0 | OS App Id | `TD_A0_OS_App_Id.pcap` | ✅ |
| 23 | 0xA1 | Destination MAC address range | `TD_A1_dest_MAC_range.pcap` | ✅ |

### RSD Detailed (all 17 cases)

| Case | Type ID | Description | PCAP File | Result |
|------|---------|-------------|-----------|--------|
| 1 | 0x01 | SSC mode 1 | `RSD_01_SSC_mode.pcap` | ✅ |
| 2-1 | 0x02 | S-NSSAI (SST only) | `RSD_02_1_S_NSSAI_SST.pcap` | ✅ |
| 2-2 | 0x02 | S-NSSAI (SST+SD) | `RSD_02_2_S_NSSAI_SST_SD.pcap` | ✅ |
| 3 | 0x04 | DNN | `RSD_04_DNN.pcap` | ✅ |
| 4 | 0x08 | PDU session type (IPv4) | `RSD_08_PDU_session_type.pcap` | ✅ |
| 5 | 0x10 | Preferred access type (3GPP) | `RSD_10_preferred_access_type.pcap` | ✅ |
| 6 | 0x11 | Multi-access preference | `RSD_11_multi_access_preference.pcap` | ✅ |
| 7 | 0x20 | Non-seamless non-3GPP offload indication | `RSD_20_non_seamless_offload.pcap` | ✅ |
| 8-1 | 0x40 | Location criteria (NR cell) | `RSD_40_1_location_NR.pcap` | ℹ️ |
| 8-2 | 0x40 | Location criteria (E-UTRA cell) | `RSD_40_2_location_EUTRA.pcap` | ℹ️ |
| 8-3 | 0x40 | Location criteria (NR + E-UTRA) | `RSD_40_3_location_combined.pcap` | ℹ️ |
| 8-4 | 0x40 | Location criteria (TAI list) | `RSD_40_4_location_TAI.pcap` | ℹ️ |
| 9 | 0x80 | Time window | `RSD_80_time_window.pcap` | ℹ️ |
| 10 | 0x81 | 5G ProSe relay offload | `RSD_81_ProSe_relay_offload.pcap` | ⚠️ |
| 11 | 0x82 | PDU session pair ID | `RSD_82_PDU_session_pair_ID.pcap` | ℹ️ |
| 12 | 0x83 | RSN | `RSD_83_RSN.pcap` | ℹ️ |
| 13 | 0x84 | 5G ProSe multi-path preference | `RSD_84_ProSe_multipath.pcap` | ⚠️ |

---

## Wireshark Dissector Limitations

10 test cases are not fully parsed by Wireshark 4.6.5. Our encoding is standards-compliant — these are dissector gaps.

- **ℹ️ Not Dissected**: Type recognized, value not parsed (shown as raw hex)
- **⚠️ Malformed**: Wireshark dissector exception on zero-length IEs (Wireshark bug)

| Type ID | Standard Name | Version | Date | TDoc | Source | Status |
|---------|---------------|---------|------|------|--------|--------|
| 0x92 | Regular expression | v16.4.0 | 2020-06 | C1-204052 | Huawei, HiSilicon | ℹ️ Not Dissected |
| 0x40 | Location criteria | v16.4.0 | 2020-06 | C1-203817 | Orange, Huawei, HiSilicon | ℹ️ Not Dissected |
| 0x80 | Time window | v16.4.0 | 2020-06 | C1-203817 | Orange, Huawei, HiSilicon | ℹ️ Not Dissected |
| 0x81 | 5G ProSe relay offload | v17.3.0 | 2021-06 | C1-212981 | ZTE | ⚠️ Malformed |
| 0x82 | PDU session pair ID | v17.6.0 | 2022-03 | C1-220051 | Qualcomm | ℹ️ Not Dissected |
| 0x83 | RSN | v17.6.0 | 2022-03 | C1-220051 | Qualcomm | ℹ️ Not Dissected |
| 0x84 | 5G ProSe multi-path preference | v18.3.0 | 2023-06 | C1-232894 | Intel, China Telecom | ⚠️ Malformed |

---

## Test Methodology

Each component type is encoded as a standalone URSP rule (PTI=151, PLMN=45006, UPSC=2). TD tests pair with SSC mode 1 RSD; RSD tests pair with Match-all TD.

Test case selection principle: one case per structural encoding variant. Cases that differ only by a byte value (e.g., SSC mode 1/2/3) are consolidated to a single representative case. Cases where the internal encoding STRUCTURE differs (e.g., IP 3 tuple bitmap combinations, S-NSSAI with/without SD) are kept as separate cases.

PCAP uses Wireshark Exported PDU format (LINKTYPE 252, dissector tag `nas-5gs`).

---

## Conclusion

1. **All 52 test cases** pass encoder/decoder round-trip with zero failures.
2. **42/52 (81%)** fully decoded by Wireshark 4.6.5.
3. **10 cases** have Wireshark dissector gaps (Rel-16~18 IEs, introduced 2020-06 ~ 2023-06).
4. Encoding follows 3GPP TS 24.526 v19.3.0. "Malformed" results are Wireshark bugs, not encoding errors.
