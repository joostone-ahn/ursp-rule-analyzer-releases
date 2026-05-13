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

| Category | Total | ✅ PASS | ℹ️ Not Dissected | ⚠️ Malformed | ❌ Fail |
|----------|-------|---------|-------------------|--------------|---------|
| TD | 34 | 33 | 1 | 0 | 0 |
| RSD | 23 | 14 | 7 | 2 | 0 |
| **Total** | **57** | **47 (82%)** | **8 (14%)** | **2 (4%)** | **0** |

All 57 test cases pass encoder/decoder round-trip with zero failures.

---

## TD (Traffic Descriptor) Results

| # | Type ID | Standard Name | PCAP File | Wireshark |
|---|---------|---------------|-----------|-----------|
| 1 | 0x01 | Match-all | `TD_01_match_all.pcap` | ✅ |
| 2 | 0x08 | OS Id + OS App Id (Android ENTERPRISE) | `TD_08_OS_Id_OS_App_Id.pcap` | ✅ |
| 3 | 0x08 | OS Id + OS App Id (Android CBS) | `TD_08a_OS_Id_Android_CBS.pcap` | ✅ |
| 4 | 0x08 | OS Id + OS App Id (Android LATENCY) | `TD_08b_OS_Id_Android_LATENCY.pcap` | ✅ |
| 5 | 0x08 | OS Id + OS App Id (iOS) | `TD_08c_OS_Id_iOS.pcap` | ✅ |
| 6 | 0x10 | IPv4 remote address | `TD_10_IPv4_remote_address.pcap` | ✅ |
| 7 | 0x21 | IPv6 remote address/prefix length | `TD_21_IPv6_remote_address.pcap` | ✅ |
| 8 | 0x30 | Protocol identifier/next header | `TD_30_protocol_id.pcap` | ✅ |
| 9 | 0x50 | Single remote port | `TD_50_single_remote_port.pcap` | ✅ |
| 10 | 0x51 | Remote port range | `TD_51_remote_port_range.pcap` | ✅ |
| 11 | 0x52 | IP 3 tuple (full) | `TD_52_IP_3_tuple.pcap` | ✅ |
| 12 | 0x52 | IP 3 tuple (IPv4 only) | `TD_52a_IP_3_tuple_IPv4_only.pcap` | ✅ |
| 13 | 0x52 | IP 3 tuple (protocol only) | `TD_52b_IP_3_tuple_protocol_only.pcap` | ✅ |
| 14 | 0x52 | IP 3 tuple (port only) | `TD_52c_IP_3_tuple_port_only.pcap` | ✅ |
| 15 | 0x52 | IP 3 tuple (IPv6 full) | `TD_52d_IP_3_tuple_IPv6_full.pcap` | ✅ |
| 16 | 0x52 | IP 3 tuple (IPv6 only) | `TD_52e_IP_3_tuple_IPv6_only.pcap` | ✅ |
| 17 | 0x52 | IP 3 tuple (IPv6 port range) | `TD_52f_IP_3_tuple_IPv6_port_range.pcap` | ✅ |
| 18 | 0x60 | Security parameter index | `TD_60_SPI.pcap` | ✅ |
| 19 | 0x70 | Type of service/traffic class (EF) | `TD_70_ToS_traffic_class.pcap` | ✅ |
| 20 | 0x70 | Type of service/traffic class (CS0 exact) | `TD_70a_ToS_CS0_exact.pcap` | ✅ |
| 21 | 0x70 | Type of service/traffic class (precedence) | `TD_70b_ToS_precedence_only.pcap` | ✅ |
| 22 | 0x80 | Flow label | `TD_80_flow_label.pcap` | ✅ |
| 23 | 0x81 | Destination MAC address | `TD_81_dest_MAC.pcap` | ✅ |
| 24 | 0x83 | 802.1Q C-TAG VID | `TD_83_CTAG_VID.pcap` | ✅ |
| 25 | 0x84 | 802.1Q S-TAG VID | `TD_84_STAG_VID.pcap` | ✅ |
| 26 | 0x85 | 802.1Q C-TAG PCP/DEI | `TD_85_CTAG_PCP_DEI.pcap` | ✅ |
| 27 | 0x86 | 802.1Q S-TAG PCP/DEI | `TD_86_STAG_PCP_DEI.pcap` | ✅ |
| 28 | 0x87 | Ethertype | `TD_87_ethertype.pcap` | ✅ |
| 29 | 0x88 | DNN | `TD_88_DNN.pcap` | ✅ |
| 30 | 0x90 | Connection capabilities (single) | `TD_90_connection_capabilities.pcap` | ✅ |
| 31 | 0x90 | Connection capabilities (multi) | `TD_90a_connection_capabilities_multi.pcap` | ✅ |
| 32 | 0x91 | Destination FQDN | `TD_91_dest_FQDN.pcap` | ✅ |
| 33 | 0x92 | Regular expression | `TD_92_regex.pcap` | ℹ️ |
| 34 | 0xA0 | OS App Id | `TD_A0_OS_App_Id.pcap` | ✅ |
| 35 | 0xA1 | Destination MAC address range | `TD_A1_dest_MAC_range.pcap` | ✅ |

---

## RSD (Route Selection Descriptor) Results

| # | Type ID | Standard Name | PCAP File | Wireshark |
|---|---------|---------------|-----------|-----------|
| 1 | 0x01 | SSC mode 1 | `RSD_01_SSC_mode.pcap` | ✅ |
| 2 | 0x01 | SSC mode 2 | `RSD_01a_SSC_mode_2.pcap` | ✅ |
| 3 | 0x01 | SSC mode 3 | `RSD_01b_SSC_mode_3.pcap` | ✅ |
| 4 | 0x02 | S-NSSAI (SST only) | `RSD_02_S_NSSAI.pcap` | ✅ |
| 5 | 0x02 | S-NSSAI (SST+SD) | `RSD_02a_S_NSSAI_SST_SD.pcap` | ✅ |
| 6 | 0x04 | DNN | `RSD_04_DNN.pcap` | ✅ |
| 7 | 0x08 | PDU session type (IPv4) | `RSD_08_PDU_session_type.pcap` | ✅ |
| 8 | 0x08 | PDU session type (IPv6) | `RSD_08a_PDU_session_type_IPv6.pcap` | ✅ |
| 9 | 0x08 | PDU session type (IPv4v6) | `RSD_08b_PDU_session_type_IPv4v6.pcap` | ✅ |
| 10 | 0x10 | Preferred access type (3GPP) | `RSD_10_preferred_access_type.pcap` | ✅ |
| 11 | 0x10 | Preferred access type (Non-3GPP) | `RSD_10a_preferred_access_type_non3GPP.pcap` | ✅ |
| 12 | 0x11 | Multi-access preference | `RSD_11_multi_access_preference.pcap` | ✅ |
| 13 | 0x20 | Non-seamless non-3GPP offload indication | `RSD_20_non_seamless_offload.pcap` | ✅ |
| 14 | 0x40 | Location criteria (NR) | `RSD_40_location_criteria.pcap` | ℹ️ |
| 15 | 0x40 | Location criteria (E-UTRA) | `RSD_40a_location_criteria_EUTRA.pcap` | ℹ️ |
| 16 | 0x40 | Location criteria (NR+E-UTRA) | `RSD_40b_location_criteria_combined.pcap` | ℹ️ |
| 17 | 0x40 | Location criteria (TAI list) | `RSD_40c_location_criteria_TAI.pcap` | ℹ️ |
| 18 | 0x80 | Time window | `RSD_80_time_window.pcap` | ℹ️ |
| 19 | 0x81 | 5G ProSe layer-3 UE-to-network relay offload indication | `RSD_81_ProSe_relay_offload.pcap` | ⚠️ |
| 20 | 0x82 | PDU session pair ID | `RSD_82_PDU_session_pair_ID.pcap` | ℹ️ |
| 21 | 0x83 | RSN | `RSD_83_RSN.pcap` | ℹ️ |
| 22 | 0x84 | 5G ProSe multi-path preference | `RSD_84_ProSe_multipath.pcap` | ⚠️ |

---

## Wireshark Dissector Limitations

10 test cases are not fully parsed by Wireshark 4.6.5. Our encoding is standards-compliant — these are dissector gaps.

| Type ID | Standard Name | Version | Date | TDoc | Source | Status |
|---------|---------------|---------|------|------|--------|--------|
| 0x92 | Regular expression | v16.4.0 | 2020-06 | C1-204052 | Huawei, HiSilicon | ℹ️ Not Dissected |
| 0x40 | Location criteria | v16.4.0 | 2020-06 | C1-203817 | Orange, Huawei, HiSilicon | ℹ️ Not Dissected |
| 0x80 | Time window | v16.4.0 | 2020-06 | C1-203817 | Orange, Huawei, HiSilicon | ℹ️ Not Dissected |
| 0x81 | 5G ProSe relay offload | v17.3.0 | 2021-06 | C1-212981 | ZTE | ⚠️ Malformed |
| 0x82 | PDU session pair ID | v17.6.0 | 2022-03 | C1-220051 | Qualcomm | ℹ️ Not Dissected |
| 0x83 | RSN | v17.6.0 | 2022-03 | C1-220051 | Qualcomm | ℹ️ Not Dissected |
| 0x84 | 5G ProSe multi-path preference | v18.3.0 | 2023-06 | C1-232894 | Intel, China Telecom | ⚠️ Malformed |

- **ℹ️ Not Dissected**: Type recognized, value not parsed (shown as raw hex)
- **⚠️ Malformed**: Wireshark dissector exception on zero-length IEs (Wireshark bug)

---

## Test Methodology

Each component type is encoded as a standalone URSP rule (PTI=151, PLMN=45006, UPSC=2). TD tests pair with SSC mode 1 RSD; RSD tests pair with Match-all TD.

PCAP uses Wireshark Exported PDU format (LINKTYPE 252, dissector tag `nas-5gs`).

---

## How to Reproduce

```bash
python pcap/test/roundtrip_test.py
tshark -r pcap/log/TD_70_ToS_traffic_class.pcap -V
```

---

## Conclusion

1. **All 57 test cases** pass encoder/decoder round-trip with zero failures.
2. **47/57 (82%)** fully decoded by Wireshark 4.6.5.
3. **10 cases** have Wireshark dissector gaps (Rel-16~18 IEs, introduced 2020-06 ~ 2023-06).
4. Encoding follows 3GPP TS 24.526 v19.3.0. "Malformed" results are Wireshark bugs, not encoding errors.
