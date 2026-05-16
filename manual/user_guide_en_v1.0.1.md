# URSP Rule Analyzer User Guide

**Version:** v1.0.0  
**Last Updated:** 2026-05-13

---

## 1. How to Run

1. Double-click the `URSP-Rule-Analyzer-v1.0.0.exe` file.
2. A console window will display the message `Access the application at: http://127.0.0.1:8081`.
3. Open the address in your web browser.
4. To quit: close the console window or press `Ctrl+C`.

> If a firewall warning appears, select "Allow". The application runs locally only.

---

## 2. Screen Layout

| Area | Description |
|------|-------------|
| Header | Program title, version, 📖 Guide button, 🔗 GitHub link |
| Tab Bar | Encoder / Decoder / Result tab switching + action buttons (PLMN, Encoding/Decoding) |
| Main Area | Content of the selected tab |
| Bottom Bar (mobile) | PLMN input + Encoding/Decoding buttons |

---

## 3. Encoder Tab

### 3.1 Basic Structure

A URSP Rule consists of a **Traffic Descriptor (TD)** and a **Route Selection Descriptor (RSD)**.

- On startup, a **Match-all** rule is created by default (PV 255, cannot be deleted)
- Click `+ Add URSP Rule` to add a new rule (inserted at the top)
- When a new rule is added, existing rules are automatically collapsed
- Click a card header to expand/collapse

### 3.2 Numbering and Precedence

- **Numbering**: Rule, TD, RSD, and Comp numbers start from 1 (e.g., Rule1.TD1, Rule1.RSD1.Comp1)
- **PV (Precedence Value)**: Starts from 0 and is automatically assigned based on card order
- Higher position = lower PV = higher priority
- The Match-all rule always has PV 255 (lowest priority)

### 3.3 PLMN Configuration

Enter a 6-digit hex value on the right side of the tab bar (desktop) or the bottom bar (mobile).
- Default: `45006F` (LG U+ Korea)
- MCC/MNC concatenated format (MCC=450, MNC=06 → 45006, F-padded for odd length → 45006F)
- The program internally performs nibble-swap for encoding (45006F → 54F060)

---

## 4. Traffic Descriptor (TD) Details

Use `+ TD` to add a component, `✕` to delete (minimum 1 required)

### 4.1 OS Id + OS App Id

Set OS-specific app identifiers.

**Android mode:**
- Select `Android` from the OS dropdown
- Select from the Slice Category dropdown (ENTERPRISE, CBS, PRIORITIZE_LATENCY, etc.)

**iOS mode:**
- Select `iOS` from the OS dropdown
- App Category dropdown: gaming-6014, communication-9000, streaming-9001
- Traffic Category dropdown: defaultslice-1, video-2, background-3, voice-4, etc.
- **Custom input**: Select `custom-9XXX` in App Category → switches to text input (4-digit number starting with 9)
  - Traffic Category is automatically fixed to `wildcard-*`
  - Click `☰` button to return to dropdown mode
  - Entering a known code (6014, 9000, 9001) automatically switches back to dropdown

### 4.2 DNN

Enter the Data Network Name as text (e.g., `internet`, `business`)

### 4.3 Connection capabilities

Select multiple options via checkboxes. At least 1 must be selected.
- IMS, Internet, MMS, SUPL, IoT delay-tolerant, etc.

### 4.4 IP 3 tuple

Match traffic by combining IP address, protocol, and port.

- **IP type**: Select IPv4 / IPv6
- **IPv4**: Address (e.g., 10.0.0.1) + Subnet mask (e.g., 255.255.255.0)
- **IPv6**: Address (e.g., 2001:db8::1) + Prefix length (e.g., 64)
- **Protocol**: None / TCP / UDP / ICMP / ICMPv6 / ESP
- **Port type**: Single remote port / Remote port range
  - Single: One port number (e.g., 8080)
  - Range: Remote port low + Remote port high (e.g., 5000–6000)
- At least 1 field must be filled

### 4.5 Type of service/traffic class (ToS/TC)

Set DSCP value and mask.

**Value (DSCP):**
- Select a standard DSCP from the dropdown (CS0–CS7, AF11–AF43, EF, etc.)
- Select `Custom` to switch to text input (2 hex digits, e.g., A4)
- Click `☰` button to return to dropdown
- Entering a known value automatically switches back to dropdown

**Mask:**
- Dropdown: 0xFC (DSCP only), 0xFF (exact), 0xE0 (IP Precedence only)
- Select `Custom` to switch to text input (2 hex digits, e.g., F0)
- Same `☰` return and known-value auto-switch behavior

### 4.6 IPv4 remote address

- IPv4 address (e.g., 10.0.0.0) + Subnet mask (e.g., 255.0.0.0)
- Both must be filled or both must be empty

### 4.7 IPv6 remote address/prefix length

- IPv6 address (e.g., 2001:db8::) + Prefix length (e.g., 64)
- Both must be filled or both must be empty

### 4.8 Remote port range

- Remote port low (e.g., 1024) + Remote port high (e.g., 65535)
- low ≤ high required

### 4.9 Destination MAC address range

- Low limit (e.g., AA:BB:CC:DD:EE:00) + High limit (e.g., AA:BB:CC:DD:EE:FF)

### 4.10 Other TD Types

| Type | Description | Input |
|------|-------------|-------|
| Single remote port | Single port | Number (0–65535) |
| Protocol identifier/next header | Protocol | Dropdown |
| Security parameter index | IPSec SPI | 4-byte hex (e.g., 0x12345678) |
| Flow label | IPv6 Flow label | 3-byte hex (e.g., 0x12345) |
| Destination MAC address | Destination MAC | MAC address (e.g., AA:BB:CC:DD:EE:FF) |
| 802.1Q C-TAG/S-TAG VID | VLAN ID | Number |
| 802.1Q C-TAG/S-TAG PCP/DEI | Priority | hex |
| Ethertype | Ethernet type | hex (e.g., 0x0800) |
| Destination FQDN | Domain | Text (e.g., example.com) |
| Regular expression | Regex | Text |
| OS App Id | App identifier | Text |
| Match-all | All traffic | No value (auto-managed) |

### 4.11 TD Combination Rules

| Rule | Description |
|------|-------------|
| Multiple of same type | OR condition (only one needs to match) |
| Different type combination | AND condition (all must match) |
| PIN ID | Standalone use only (cannot combine with other TDs) |
| Single remote port ↔ Remote port range | Cannot be used simultaneously |
| Destination MAC ↔ Destination MAC range | Cannot be used simultaneously |

---

## 5. Route Selection Descriptor (RSD) Details

Use `+ RSD` to add an RSD, `+ Component` to add a component, `✕` to delete

### 5.1 S-NSSAI

Set the network slice identifier.
- **SST**: Dropdown (01=eMBB, 02=URLLC, 03=MIoT, 04=V2X, etc.)
- **SD** (optional): 0–FFFFFF (3-byte hex)
  - Input is interpreted as hex. Example: entering `10` means 0x10 (decimal 16), entering `000064` means 0x000064 (decimal 100)

### 5.2 DNN

Data Network Name for routing (e.g., `internet`, `business`)

### 5.3 SSC mode

Session and Service Continuity mode
- SSC mode 1: Default (IP address preserved)
- SSC mode 2: Switch to new PDU session
- SSC mode 3: IP address change allowed

### 5.4 Preferred access type

- 3GPP access: Cellular preferred
- Non-3GPP access: Wi-Fi etc. preferred

### 5.5 Multi-access preference

No value (selection alone is meaningful). Indicates multi-access preference.

### 5.6 Time window

- Starttime: Select start date/time
- Stoptime: Select end date/time
- Internally encoded as NTP 64-bit timestamp

### 5.7 Location criteria

Click `Edit` button → edit in a dedicated modal

**Modal layout:**
- `+ Location Area` button to add an area
- Area types: NR cell identities list / E-UTRA cell identities list / Global RAN node identities list / TAI list
- Add Cell IDs with `+ Add Id` for each area
- Input fields: PLMN (6 hex) + Cell ID (NR: 10 hex, E-UTRA: 8 hex, gNB: 8 hex) or TAC (6 hex)
- Real-time hex character count display
- Save with `💾 Save` or by closing the modal
- At least 1 Cell ID or TAI required

**TAI list encoding optimization:**
- TAIs are grouped by PLMN and TACs are sorted
- Consecutive TACs (+1 increment) are compressed as Type 1 (consecutive)
- Remaining TACs are merged into a single Type 0 (non-consecutive) to save bytes

### 5.8 PDU session pair ID

PDU session pair identifier (dropdown)

### 5.9 RSN (Redundancy Sequence Number)

Redundancy transmission sequence number (dropdown: v1, v2)

### 5.10 Other RSD Types

| Type | Description |
|------|-------------|
| PDU session type | IPv4 / IPv6 / IPv4v6 |
| Non-seamless non-3GPP offload | No value (standalone use) |
| 5G ProSe layer-3 UE-to-network relay offload | No value (standalone use) |
| 5G ProSe multi-path preference | No value |

### 5.11 RSD Combination Rules

| Rule | Description |
|------|-------------|
| Duplicate same type | Not allowed (no more than one of the same type within a single RSD) |
| Non-seamless offload | Standalone use (cannot combine with other components) |
| 5G ProSe relay offload | Standalone use |
| Preferred access type ↔ Multi-access preference | Cannot be used simultaneously |
| PDU session pair ID ↔ Multi-access preference | Cannot be used simultaneously |
| RSN ↔ Multi-access preference | Cannot be used simultaneously |
| 5G ProSe relay offload ↔ 5G ProSe multi-path | Cannot be used simultaneously |

---

## 6. Encoding Execution and Error Handling

### 6.1 Encoding

1. Configure the URSP rules
2. Verify the PLMN value
3. Click the `🚀 Encoding` button
4. On success, the view automatically switches to the Result tab

### 6.2 When an Error Occurs

- An error message is displayed as a badge at the top
  - Red badge: Error code (e.g., E-TD02)
  - Green/pink badge: Location (e.g., Rule1.TD1)
- The corresponding component is highlighted with a red border
- Collapsed cards are automatically expanded
- The view scrolls to the first error location

### 6.3 Resolving Errors

- **Fix the value**: Entering a valid value removes the red box in real time
- **Delete the component**: If an exclusive/standalone condition is resolved, the highlight is automatically removed
- **Change the type**: Changing a conflicting type to another automatically removes the highlight
- When all errors are resolved, the top error message is also automatically removed

---

## 7. Decoder Tab

1. Paste hex data into the text area
2. Click the `🔍 Decoding` button
3. On success, the view switches to the Result tab

**Supported input formats:**
- Wireshark hex dump (with offset):
  ```
  0000   68 05 00 1F 97 01 00 1B ...
  ```
- Plain hex string:
  ```
  6805001F9701001B...
  ```

**Supported message types:**
- `6805...`: DL NAS Transport
- `80...`: SIM EF_URSP

**Auxiliary buttons:**
- `🗑 Clear`: Reset the text area
- `📋 Load Sample`: Load sample data for testing

---

## 8. Result Tab

Encoding/decoding results are displayed in 3 cards.
- Desktop: 3-column grid layout
- Mobile: Horizontal swipe (dot indicator at the bottom)

### 8.1 URSP RULE Card (purple header)

- **Tree view** (default): Displays rules in a hierarchical structure
- **JSON view**: Displays in JSON format
- `📋 Copy`: Copies the current view content to clipboard

### 8.2 SIM EF.URSP Card (green header)

- **Table view** (default): Bytemap table (Idx, Hex, Description)
  - Length fields automatically display the decimal value after the description (1-byte: direct value, 2-byte: combined value)
- **Hex view**: Hex dump with offset
- `📋 Copy`: Table → TSV (pasteable into Excel), Hex → raw hex string

> **Usage**: This hex value can be directly written to the SIM card's EF_URSP file for network slicing testing. Tools for SIM write:
> - [SIM AT Command](https://github.com/joostone-ahn/sim-at-command-releases) — AT command-based SIM file read/write
> - [SIM OTA Test](https://github.com/joostone-ahn/sim-ota-test-releases) — OTA-based SIM provisioning test

### 8.3 DL NAS TRANSPORT Card (blue header)

- **Table view** (default): Bytemap table (Idx, Hex, Description)
  - Length fields automatically display the decimal value after the description (1-byte: direct value, 2-byte: combined value)
- **Hex view**: Hex dump with offset
- **Hex view**: Hex dump with offset
- `📦 PCAP`: Download a .pcap file that can be opened in Wireshark
- `✏️ Edit`: Direct edit mode for PTI/UPSC values
  - Editable fields are highlighted in yellow
  - Edit the 2-digit hex value and click `💾 Save`
  - Modified values are automatically reflected in the Hex view
- `📋 Copy`: Table → TSV (Excel-compatible), Hex → raw hex string

---

## 9. Guide Modal

Displayed when clicking the `📖 Guide` button in the header.

**Contents:**
- Abbreviation descriptions (URSP, TD, RSD, PTI, PLMN, UPSC, PV)
- URSP Rule structure (PV, TD, RSD relationships)
- TD validation rules (Same Type: OR, Different: AND, Standalone, Exclusive)
- RSD validation rules (No duplicates, Standalone use, Exclusive pairs, PV rules)

Close: `✕` button, background click, or `Esc` key

---

## 10. FAQ

**Q: An error occurs during encoding.**  
A: Check the error code (e.g., E-TD02) and location (e.g., Rule1.TD1). The corresponding component will be highlighted in red.

**Q: Can I delete the Match-all rule?**  
A: No. It is mandatory per 3GPP specifications and is automatically managed by the program.

**Q: How do I use the PCAP file?**  
A: Download it using the `📦 PCAP` button on the DL NAS card, then open it in Wireshark — it will be automatically decoded as NAS-5GS protocol.

**Q: The program does not start.**  
A: Check whether port 8081 is already in use by another program.

**Q: Can I paste Table data copied with the Copy button into Excel?**  
A: Yes. Copying from the Table view uses TSV (tab-separated) format, which can be pasted directly into Excel.

**Q: What value should I enter for iOS custom App Category?**  
A: Enter a 4-digit number starting with 9 (e.g., 9500). If you enter a known code (6014, 9000, 9001), it will automatically switch to the dropdown.

**Q: How do I enter a custom ToS/TC value?**  
A: Enter exactly 2 hex digits (e.g., A4). If you enter a known DSCP value, it will automatically switch to the dropdown.

---

**© 2026 JUSEOK AHN <ajs3013@lguplus.co.kr> All rights reserved.**
