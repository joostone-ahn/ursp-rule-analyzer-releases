-- =============================================================================
-- URSP NAS Post-Dissector for Wireshark
-- Supplements Wireshark's built-in NAS-5GS dissector with:
--   1. Full RSD contents re-parsing when Wireshark fails (0x40/0x80/0x84 trigger)
--   2. Full TD contents re-parsing when Wireshark fails (0x92 trigger)
--   3. Location criteria (RSD 0x40) — full parsing (TAI, NR/E-UTRA/gNB)
--   4. Time window (RSD 0x80) — full parsing
--   5. Connection capabilities (TD 0x90) — Rel-18 name annotation (0xA1~0xAB)
--   6. OS Id + OS App Id (TD 0x08) — human-readable interpretation
--   7. OS App Id (TD 0xA0) — hex-to-ASCII decoding
--   8. Destination FQDN (TD 0x91) — Wireshark native parsing (RFC 1035 label format)
--
-- Full parsing covers all RSD types (13) and TD types (24) defined in
-- 3GPP TS 24.526, matching Wireshark's native output style.
--
-- NOTE: This plugin does NOT replace Wireshark's built-in dissection.
--       It adds a single collapsible tree at the bottom of the packet,
--       with each decoded item referencing its location in the URSP structure.
--
-- Install: Copy to Wireshark Personal Lua Plugins folder
--   Windows: %APPDATA%\Wireshark\plugins\
--   macOS:   ~/.local/lib/wireshark/plugins/
--   Linux:   ~/.local/lib/wireshark/plugins/
--
-- Reference: 3GPP TS 24.526, TS 24.501 Section 9.11.3.9
-- Version: 1.2.0
-- Author: JUSEOK AHN <ajs3013@lguplus.co.kr>
-- =============================================================================

local ursp_post = Proto("ursp_ext_info", "[Extended Info: decoded by ursp_extended_info.lua]")

-- ============================================================================
-- Protocol Fields
-- ============================================================================

local f_loc_len       = ProtoField.uint8("ursp_ext_info.loc.length", "Length of location criteria", base.DEC)
local f_loc_area_type = ProtoField.uint8("ursp_ext_info.loc.area_type", "Type of location area", base.DEC)
local f_loc_num_eutra = ProtoField.uint8("ursp_ext_info.loc.num_eutra", "Number of E-UTRA cell identities", base.DEC)
local f_loc_num_nr    = ProtoField.uint8("ursp_ext_info.loc.num_nr", "Number of NR cell identities", base.DEC)
local f_loc_num_gnb   = ProtoField.uint8("ursp_ext_info.loc.num_gnb", "Number of Global gNB identities", base.DEC)
local f_loc_mcc       = ProtoField.string("ursp_ext_info.loc.mcc", "Mobile Country Code (MCC)")
local f_loc_mnc       = ProtoField.string("ursp_ext_info.loc.mnc", "Mobile Network Code (MNC)")
local f_loc_nci       = ProtoField.bytes("ursp_ext_info.loc.nci", "NR Cell Identity (NCI)")
local f_loc_eci       = ProtoField.bytes("ursp_ext_info.loc.eci", "E-UTRA Cell Identity (ECI)")
local f_loc_gnb       = ProtoField.bytes("ursp_ext_info.loc.gnb_id", "gNB ID")
local f_loc_tai_len   = ProtoField.uint8("ursp_ext_info.loc.tai_len", "Length", base.DEC)
local f_loc_tai_type  = ProtoField.uint8("ursp_ext_info.loc.tai_type_num", "Type/Num octet", base.HEX)
local f_loc_tac       = ProtoField.bytes("ursp_ext_info.loc.tac", "TAC")
local f_tw_start_sec  = ProtoField.uint32("ursp_ext_info.tw.start_sec", "Start time (seconds)", base.DEC)
local f_tw_start_frac = ProtoField.uint32("ursp_ext_info.tw.start_frac", "Start time (fraction)", base.HEX)
local f_tw_stop_sec   = ProtoField.uint32("ursp_ext_info.tw.stop_sec", "Stop time (seconds)", base.DEC)
local f_tw_stop_frac  = ProtoField.uint32("ursp_ext_info.tw.stop_frac", "Stop time (fraction)", base.HEX)
local f_tw_start_str  = ProtoField.string("ursp_ext_info.tw.start_utc", "Start time")
local f_tw_stop_str   = ProtoField.string("ursp_ext_info.tw.stop_utc", "Stop time")
local f_conn_cap_name = ProtoField.string("ursp_ext_info.conn_cap.name", "Connection capability")
local f_os_name       = ProtoField.string("ursp_ext_info.os_id.os_name", "OS")
local f_app_decoded   = ProtoField.string("ursp_ext_info.os_id.app_decoded", "OS App Id (decoded)")
local f_app_ascii     = ProtoField.string("ursp_ext_info.os_app_id.ascii", "OS App Id (ASCII)")

-- Full parsing fields
local f_rsd_type      = ProtoField.string("ursp_ext_info.rsd.comp_type", "RSD component type")
local f_rsd_value     = ProtoField.string("ursp_ext_info.rsd.value", "RSD component value")
local f_td_type       = ProtoField.string("ursp_ext_info.td.comp_type", "TD component type")
local f_td_value      = ProtoField.string("ursp_ext_info.td.value", "TD component value")

ursp_post.fields = {
    f_loc_len, f_loc_area_type, f_loc_num_eutra, f_loc_num_nr, f_loc_num_gnb, f_loc_mcc, f_loc_mnc,
    f_loc_nci, f_loc_eci, f_loc_gnb, f_loc_tai_len, f_loc_tai_type, f_loc_tac,
    f_tw_start_sec, f_tw_start_frac, f_tw_stop_sec, f_tw_stop_frac,
    f_tw_start_str, f_tw_stop_str, f_conn_cap_name,
    f_os_name, f_app_decoded, f_app_ascii,
    f_rsd_type, f_rsd_value, f_td_type, f_td_value
}

-- ============================================================================
-- Constants
-- ============================================================================
local ANDROID_OS_ID = "97a498e3fc925c9489860333d06e4e47"
local IOS_OS_ID     = "4301d21197d942c9b1c2f67583c0f920"

local ios_app_categories = {
    ["6014"] = "gaming", ["9000"] = "communication", ["9001"] = "streaming",
}
local ios_traffic_categories = {
    ["1"]="defaultslice", ["2"]="video", ["3"]="background", ["4"]="voice",
    ["5"]="callsignaling", ["6"]="responsivedata", ["7"]="avstreaming",
    ["8"]="responsiveav", ["*"]="wildcard",
}
local conn_cap_names = {
    [0x01]="IMS", [0x02]="MMS", [0x04]="SUPL", [0x08]="Internet",
    [0x10]="LCS user plane positioning", [0x20]="Operator specific",
    [0xA1]="IoT delay-tolerant", [0xA2]="IoT non-delay-tolerant",
    [0xA3]="Downlink streaming", [0xA4]="Uplink streaming",
    [0xA5]="Vehicular communications", [0xA6]="Real time interactive",
    [0xA7]="Unified communications", [0xA8]="Background",
    [0xA9]="Mission critical communications", [0xAA]="Time critical communications",
    [0xAB]="Low latency loss tolerant communications",
}
local loc_area_type_names = {
    [0x01]="E-UTRA cell identities list", [0x02]="NR cell identities list",
    [0x03]="Global RAN node identities list", [0x04]="TAI list",
}
local loc_area_cell_sizes = { [0x01]=7, [0x02]=8, [0x03]=7 }
local tai_list_type_names = {
    [0]="list of TACs belonging to one PLMN, with non-consecutive TAC values",
    [1]="list of TACs belonging to one PLMN, with consecutive TAC values",
    [2]="list of TAIs belonging to different PLMNs",
    [3]="list of TAIs belonging to one PLMN, with any TAC value",
}

-- RSD component type names (3GPP TS 24.526 Table 5.2)
local rsd_type_names = {
    [0x01]="SSC mode", [0x02]="S-NSSAI", [0x04]="DNN",
    [0x08]="PDU session type", [0x10]="Preferred access type",
    [0x11]="Multi-access preference",
    [0x20]="Non-seamless non-3GPP offload indication",
    [0x40]="Location criteria", [0x80]="Time window",
    [0x81]="5G ProSe layer-3 UE-to-network relay offload indication",
    [0x82]="PDU session pair ID", [0x83]="RSN",
    [0x84]="5G ProSe multi-path preference",
}
-- RSD types with zero-length value (type-only)
local rsd_zero_types = {[0x11]=true, [0x20]=true, [0x81]=true, [0x84]=true}

-- TD component type names (3GPP TS 24.526 Table 5.2)
local td_type_names = {
    [0x01]="Match-all", [0x08]="OS Id + OS App Id",
    [0x10]="IPv4 remote address", [0x21]="IPv6 remote address/prefix length",
    [0x30]="Protocol identifier/next header",
    [0x50]="Single remote port", [0x51]="Remote port range",
    [0x52]="IP 3 tuple", [0x60]="Security parameter index",
    [0x70]="Type of service/traffic class", [0x80]="Flow label",
    [0x81]="Destination MAC address",
    [0x83]="802.1Q C-TAG VID", [0x84]="802.1Q S-TAG VID",
    [0x85]="802.1Q C-TAG PCP/DEI", [0x86]="802.1Q S-TAG PCP/DEI",
    [0x87]="Ethertype", [0x88]="DNN",
    [0x90]="Connection capabilities", [0x91]="Destination FQDN",
    [0x92]="Regular expression", [0xA0]="OS App Id",
    [0xA1]="Destination MAC address range",
    [0xA2]="PIN ID", [0xA3]="Connectivity group ID",
}

-- SSC mode value names
local ssc_mode_names = {[1]="SSC mode 1", [2]="SSC mode 2", [3]="SSC mode 3"}
-- PDU session type names
local pdu_session_type_names = {
    [1]="IPv4", [2]="IPv6", [3]="IPv4v6", [4]="Unstructured", [5]="Ethernet",
}
-- Preferred access type names
local preferred_access_type_names = {[1]="3GPP access", [2]="non-3GPP access"}
-- Protocol identifier names (common)
local protocol_id_names = {[6]="TCP", [17]="UDP", [132]="SCTP"}

-- Ethertype names (common)
local ethertype_names = {
    [0x0800]="IPv4", [0x86DD]="IPv6", [0x0806]="ARP", [0x8100]="802.1Q",
}

-- ============================================================================
-- Helper Functions
-- ============================================================================
local function decode_plmn(buf, offset)
    if buf:len() < offset + 3 then return "000", "00", offset + 3 end
    local b0 = buf(offset, 1):uint()
    local b1 = buf(offset + 1, 1):uint()
    local b2 = buf(offset + 2, 1):uint()
    local mcc = string.format("%d%d%d", bit.band(b0, 0x0F), bit.rshift(b0, 4), bit.band(b1, 0x0F))
    local mnc3 = bit.rshift(b1, 4)
    local mnc = string.format("%d%d", bit.band(b2, 0x0F), bit.rshift(b2, 4))
    if mnc3 ~= 0x0F then mnc = mnc .. string.format("%d", mnc3) end
    return mcc, mnc, offset + 3
end

local function bytes_to_hex(buf, offset, length)
    local hex = ""
    for i = 0, length - 1 do
        if offset + i < buf:len() then hex = hex .. string.format("%02x", buf(offset + i, 1):uint()) end
    end
    return hex
end

local function hex_to_ascii(hex_str)
    local ascii = ""
    for i = 1, #hex_str, 2 do
        local byte = tonumber(hex_str:sub(i, i + 1), 16)
        if byte and byte >= 0x20 and byte <= 0x7E then ascii = ascii .. string.char(byte)
        else return nil end
    end
    return ascii
end

local function epoch_to_utc(epoch)
    if epoch == 0 then return "0 (not set)" end
    return os.date("!%Y-%m-%d %H:%M:%S UTC", epoch)
end

local function compress_ipv6(hex32)
    -- Convert 32-char hex string to compressed IPv6 notation
    local groups = {}
    for i = 0, 7 do
        local g = tonumber(hex32:sub(i*4+1, i*4+4), 16)
        groups[i+1] = g
    end
    -- Find longest run of consecutive zero groups
    local best_start, best_len = -1, 0
    local cur_start, cur_len = -1, 0
    for i = 1, 8 do
        if groups[i] == 0 then
            if cur_start == -1 then cur_start = i end
            cur_len = cur_len + 1
        else
            if cur_len > best_len then
                best_start = cur_start
                best_len = cur_len
            end
            cur_start = -1
            cur_len = 0
        end
    end
    if cur_len > best_len then
        best_start = cur_start
        best_len = cur_len
    end
    -- Build compressed string
    if best_len < 2 then
        -- No compression needed
        local parts = {}
        for i = 1, 8 do
            parts[i] = string.format("%x", groups[i])
        end
        return table.concat(parts, ":")
    end
    local parts = {}
    local i = 1
    while i <= 8 do
        if i == best_start then
            if i == 1 then parts[#parts+1] = "" end
            parts[#parts+1] = ""
            if best_start + best_len - 1 == 8 then parts[#parts+1] = "" end
            i = i + best_len
        else
            parts[#parts+1] = string.format("%x", groups[i])
            i = i + 1
        end
    end
    return table.concat(parts, ":")
end

-- ============================================================================
-- Location Criteria Parser
-- ============================================================================
local function parse_location_criteria(buf, offset, length, tree)
    local loc_end = offset + length
    while offset < loc_end and offset < buf:len() do
        local area_type = buf(offset, 1):uint()
        local area_name = loc_area_type_names[area_type] or string.format("Unknown (0x%02X)", area_type)
        if area_type == 0x04 then
            tree:add(f_loc_area_type, buf(offset, 1))
                :set_text(string.format("Type of location area: %s (%d)", area_name, area_type))
            offset = offset + 1
            if offset >= buf:len() then break end
            local tai_len = buf(offset, 1):uint()
            tree:add(f_loc_tai_len, buf(offset, 1)):set_text(string.format("Length: %d", tai_len))
            offset = offset + 1
            local tai_end = offset + tai_len
            local partial_idx = 0
            while offset < tai_end and offset < buf:len() do
                partial_idx = partial_idx + 1
                local type_num_byte = buf(offset, 1):uint()
                local list_type = bit.rshift(bit.band(type_num_byte, 0x60), 5)
                local num_elements = bit.band(type_num_byte, 0x1F) + 1
                local list_type_name = tai_list_type_names[list_type] or "reserved"
                local pt = tree:add(ursp_post, buf(offset, 1),
                    string.format("Partial tracking area identity list %d", partial_idx))
                local num_raw = num_elements - 1
                pt:add(f_loc_tai_type, buf(offset, 1)):set_text("0... .... = Spare: 0")
                pt:add(f_loc_tai_type, buf(offset, 1)):set_text(string.format(
                    ".%d%d. .... = Type of list: %s (%d)",
                    bit.rshift(list_type, 1), bit.band(list_type, 1), list_type_name, list_type))
                pt:add(f_loc_tai_type, buf(offset, 1)):set_text(string.format(
                    "...%d %d%d%d%d = Number of elements: %d element%s",
                    bit.rshift(bit.band(num_raw,0x10),4), bit.rshift(bit.band(num_raw,0x08),3),
                    bit.rshift(bit.band(num_raw,0x04),2), bit.rshift(bit.band(num_raw,0x02),1),
                    bit.band(num_raw,0x01), num_elements, num_elements > 1 and "s" or ""))
                offset = offset + 1
                if list_type == 0 then
                    -- Type 0: same PLMN, list of non-consecutive TACs
                    if offset + 3 > buf:len() then break end
                    local mcc, mnc, new_off = decode_plmn(buf, offset)
                    pt:add(f_loc_mcc, buf(offset, 3), mcc):set_text("Mobile Country Code (MCC): " .. mcc)
                    pt:add(f_loc_mnc, buf(offset, 3), mnc):set_text("Mobile Network Code (MNC): " .. mnc)
                    offset = new_off
                    for t = 1, num_elements do
                        if offset + 3 > buf:len() then break end
                        pt:add(f_loc_tac, buf(offset, 3)):set_text(string.format("TAC: %d", buf(offset, 3):uint()))
                        offset = offset + 3
                    end
                elseif list_type == 1 then
                    -- Type 1: same PLMN, consecutive TACs (first TAC only)
                    if offset + 3 > buf:len() then break end
                    local mcc, mnc, new_off = decode_plmn(buf, offset)
                    pt:add(f_loc_mcc, buf(offset, 3), mcc):set_text("Mobile Country Code (MCC): " .. mcc)
                    pt:add(f_loc_mnc, buf(offset, 3), mnc):set_text("Mobile Network Code (MNC): " .. mnc)
                    offset = new_off
                    if offset + 3 <= buf:len() then
                        pt:add(f_loc_tac, buf(offset, 3)):set_text(string.format("TAC: %d", buf(offset, 3):uint()))
                        offset = offset + 3
                    end
                elseif list_type == 2 then
                    -- Type 2: different PLMNs, each element has its own PLMN + TAC
                    for t = 1, num_elements do
                        if offset + 6 > buf:len() then break end
                        local mcc, mnc, new_off = decode_plmn(buf, offset)
                        pt:add(f_loc_mcc, buf(offset, 3), mcc):set_text("Mobile Country Code (MCC): " .. mcc)
                        pt:add(f_loc_mnc, buf(offset, 3), mnc):set_text("Mobile Network Code (MNC): " .. mnc)
                        offset = new_off
                        if offset + 3 > buf:len() then break end
                        pt:add(f_loc_tac, buf(offset, 3)):set_text(string.format("TAC: %d", buf(offset, 3):uint()))
                        offset = offset + 3
                    end
                elseif list_type == 3 then
                    -- Type 3: same PLMN, no TAC (all TAIs of the PLMN)
                    if offset + 3 > buf:len() then break end
                    local mcc, mnc, new_off = decode_plmn(buf, offset)
                    pt:add(f_loc_mcc, buf(offset, 3), mcc):set_text("Mobile Country Code (MCC): " .. mcc)
                    pt:add(f_loc_mnc, buf(offset, 3), mnc):set_text("Mobile Network Code (MNC): " .. mnc)
                    offset = new_off
                end
            end
        else
            local cell_size = loc_area_cell_sizes[area_type] or 8
            tree:add(f_loc_area_type, buf(offset, 1))
                :set_text(string.format("Type of location area: %s (%d)", area_name, area_type))
            offset = offset + 1
            if offset >= buf:len() then break end
            local num_cells = buf(offset, 1):uint()
            local f_num, num_label
            if area_type == 0x02 then
                f_num = f_loc_num_nr
                num_label = "Number of NR cell identities: "
            elseif area_type == 0x01 then
                f_num = f_loc_num_eutra
                num_label = "Number of E-UTRA cell identities: "
            else
                f_num = f_loc_num_gnb
                num_label = "Number of Global gNB identities: "
            end
            tree:add(f_num, buf(offset, 1)):set_text(num_label .. num_cells)
            offset = offset + 1
            for c = 1, num_cells do
                if offset + cell_size > buf:len() then break end
                local cs = offset
                local cl
                if area_type == 0x02 then cl = string.format("NR cell id %d", c)
                elseif area_type == 0x01 then cl = string.format("E-UTRA cell id %d", c)
                else cl = string.format("Global gNB id %d", c) end
                local ct = tree:add(ursp_post, buf(cs, cell_size), cl)
                local mcc, mnc, pe = decode_plmn(buf, offset)
                ct:add(f_loc_mcc, buf(offset, 3), mcc):set_text("Mobile Country Code (MCC): " .. mcc)
                ct:add(f_loc_mnc, buf(offset, 3), mnc):set_text("Mobile Network Code (MNC): " .. mnc)
                offset = pe
                local id_len = cell_size - 3
                local id_hex = bytes_to_hex(buf, offset, id_len)
                if area_type == 0x02 then ct:add(f_loc_nci, buf(offset, id_len)):set_text("NR Cell ID: 0x" .. id_hex)
                elseif area_type == 0x01 then ct:add(f_loc_eci, buf(offset, id_len)):set_text("E-UTRA Cell ID: 0x" .. id_hex)
                else ct:add(f_loc_gnb, buf(offset, id_len)):set_text("gNB ID: 0x" .. id_hex) end
                offset = offset + id_len
            end
        end
    end
end

-- ============================================================================
-- Time Window Parser
-- ============================================================================
local function parse_time_window(buf, offset, tree)
    if buf:len() < offset + 16 then return end
    local ss = buf(offset, 4):uint()
    local sf = buf(offset + 4, 4):uint()
    local es = buf(offset + 8, 4):uint()
    local ef = buf(offset + 12, 4):uint()
    local start_str = ss > 0 and os.date("!%b %d, %Y %H:%M:%S", ss) or "not set"
    local stop_str = es > 0 and os.date("!%b %d, %Y %H:%M:%S", es) or "not set"
    tree:add(f_tw_start_str, buf(offset, 8), start_str)
        :set_text(string.format("Starttime: %s.%09d UTC", start_str, sf))
    tree:add(f_tw_stop_str, buf(offset + 8, 8), stop_str)
        :set_text(string.format("Stoptime: %s.%09d UTC", stop_str, ef))
end

-- ============================================================================
-- DNN Parser (shared by RSD and TD)
-- ============================================================================
local function parse_dnn_value(buf, offset)
    -- DNN: len(1) + apn_len(1) + ascii
    if offset >= buf:len() then return nil, offset end
    local dnn_len = buf(offset, 1):uint()
    offset = offset + 1
    if offset >= buf:len() then return nil, offset end
    local apn_len = buf(offset, 1):uint()
    offset = offset + 1
    if offset + apn_len > buf:len() then return nil, offset end
    local dnn = buf(offset, apn_len):string()
    offset = offset + apn_len
    return dnn, offset
end

-- ============================================================================
-- RSD Contents Full Parser
-- ============================================================================

-- SST standard value names (3GPP TS 23.501)
local sst_standard_names = {
    [1]="eMBB", [2]="URLLC", [3]="MIoT", [4]="V2X", [5]="HMTC",
}

local function parse_rsd_contents_full(buf, offset, length, tree)
    local cont_end = offset + length
    while offset < cont_end and offset < buf:len() do
        local type_id = buf(offset, 1):uint()
        local type_name = rsd_type_names[type_id] or string.format("Unknown (0x%02X)", type_id)
        offset = offset + 1

        -- Type identifier line (Wireshark style: "...type identifier: {name} ({id})")
        -- Some types have "type" suffix in Wireshark's value_string (0x82, 0x83)
        local rsd_id_text
        if type_id == 0x82 or type_id == 0x83 then
            rsd_id_text = string.format("Route selection descriptor component type identifier: %s type (%d)", type_name, type_id)
        else
            rsd_id_text = string.format("Route selection descriptor component type identifier: %s (%d)", type_name, type_id)
        end
        tree:add(f_rsd_type, buf(offset - 1, 1), type_name)
            :set_text(rsd_id_text)

        if rsd_zero_types[type_id] then
            -- Zero-length types: type identifier only (no additional lines)

        elseif type_id == 0x01 then  -- SSC mode
            if offset >= buf:len() then break end
            local v = buf(offset, 1):uint()
            local name = ssc_mode_names[v] or string.format("Unknown (%d)", v)
            -- Wireshark style: .... .XXX = SSC mode: SSC mode N (N)
            local bits = string.format("%d%d%d", bit.rshift(bit.band(v, 4), 2), bit.rshift(bit.band(v, 2), 1), bit.band(v, 1))
            tree:add(f_rsd_value, buf(offset, 1), name)
                :set_text(string.format(".... .%s = SSC mode: %s (%d)", bits, name, v))
            offset = offset + 1

        elseif type_id == 0x02 then  -- S-NSSAI
            if offset >= buf:len() then break end
            local slen = buf(offset, 1):uint()
            tree:add(f_rsd_value, buf(offset, 1), "")
                :set_text(string.format("Length of Mapped S-NSSAI content: %d", slen))
            offset = offset + 1
            if offset >= buf:len() then break end
            local sst = buf(offset, 1):uint()
            local sst_name = sst_standard_names[sst] or string.format("%d", sst)
            tree:add(f_rsd_value, buf(offset, 1), "")
                :set_text(string.format("Slice/service type (SST): %s (%d)", sst_name, sst))
            offset = offset + 1
            if slen == 4 and offset + 3 <= buf:len() then
                local sd_val = buf(offset, 3):uint()
                tree:add(f_rsd_value, buf(offset, 3), "")
                    :set_text(string.format("Slice differentiator (SD): %d", sd_val))
                offset = offset + 3
            end

        elseif type_id == 0x04 then  -- DNN
            local start_off = offset
            if offset >= buf:len() then break end
            local dnn_len = buf(offset, 1):uint()
            tree:add(f_rsd_value, buf(offset, 1), "")
                :set_text(string.format("Length: %d", dnn_len))
            offset = offset + 1
            if offset >= buf:len() then break end
            local apn_len = buf(offset, 1):uint()
            offset = offset + 1
            if offset + apn_len > buf:len() then break end
            local dnn = buf(offset, apn_len):string()
            tree:add(f_rsd_value, buf(offset, apn_len), "")
                :set_text(string.format("DNN: %s", dnn))
            offset = offset + apn_len

        elseif type_id == 0x08 then  -- PDU session type
            if offset >= buf:len() then break end
            local v = buf(offset, 1):uint()
            local name = pdu_session_type_names[v] or string.format("Unknown (%d)", v)
            local bits = string.format("%d%d%d", bit.rshift(bit.band(v, 4), 2), bit.rshift(bit.band(v, 2), 1), bit.band(v, 1))
            tree:add(f_rsd_value, buf(offset, 1), "")
                :set_text(string.format(".... .%s = PDU session type: %s (%d)", bits, name, v))
            offset = offset + 1

        elseif type_id == 0x10 then  -- Preferred access type
            if offset >= buf:len() then break end
            local v = buf(offset, 1):uint()
            local name = preferred_access_type_names[v] or string.format("Unknown (%d)", v)
            local bits = string.format("%d%d", bit.rshift(bit.band(v, 2), 1), bit.band(v, 1))
            tree:add(f_rsd_value, buf(offset, 1), "")
                :set_text(".... 0... = Spare: 0")
            tree:add(f_rsd_value, buf(offset, 1), "")
                :set_text(".... .0.. = Spare: 0")
            tree:add(f_rsd_value, buf(offset, 1), "")
                :set_text(string.format(".... ..%s = Access type: %s (%d)", bits, name, v))
            offset = offset + 1

        elseif type_id == 0x40 then  -- Location criteria
            if offset >= buf:len() then break end
            local loc_len = buf(offset, 1):uint()
            offset = offset + 1
            if offset + loc_len > buf:len() then break end
            local loc_tree = tree:add(ursp_post, buf(offset - 2, loc_len + 2), "Location criteria")
            loc_tree:add(f_loc_len, buf(offset - 1, 1))
                :set_text(string.format("Length of location criteria: %d", loc_len))
            parse_location_criteria(buf, offset, loc_len, loc_tree)
            offset = offset + loc_len

        elseif type_id == 0x80 then  -- Time window
            if offset + 16 > buf:len() then break end
            local tw_tree = tree:add(ursp_post, buf(offset - 1, 17), "Time window")
            parse_time_window(buf, offset, tw_tree)
            offset = offset + 16

        elseif type_id == 0x82 then  -- PDU session pair ID
            if offset >= buf:len() then break end
            local v = buf(offset, 1):uint()
            tree:add(f_rsd_value, buf(offset, 1), "")
                :set_text(string.format("PDU session pair ID: %d", v))
            offset = offset + 1

        elseif type_id == 0x83 then  -- RSN
            if offset >= buf:len() then break end
            local v = buf(offset, 1):uint()
            local rsn_name = (v == 0) and "v1" or (v == 1) and "v2" or string.format("%d", v)
            tree:add(f_rsd_value, buf(offset, 1), "")
                :set_text(string.format("RSN: %s (%d)", rsn_name, v))
            offset = offset + 1

        else
            -- Unknown type — skip remaining (cannot determine length)
            tree:add(f_rsd_value, buf(offset - 1, 1), type_name)
                :set_text(string.format("Unknown RSD type 0x%02X", type_id))
            break
        end
    end
end

-- ============================================================================
-- OS Id + OS App Id Interpreter
-- ============================================================================
local function interpret_os_app_id(os_id_hex, app_id_hex)
    local os_lower = os_id_hex:lower()
    local app_ascii = hex_to_ascii(app_id_hex)
    if os_lower == ANDROID_OS_ID then
        return "Android", string.format("Slice Category: %s", app_ascii or app_id_hex)
    elseif os_lower == IOS_OS_ID then
        if app_ascii then
            local dot = app_ascii:find("%.")
            if dot then
                local tc = app_ascii:sub(1, dot - 1)
                local ac = app_ascii:sub(dot + 1)
                local an = ios_app_categories[ac]
                local tn = ios_traffic_categories[tc]
                local ad = an and (an .. "-" .. ac) or ("custom-" .. ac)
                local td = tn and (tn .. "-" .. tc) or ("unknown-" .. tc)
                return "iOS", string.format("App Category: %s, Traffic Category: %s", ad, td)
            end
            return "iOS", string.format("OS App Id: %s", app_ascii)
        end
        return "iOS", string.format("OS App Id (hex): %s", app_id_hex)
    else
        if app_ascii then return nil, string.format("OS App Id: %s", app_ascii) end
        return nil, nil
    end
end

-- ============================================================================
-- TD Contents Full Parser
-- ============================================================================
local function parse_td_contents_full(buf, offset, length, tree)
    local cont_end = offset + length
    while offset < cont_end and offset < buf:len() do
        local type_id = buf(offset, 1):uint()
        local type_name = td_type_names[type_id] or string.format("Unknown (0x%02X)", type_id)
        offset = offset + 1

        -- Type identifier line (Wireshark style — most have "type" suffix, some don't)
        local td_type_suffix = "type"
        if type_id == 0x91 or type_id == 0x92 then td_type_suffix = "" end
        local td_id_text
        if td_type_suffix == "" then
            td_id_text = string.format("Traffic descriptor: %s (%d)", type_name, type_id)
        else
            td_id_text = string.format("Traffic descriptor: %s type (%d)", type_name, type_id)
        end
        tree:add(f_td_type, buf(offset - 1, 1), type_name)
            :set_text(td_id_text)

        if type_id == 0x01 then  -- Match-all (type only, no additional lines)

        elseif type_id == 0x08 then  -- OS Id + OS App Id
            -- UUID(16) + app_id_len(1) + app_id
            if offset + 17 > buf:len() then break end
            local os_hex = bytes_to_hex(buf, offset, 16)
            local uuid = string.format("%s-%s-%s-%s-%s",
                os_hex:sub(1,8), os_hex:sub(9,12), os_hex:sub(13,16),
                os_hex:sub(17,20), os_hex:sub(21,32))
            tree:add(f_td_value, buf(offset, 16), "")
                :set_text(string.format("OS id(UUID): %s", uuid))
            offset = offset + 16
            local app_len = buf(offset, 1):uint()
            tree:add(f_td_value, buf(offset, 1), "")
                :set_text(string.format("Length: %d", app_len))
            offset = offset + 1
            if offset + app_len > buf:len() then break end
            local app_hex = bytes_to_hex(buf, offset, app_len)
            tree:add(f_td_value, buf(offset, app_len), "")
                :set_text(string.format("OS App id: %s", app_hex))
            offset = offset + app_len

        elseif type_id == 0x10 then  -- IPv4 remote address: addr(4) + mask(4)
            if offset + 8 > buf:len() then break end
            local addr = string.format("%d.%d.%d.%d",
                buf(offset, 1):uint(), buf(offset+1, 1):uint(),
                buf(offset+2, 1):uint(), buf(offset+3, 1):uint())
            tree:add(f_td_value, buf(offset, 4), "")
                :set_text(string.format("IPv4 address: %s", addr))
            local mask = string.format("%d.%d.%d.%d",
                buf(offset+4, 1):uint(), buf(offset+5, 1):uint(),
                buf(offset+6, 1):uint(), buf(offset+7, 1):uint())
            tree:add(f_td_value, buf(offset + 4, 4), "")
                :set_text(string.format("IPv4 mask: %s", mask))
            offset = offset + 8

        elseif type_id == 0x21 then  -- IPv6 remote address: addr(16) + prefix(1)
            if offset + 17 > buf:len() then break end
            local ipv6_hex = bytes_to_hex(buf, offset, 16)
            local ipv6_str = compress_ipv6(ipv6_hex)
            tree:add(f_td_value, buf(offset, 16), "")
                :set_text(string.format("IPv6 address: %s", ipv6_str))
            local prefix = buf(offset + 16, 1):uint()
            tree:add(f_td_value, buf(offset + 16, 1), "")
                :set_text(string.format("IPv6 prefix length: %d", prefix))
            offset = offset + 17

        elseif type_id == 0x30 then  -- Protocol identifier: 1 byte
            if offset >= buf:len() then break end
            local v = buf(offset, 1):uint()
            local name = protocol_id_names[v] or tostring(v)
            tree:add(f_td_value, buf(offset, 1), "")
                :set_text(string.format("Protocol identifier/next header type: %s (%d)", name, v))
            offset = offset + 1

        elseif type_id == 0x50 then  -- Single remote port: 2 bytes
            if offset + 2 > buf:len() then break end
            local port = buf(offset, 2):uint()
            tree:add(f_td_value, buf(offset, 2), "")
                :set_text(string.format("Remote port: %d", port))
            offset = offset + 2

        elseif type_id == 0x51 then  -- Remote port range: low(2) + high(2)
            if offset + 4 > buf:len() then break end
            local low = buf(offset, 2):uint()
            local high = buf(offset + 2, 2):uint()
            tree:add(f_td_value, buf(offset, 2), "")
                :set_text(string.format("Remote port range low: %d", low))
            tree:add(f_td_value, buf(offset + 2, 2), "")
                :set_text(string.format("Remote port range high: %d", high))
            offset = offset + 4

        elseif type_id == 0x52 then  -- IP 3 tuple: bitmap(1) + variable
            if offset >= buf:len() then break end
            local bitmap = buf(offset, 1):uint()
            tree:add(f_td_value, buf(offset, 1), "")
                :set_text(string.format("IP 3 tuple bitmap: 0x%02x", bitmap))
            offset = offset + 1
            if bit.band(bitmap, 0x01) ~= 0 then
                if offset + 8 > buf:len() then break end
                local addr = string.format("%d.%d.%d.%d",
                    buf(offset, 1):uint(), buf(offset+1, 1):uint(),
                    buf(offset+2, 1):uint(), buf(offset+3, 1):uint())
                tree:add(f_td_value, buf(offset, 4), ""):set_text("IPv4 address: " .. addr)
                local msk = string.format("%d.%d.%d.%d",
                    buf(offset+4, 1):uint(), buf(offset+5, 1):uint(),
                    buf(offset+6, 1):uint(), buf(offset+7, 1):uint())
                tree:add(f_td_value, buf(offset+4, 4), ""):set_text("IPv4 mask: " .. msk)
                offset = offset + 8
            end
            if bit.band(bitmap, 0x02) ~= 0 then
                if offset + 17 > buf:len() then break end
                local v6hex = bytes_to_hex(buf, offset, 16)
                local v6str = compress_ipv6(v6hex)
                tree:add(f_td_value, buf(offset, 16), ""):set_text("IPv6 address: " .. v6str)
                local pfx = buf(offset+16, 1):uint()
                tree:add(f_td_value, buf(offset+16, 1), ""):set_text("IPv6 prefix length: " .. pfx)
                offset = offset + 17
            end
            if bit.band(bitmap, 0x04) ~= 0 then
                if offset >= buf:len() then break end
                local proto = buf(offset, 1):uint()
                local pname = protocol_id_names[proto] or tostring(proto)
                tree:add(f_td_value, buf(offset, 1), ""):set_text(string.format("Protocol identifier/next header type: %s (%d)", pname, proto))
                offset = offset + 1
            end
            if bit.band(bitmap, 0x08) ~= 0 then
                if offset + 2 > buf:len() then break end
                local port = buf(offset, 2):uint()
                tree:add(f_td_value, buf(offset, 2), ""):set_text("Remote port: " .. port)
                offset = offset + 2
            end
            if bit.band(bitmap, 0x10) ~= 0 then
                if offset + 4 > buf:len() then break end
                local lo = buf(offset, 2):uint()
                local hi = buf(offset+2, 2):uint()
                tree:add(f_td_value, buf(offset, 2), ""):set_text("Remote port range low: " .. lo)
                tree:add(f_td_value, buf(offset+2, 2), ""):set_text("Remote port range high: " .. hi)
                offset = offset + 4
            end

        elseif type_id == 0x60 then  -- Security parameter index: 4 bytes
            if offset + 4 > buf:len() then break end
            local spi = bytes_to_hex(buf, offset, 4)
            tree:add(f_td_value, buf(offset, 4), "")
                :set_text(string.format("Security parameter index: 0x%s", spi))
            offset = offset + 4

        elseif type_id == 0x70 then  -- ToS/traffic class: value(1) + mask(1)
            if offset + 2 > buf:len() then break end
            local val = buf(offset, 1):uint()
            local mask = buf(offset + 1, 1):uint()
            tree:add(f_td_value, buf(offset, 1), "")
                :set_text(string.format("Type of service/traffic class: 0x%02x", val))
            tree:add(f_td_value, buf(offset + 1, 1), "")
                :set_text(string.format("Type of service/traffic class mask: 0x%02x", mask))
            offset = offset + 2

        elseif type_id == 0x80 then  -- Flow label: 3 bytes
            if offset + 3 > buf:len() then break end
            local fl_val = buf(offset, 1):uint() * 65536 + buf(offset+1, 1):uint() * 256 + buf(offset+2, 1):uint()
            -- Flow label is 20 bits (lower 20 bits of 3 bytes)
            local fl_20 = bit.band(fl_val, 0x0FFFFF)
            -- Build bit representation: .... XXXX XXXX XXXX XXXX XXXX
            local bits_str = ""
            for i = 23, 0, -1 do
                if i >= 20 then
                    bits_str = bits_str .. "."
                else
                    bits_str = bits_str .. (bit.band(bit.rshift(fl_val, i), 1) == 1 and "1" or "0")
                end
                if i == 20 or i == 16 or i == 12 or i == 8 or i == 4 then
                    bits_str = bits_str .. " "
                end
            end
            tree:add(f_td_value, buf(offset, 3), "")
                :set_text(string.format("%s = Flow label: 0x%05x", bits_str, fl_20))
            offset = offset + 3

        elseif type_id == 0x81 then  -- Destination MAC address: 6 bytes
            if offset + 6 > buf:len() then break end
            local mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x",
                buf(offset, 1):uint(), buf(offset+1, 1):uint(), buf(offset+2, 1):uint(),
                buf(offset+3, 1):uint(), buf(offset+4, 1):uint(), buf(offset+5, 1):uint())
            tree:add(f_td_value, buf(offset, 6), "")
                :set_text(string.format("Destination MAC address: %s (%s)", mac, mac))
            offset = offset + 6

        elseif type_id == 0x83 or type_id == 0x84 then  -- 802.1Q C-TAG/S-TAG VID: 2 bytes
            if offset + 2 > buf:len() then break end
            local raw16 = buf(offset, 2):uint()
            local vid = bit.band(raw16, 0x0FFF)
            -- Build bit representation: .... XXXX XXXX XXXX
            local bits_str = ""
            for i = 15, 0, -1 do
                if i >= 12 then
                    bits_str = bits_str .. "."
                else
                    bits_str = bits_str .. (bit.band(bit.rshift(raw16, i), 1) == 1 and "1" or "0")
                end
                if i == 12 or i == 8 or i == 4 then
                    bits_str = bits_str .. " "
                end
            end
            tree:add(f_td_value, buf(offset, 2), "")
                :set_text(string.format("%s = %s: 0x%03x", bits_str, type_name, vid))
            offset = offset + 2

        elseif type_id == 0x85 or type_id == 0x86 then  -- 802.1Q C-TAG/S-TAG PCP/DEI: 1 byte
            if offset >= buf:len() then break end
            local v = buf(offset, 1):uint()
            local pcp = bit.rshift(bit.band(v, 0xE0), 5)
            local dei = bit.rshift(bit.band(v, 0x10), 4)
            local tag_prefix = (type_id == 0x85) and "802.1Q C-TAG" or "802.1Q S-TAG"
            -- PCP line: .... XXX. = 802.1Q C/S-TAG PCP: 0xN
            local pcp_bits = string.format("%d%d%d", bit.rshift(bit.band(pcp, 4), 2), bit.rshift(bit.band(pcp, 2), 1), bit.band(pcp, 1))
            tree:add(f_td_value, buf(offset, 1), "")
                :set_text(string.format(".... %s. = %s PCP: 0x%x", pcp_bits, tag_prefix, pcp))
            -- DEI line: .... ...X = 802.1Q C/S-TAG DEI: 0xN
            tree:add(f_td_value, buf(offset, 1), "")
                :set_text(string.format(".... ...%d = %s DEI: 0x%x", dei, tag_prefix, dei))
            offset = offset + 1

        elseif type_id == 0x87 then  -- Ethertype: 2 bytes
            if offset + 2 > buf:len() then break end
            local et = buf(offset, 2):uint()
            local et_name = ethertype_names[et]
            if et_name then
                tree:add(f_td_value, buf(offset, 2), "")
                    :set_text(string.format("Ethertype: %s (0x%04x)", et_name, et))
            else
                tree:add(f_td_value, buf(offset, 2), "")
                    :set_text(string.format("Ethertype: 0x%04x", et))
            end
            offset = offset + 2

        elseif type_id == 0x88 then  -- DNN
            if offset >= buf:len() then break end
            local dnn_len = buf(offset, 1):uint()
            tree:add(f_td_value, buf(offset, 1), "")
                :set_text(string.format("Length: %d", dnn_len))
            offset = offset + 1
            if offset >= buf:len() then break end
            local apn_len = buf(offset, 1):uint()
            offset = offset + 1
            if offset + apn_len > buf:len() then break end
            local dnn = buf(offset, apn_len):string()
            tree:add(f_td_value, buf(offset, apn_len), "")
                :set_text(string.format("DNN: %s", dnn))
            offset = offset + apn_len

        elseif type_id == 0x90 then  -- Connection capabilities: len(1) + values
            if offset >= buf:len() then break end
            local clen = buf(offset, 1):uint()
            tree:add(f_td_value, buf(offset, 1), "")
                :set_text(string.format("Connection capabilities length: %d", clen))
            offset = offset + 1
            for i = 1, clen do
                if offset >= buf:len() then break end
                local cv = buf(offset, 1):uint()
                local cn = conn_cap_names[cv] or string.format("Unknown (0x%02x)", cv)
                tree:add(f_td_value, buf(offset, 1), "")
                    :set_text(string.format("Connection capability: %s (0x%02x)", cn, cv))
                offset = offset + 1
            end

        elseif type_id == 0x91 then  -- Destination FQDN: len(1) + RFC 1035 labels
            if offset >= buf:len() then break end
            local flen = buf(offset, 1):uint()
            tree:add(f_td_value, buf(offset, 1), "")
                :set_text(string.format("Destination FQDN length: %d", flen))
            offset = offset + 1
            if offset + flen > buf:len() then break end
            -- Decode RFC 1035 label format: [label_len][label_chars] × N
            local fqdn_labels = {}
            local fqdn_end = offset + flen
            while offset < fqdn_end do
                local label_len = buf(offset, 1):uint()
                if label_len == 0 then offset = offset + 1; break end
                offset = offset + 1
                if offset + label_len > fqdn_end then break end
                table.insert(fqdn_labels, buf(offset, label_len):string())
                offset = offset + label_len
            end
            local fqdn = table.concat(fqdn_labels, ".")
            tree:add(f_td_value, buf(fqdn_end - flen, flen), "")
                :set_text(string.format("Destination FQDN: %s", fqdn))
            offset = fqdn_end

        elseif type_id == 0x92 then  -- Regular expression: len(1) + ascii
            if offset >= buf:len() then break end
            local rlen = buf(offset, 1):uint()
            tree:add(f_td_value, buf(offset, 1), "")
                :set_text(string.format("Length: %d", rlen))
            offset = offset + 1
            if offset + rlen > buf:len() then break end
            local regex = buf(offset, rlen):string()
            tree:add(f_td_value, buf(offset, rlen), "")
                :set_text(string.format("Regular expression: %s", regex))
            offset = offset + rlen

        elseif type_id == 0xA0 then  -- OS App Id: len(1) + hex
            if offset >= buf:len() then break end
            local alen = buf(offset, 1):uint()
            tree:add(f_td_value, buf(offset, 1), "")
                :set_text(string.format("Length: %d", alen))
            offset = offset + 1
            if offset + alen > buf:len() then break end
            local app_hex = bytes_to_hex(buf, offset, alen)
            tree:add(f_td_value, buf(offset, alen), "")
                :set_text(string.format("OS App id: %s", app_hex))
            offset = offset + alen

        elseif type_id == 0xA1 then  -- Destination MAC address range: low(6) + high(6)
            if offset + 12 > buf:len() then break end
            local low_mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x",
                buf(offset, 1):uint(), buf(offset+1, 1):uint(), buf(offset+2, 1):uint(),
                buf(offset+3, 1):uint(), buf(offset+4, 1):uint(), buf(offset+5, 1):uint())
            tree:add(f_td_value, buf(offset, 6), "")
                :set_text(string.format("Destination MAC address range low: %s (%s)", low_mac, low_mac))
            local high_mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x",
                buf(offset+6, 1):uint(), buf(offset+7, 1):uint(), buf(offset+8, 1):uint(),
                buf(offset+9, 1):uint(), buf(offset+10, 1):uint(), buf(offset+11, 1):uint())
            tree:add(f_td_value, buf(offset + 6, 6), "")
                :set_text(string.format("Destination MAC address range high: %s (%s)", high_mac, high_mac))
            offset = offset + 12

        elseif type_id == 0xA2 then  -- PIN ID: len(1) + ascii
            if offset >= buf:len() then break end
            local plen = buf(offset, 1):uint()
            tree:add(f_td_value, buf(offset, 1), "")
                :set_text(string.format("Length: %d", plen))
            offset = offset + 1
            if offset + plen > buf:len() then break end
            local pin_id = buf(offset, plen):string()
            tree:add(f_td_value, buf(offset, plen), "")
                :set_text(string.format("PIN ID: %s", pin_id))
            offset = offset + plen

        elseif type_id == 0xA3 then  -- Connectivity group ID: len(1) + ascii
            if offset >= buf:len() then break end
            local glen = buf(offset, 1):uint()
            tree:add(f_td_value, buf(offset, 1), "")
                :set_text(string.format("Length: %d", glen))
            offset = offset + 1
            if offset + glen > buf:len() then break end
            local group_id = buf(offset, glen):string()
            tree:add(f_td_value, buf(offset, glen), "")
                :set_text(string.format("Connectivity group ID: %s", group_id))
            offset = offset + glen

        else
            -- Unknown type — skip remaining
            tree:add(f_td_value, buf(offset - 1, 1), type_name)
                :set_text(string.format("Unknown TD type 0x%02X", type_id))
            break
        end
    end
end

-- ============================================================================
-- Rule Position Tracker
-- ============================================================================
local function find_rule_position(tvb, offset, rule_fields, rsd_fields)
    -- Determine which URSP rule and RSD this offset belongs to
    -- rule_fields: each has .offset (pos of length field) and .value (rule length)
    -- The rule spans from .offset to .offset + 2 + .value (2-byte length + content)
    local rule_num = 0
    local rsd_num = 0
    if rule_fields then
        for i, rf in ipairs(rule_fields) do
            local rule_start = rf.offset
            local rule_end = rf.offset + 2 + rf.value  -- 2-byte len field + content
            if offset >= rule_start and offset < rule_end then
                rule_num = i
                break
            end
        end
    end
    if rsd_fields and rule_num > 0 then
        local rule_start = rule_fields[rule_num].offset
        local rule_end = rule_start + 2 + rule_fields[rule_num].value
        local rsd_count = 0
        for _, rsdf in ipairs(rsd_fields) do
            local rsd_start = rsdf.offset
            local rsd_end = rsdf.offset + 2 + rsdf.value
            if rsd_start >= rule_start and rsd_start < rule_end then
                rsd_count = rsd_count + 1
                if offset >= rsd_start and offset < rsd_end then
                    rsd_num = rsd_count
                    break
                end
            end
        end
    end
    return rule_num, rsd_num
end

-- ============================================================================
-- Post-Dissector Main
-- ============================================================================
local f_nas_epd       = Field.new("nas-5gs.epd")
local f_rsd_comp_type = Field.new("nas-5gs.ursp.r_sel_desc_comp_type")
local f_conn_cap_val  = Field.new("nas-5gs.ursp.traff_desc.conn_cap")
local f_os_id_val     = Field.new("nas-5gs.os_id")
local f_os_app_id_val = Field.new("nas-5gs.os_app_id")
local f_rule_len      = Field.new("nas-5gs.ursp.rule_len")
local f_rsd_len       = Field.new("nas-5gs.ursp.r_sel_desc_len")
local f_rsd_cont_len  = Field.new("nas-5gs.ursp.r_sel_des_cont_len")
local f_td_comp_type  = Field.new("nas-5gs.ursp.traff_desc")
local f_td_lst_len    = Field.new("nas-5gs.ursp.traff_desc_len")

function ursp_post.dissector(tvb, pinfo, tree)
    local epd = f_nas_epd()
    if not epd then return end

    -- Collect rule/RSD field instances for position tracking
    local rule_fields = { f_rule_len() }
    local rsd_fields = { f_rsd_len() }

    local has_content = false
    local items = {}  -- {label, build_fn}

    -- =========================================================================
    -- Collect: RSD contents full parsing (triggered by 0x40, 0x80, or 0x84)
    -- When Location criteria, Time window, or 5G ProSe multi-path is present,
    -- Wireshark may fail to parse subsequent components. We re-parse the entire RSD contents.
    -- =========================================================================
    local comp_types = { f_rsd_comp_type() }
    local rsd_cont_lens = { f_rsd_cont_len() }
    if #comp_types > 0 then
        -- Check if full RSD parsing is needed (0x40, 0x80, or 0x84 present)
        local needs_full_rsd = false
        for _, comp_fi in ipairs(comp_types) do
            if comp_fi.value == 64 or comp_fi.value == 128 or comp_fi.value == 130 or comp_fi.value == 131 or comp_fi.value == 132 then
                needs_full_rsd = true
                break
            end
        end

        if needs_full_rsd and #rsd_cont_lens > 0 then
            -- Full RSD contents re-parsing for each RSD that contains 0x40 or 0x80
            -- Group comp_types by their parent RSD (using rsd_cont_lens offsets)
            for rsd_idx, rcl_fi in ipairs(rsd_cont_lens) do
                local cont_offset = rcl_fi.offset + 2  -- 2-byte length field
                local cont_len = rcl_fi.value
                if cont_offset + cont_len <= tvb:len() then
                    -- Check if this RSD contains 0x40 or 0x80
                    local has_problematic = false
                    for _, comp_fi in ipairs(comp_types) do
                        if (comp_fi.value == 64 or comp_fi.value == 128 or comp_fi.value == 130 or comp_fi.value == 131 or comp_fi.value == 132) and
                           comp_fi.offset >= cont_offset and comp_fi.offset < cont_offset + cont_len then
                            has_problematic = true
                            break
                        end
                    end
                    if has_problematic then
                        local rn = find_rule_position(tvb, rcl_fi.offset, rule_fields, rsd_fields)
                        local label = string.format("URSP rule %d → Route selection descriptor %d", rn, rsd_idx)
                        table.insert(items, {label=label, offset=cont_offset, len=cont_len,
                            type_name="Route selection descriptor contents",
                            build=function(subtree)
                                parse_rsd_contents_full(tvb, cont_offset, cont_len, subtree)
                            end})
                        has_content = true
                    end
                end
            end
        end

        -- For RSDs without full parsing trigger, still handle individual items
        if not needs_full_rsd then
            for _, comp_fi in ipairs(comp_types) do
                local comp_val = comp_fi.value
                if comp_val == 64 then
                    local data_offset = comp_fi.offset + 1
                    if data_offset < tvb:len() then
                        local loc_len = tvb(data_offset, 1):uint()
                        local total_len = 1 + loc_len
                        if data_offset + total_len <= tvb:len() then
                            local rn, rsdn = find_rule_position(tvb, comp_fi.offset, rule_fields, rsd_fields)
                            local loc_label = string.format("URSP rule %d → Route selection descriptor %d", rn, rsdn)
                            table.insert(items, {label=loc_label, offset=comp_fi.offset, len=1+total_len,
                                type_name="Location criteria",
                                build=function(subtree)
                                    subtree:add(f_loc_len, tvb(data_offset, 1))
                                        :set_text(string.format("Length of location criteria: %d", loc_len))
                                    parse_location_criteria(tvb, data_offset + 1, loc_len, subtree)
                                end})
                            has_content = true
                        end
                    end
                elseif comp_val == 128 then
                    local data_offset = comp_fi.offset + 1
                    if data_offset + 16 <= tvb:len() then
                        local rn, rsdn = find_rule_position(tvb, comp_fi.offset, rule_fields, rsd_fields)
                        local tw_label = string.format("URSP rule %d → Route selection descriptor %d", rn, rsdn)
                        table.insert(items, {label=tw_label, offset=comp_fi.offset, len=17,
                            type_name="Time window",
                            build=function(subtree)
                                parse_time_window(tvb, data_offset, subtree)
                            end})
                        has_content = true
                    end
                end
            end
        end
    end

    -- =========================================================================
    -- Collect: TD contents full parsing (triggered by 0x92 Regular expression)
    -- When Regular expression is present, Wireshark fails to parse subsequent
    -- TD components. We re-parse the entire TD contents.
    -- =========================================================================
    local td_comp_types = { f_td_comp_type() }
    local td_lst_lens = { f_td_lst_len() }
    if #td_comp_types > 0 then
        local needs_full_td = false
        for _, td_fi in ipairs(td_comp_types) do
            if td_fi.value == 0x92 or td_fi.value == 0xA2 or td_fi.value == 0xA3 then
                needs_full_td = true
                break
            end
        end

        if needs_full_td and #td_lst_lens > 0 then
            for td_idx, tdl_fi in ipairs(td_lst_lens) do
                local cont_offset = tdl_fi.offset + 2  -- 2-byte length field
                local cont_len = tdl_fi.value
                if cont_offset + cont_len <= tvb:len() then
                    -- Check if this TD contains 0x92
                    local has_trigger = false
                    for _, td_fi in ipairs(td_comp_types) do
                        if (td_fi.value == 0x92 or td_fi.value == 0xA2 or td_fi.value == 0xA3) and
                           td_fi.offset >= cont_offset and td_fi.offset < cont_offset + cont_len then
                            has_trigger = true
                            break
                        end
                    end
                    if has_trigger then
                        local rn = find_rule_position(tvb, tdl_fi.offset, rule_fields, rsd_fields)
                        local label = string.format("URSP rule %d → Traffic descriptor", rn)
                        table.insert(items, {label=label, offset=cont_offset, len=cont_len,
                            type_name="Traffic descriptor contents",
                            build=function(subtree)
                                parse_td_contents_full(tvb, cont_offset, cont_len, subtree)
                            end})
                        has_content = true
                    end
                end
            end
        end
    end

    -- =========================================================================
    -- Collect: Connection capabilities Rel-18 (0xA1~0xAB)
    -- =========================================================================
    local conn_caps = { f_conn_cap_val() }
    if #conn_caps > 0 then
        local rel18_caps = {}
        for _, cap_fi in ipairs(conn_caps) do
            if cap_fi.value >= 0xA1 and cap_fi.value <= 0xAB then
                table.insert(rel18_caps, cap_fi)
            end
        end
        if #rel18_caps > 0 then
            local rn = find_rule_position(tvb, rel18_caps[1].offset, rule_fields, rsd_fields)
            local label = string.format("URSP rule %d → Traffic descriptor", rn)
            table.insert(items, {label=label, offset=rel18_caps[1].offset, len=1,
                type_name="Connection capabilities",
                build=function(subtree)
                    for _, cap_fi in ipairs(rel18_caps) do
                        local name = conn_cap_names[cap_fi.value] or "Unknown"
                        subtree:add(f_conn_cap_name, tvb(cap_fi.offset, 1), name)
                            :set_text(string.format("Connection capability: %s (0x%02x)", name, cap_fi.value))
                    end
                end})
            has_content = true
        end
    end

    -- =========================================================================
    -- Collect: OS Id + OS App Id
    -- =========================================================================
    local os_ids = { f_os_id_val() }
    local app_ids = { f_os_app_id_val() }

    if #os_ids > 0 and #app_ids > 0 then
        for i, os_fi in ipairs(os_ids) do
            local app_fi = app_ids[i]
            if app_fi then
                local os_hex = bytes_to_hex(tvb, os_fi.offset, os_fi.len)
                local app_hex = bytes_to_hex(tvb, app_fi.offset, app_fi.len)
                local os_name, app_decoded = interpret_os_app_id(os_hex, app_hex)
                if os_name or app_decoded then
                    local rn = find_rule_position(tvb, os_fi.offset, rule_fields, rsd_fields)
                    local label = string.format("URSP rule %d → Traffic descriptor", rn)
                    table.insert(items, {label=label, offset=os_fi.offset, len=os_fi.len+app_fi.len+1,
                        type_name="OS Id + OS App Id",
                        build=function(subtree)
                            -- OS id(UUID) with OS name as child
                            local uuid = string.format("%s-%s-%s-%s-%s",
                                os_hex:sub(1,8), os_hex:sub(9,12), os_hex:sub(13,16),
                                os_hex:sub(17,20), os_hex:sub(21,32))
                            local uuid_node = subtree:add(f_os_name, tvb(os_fi.offset, os_fi.len), uuid)
                                :set_text("OS id(UUID): " .. uuid)
                            if os_name then
                                uuid_node:add(f_os_name, tvb(os_fi.offset, os_fi.len), os_name)
                                    :set_text("OS: " .. os_name)
                            end
                            -- Length
                            subtree:add(f_app_decoded, tvb(app_fi.offset, 1), "")
                                :set_text(string.format("Length: %d", app_fi.len))
                            -- OS App id with decoded info as children
                            local app_node = subtree:add(f_app_decoded, tvb(app_fi.offset, app_fi.len), app_hex)
                                :set_text("OS App id: " .. app_hex)
                            if app_decoded then
                                -- Parse app_decoded for iOS (has comma = two parts)
                                local part1, part2 = app_decoded:match("^(.+), (.+)$")
                                if part1 and part2 then
                                    app_node:add(f_app_decoded, tvb(app_fi.offset, app_fi.len), part1)
                                        :set_text(part1)
                                    app_node:add(f_app_decoded, tvb(app_fi.offset, app_fi.len), part2)
                                        :set_text(part2)
                                else
                                    app_node:add(f_app_decoded, tvb(app_fi.offset, app_fi.len), app_decoded)
                                        :set_text(app_decoded)
                                end
                            end
                        end})
                    has_content = true
                end
            end
        end
    elseif #app_ids > 0 and #os_ids == 0 then
        for _, app_fi in ipairs(app_ids) do
            local app_hex = bytes_to_hex(tvb, app_fi.offset, app_fi.len)
            local app_ascii = hex_to_ascii(app_hex)
            if app_ascii then
                local rn = find_rule_position(tvb, app_fi.offset, rule_fields, rsd_fields)
                local label = string.format("URSP rule %d → Traffic descriptor", rn)
                table.insert(items, {label=label, offset=app_fi.offset, len=app_fi.len,
                    type_name="OS App Id",
                    build=function(subtree)
                        subtree:add(f_app_ascii, tvb(app_fi.offset, app_fi.len), app_ascii)
                            :set_text("OS App Id (ASCII): " .. app_ascii)
                    end})
                has_content = true
            end
        end
    end

    -- =========================================================================
    -- (Removed: Destination FQDN correction — no longer needed since FQDN
    --  is now correctly encoded in RFC 1035 label format, matching Wireshark's
    --  ENC_APN_STR decoding)
    -- =========================================================================
    -- Build the single protocol tree with all items
    -- =========================================================================
    if not has_content then return end

    local root = tree:add(ursp_post, tvb(), "[Extended Info: decoded by ursp_extended_info.lua]")

    for _, item in ipairs(items) do
        -- Parse label to build tree hierarchy: "URSP rule N → Section"
        local rule_part, section_part = item.label:match("^(URSP rule %d+) → (.+)$")
        if rule_part and section_part then
            local rule_tree = root:add(ursp_post, tvb(item.offset, item.len), rule_part)
            local section_tree = rule_tree:add(ursp_post, tvb(item.offset, item.len), section_part)
            local type_tree = section_tree:add(ursp_post, tvb(item.offset, item.len), item.type_name)
            item.build(type_tree)
        else
            local loc_tree = root:add(ursp_post, tvb(item.offset, item.len), item.label)
            local type_tree = loc_tree:add(ursp_post, tvb(item.offset, item.len), item.type_name)
            item.build(type_tree)
        end
    end
end

register_postdissector(ursp_post)
