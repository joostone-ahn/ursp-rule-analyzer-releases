-- =============================================================================
-- URSP NAS Post-Dissector for Wireshark
-- Supplements Wireshark's built-in NAS-5GS dissector with:
--   1. Location criteria (RSD 0x40) — full parsing
--   2. Time window (RSD 0x80) — full parsing
--   3. Connection capabilities (TD 0x90) — Rel-18 name annotation (0xA1~0xAB)
--   4. OS Id + OS App Id (TD 0x08) — human-readable interpretation
--   5. OS App Id (TD 0xA0) — hex-to-ASCII decoding
--   6. Destination FQDN (TD 0x91) — off-by-one correction
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
-- Author: JUSEOK AHN <ajs3013@lguplus.co.kr>
-- =============================================================================

local ursp_post = Proto("ursp_nas_ext", "[Extended Info: decoded by ursp_nas_dissector.lua]")

-- ============================================================================
-- Protocol Fields
-- ============================================================================

local f_loc_len       = ProtoField.uint8("ursp_nas_ext.loc.length", "Length of location criteria contents", base.DEC)
local f_loc_area_type = ProtoField.uint8("ursp_nas_ext.loc.area_type", "Type of location area", base.DEC)
local f_loc_num_cells = ProtoField.uint8("ursp_nas_ext.loc.num_cells", "Number of cell identities", base.DEC)
local f_loc_mcc       = ProtoField.string("ursp_nas_ext.loc.mcc", "Mobile Country Code (MCC)")
local f_loc_mnc       = ProtoField.string("ursp_nas_ext.loc.mnc", "Mobile Network Code (MNC)")
local f_loc_nci       = ProtoField.bytes("ursp_nas_ext.loc.nci", "NR Cell Identity (NCI)")
local f_loc_eci       = ProtoField.bytes("ursp_nas_ext.loc.eci", "E-UTRA Cell Identity (ECI)")
local f_loc_gnb       = ProtoField.bytes("ursp_nas_ext.loc.gnb_id", "gNB ID")
local f_loc_tai_len   = ProtoField.uint8("ursp_nas_ext.loc.tai_len", "Length", base.DEC)
local f_loc_tai_type  = ProtoField.uint8("ursp_nas_ext.loc.tai_type_num", "Type/Num octet", base.HEX)
local f_loc_tac       = ProtoField.bytes("ursp_nas_ext.loc.tac", "Tracking area code(TAC)")
local f_tw_start_sec  = ProtoField.uint32("ursp_nas_ext.tw.start_sec", "Start time (seconds)", base.DEC)
local f_tw_start_frac = ProtoField.uint32("ursp_nas_ext.tw.start_frac", "Start time (fraction)", base.HEX)
local f_tw_stop_sec   = ProtoField.uint32("ursp_nas_ext.tw.stop_sec", "Stop time (seconds)", base.DEC)
local f_tw_stop_frac  = ProtoField.uint32("ursp_nas_ext.tw.stop_frac", "Stop time (fraction)", base.HEX)
local f_tw_start_str  = ProtoField.string("ursp_nas_ext.tw.start_utc", "Start time")
local f_tw_stop_str   = ProtoField.string("ursp_nas_ext.tw.stop_utc", "Stop time")
local f_conn_cap_name = ProtoField.string("ursp_nas_ext.conn_cap.name", "Connection capability")
local f_os_name       = ProtoField.string("ursp_nas_ext.os_id.os_name", "OS")
local f_app_decoded   = ProtoField.string("ursp_nas_ext.os_id.app_decoded", "OS App Id (decoded)")
local f_app_ascii     = ProtoField.string("ursp_nas_ext.os_app_id.ascii", "OS App Id (ASCII)")
local f_fqdn_correct  = ProtoField.string("ursp_nas_ext.dest_fqdn.corrected", "Destination FQDN (corrected)")

ursp_post.fields = {
    f_loc_len, f_loc_area_type, f_loc_num_cells, f_loc_mcc, f_loc_mnc,
    f_loc_nci, f_loc_eci, f_loc_gnb, f_loc_tai_len, f_loc_tai_type, f_loc_tac,
    f_tw_start_sec, f_tw_start_frac, f_tw_stop_sec, f_tw_stop_frac,
    f_tw_start_str, f_tw_stop_str, f_conn_cap_name,
    f_os_name, f_app_decoded, f_app_ascii, f_fqdn_correct
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
    [0x01]="E-UTRA cell identities", [0x02]="NR cell identities",
    [0x03]="Global RAN node identities", [0x04]="Tracking area identities",
}
local loc_area_cell_sizes = { [0x01]=7, [0x02]=8, [0x03]=7 }
local tai_list_type_names = {
    [0]="list of TACs belonging to one PLMN, with non-consecutive TAC values",
    [1]="list of TACs belonging to one PLMN, with consecutive TAC values",
    [2]="list of TAIs belonging to different PLMNs",
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
                if offset + 3 > buf:len() then break end
                local mcc, mnc, new_off = decode_plmn(buf, offset)
                pt:add(f_loc_mcc, buf(offset, 3), mcc):set_text("Mobile Country Code (MCC): " .. mcc)
                pt:add(f_loc_mnc, buf(offset, 3), mnc):set_text("Mobile Network Code (MNC): " .. mnc)
                offset = new_off
                if list_type == 0 then
                    for t = 1, num_elements do
                        if offset + 3 > buf:len() then break end
                        pt:add(f_loc_tac, buf(offset, 3)):set_text("Tracking area code(TAC): " .. bytes_to_hex(buf, offset, 3))
                        offset = offset + 3
                    end
                elseif list_type == 1 then
                    if offset + 3 <= buf:len() then
                        pt:add(f_loc_tac, buf(offset, 3)):set_text("Tracking area code(TAC): " .. bytes_to_hex(buf, offset, 3))
                        offset = offset + 3
                    end
                elseif list_type == 2 then
                    if offset + 3 <= buf:len() then
                        pt:add(f_loc_tac, buf(offset, 3)):set_text("Tracking area code(TAC): " .. bytes_to_hex(buf, offset, 3))
                        offset = offset + 3
                    end
                    for t = 2, num_elements do
                        if offset + 6 > buf:len() then break end
                        local m2, n2, pe = decode_plmn(buf, offset)
                        pt:add(f_loc_mcc, buf(offset, 3), m2):set_text("Mobile Country Code (MCC): " .. m2)
                        pt:add(f_loc_mnc, buf(offset, 3), n2):set_text("Mobile Network Code (MNC): " .. n2)
                        offset = pe
                        if offset + 3 > buf:len() then break end
                        pt:add(f_loc_tac, buf(offset, 3)):set_text("Tracking area code(TAC): " .. bytes_to_hex(buf, offset, 3))
                        offset = offset + 3
                    end
                end
            end
        else
            local cell_size = loc_area_cell_sizes[area_type] or 8
            tree:add(f_loc_area_type, buf(offset, 1))
                :set_text(string.format("Type of location area: %s (%d)", area_name, area_type))
            offset = offset + 1
            if offset >= buf:len() then break end
            local num_cells = buf(offset, 1):uint()
            tree:add(f_loc_num_cells, buf(offset, 1)):set_text("Number of cell identities: " .. num_cells)
            offset = offset + 1
            for c = 1, num_cells do
                if offset + cell_size > buf:len() then break end
                local cs = offset
                local cl
                if area_type == 0x02 then cl = string.format("NR cell identity %d", c)
                elseif area_type == 0x01 then cl = string.format("E-UTRA cell identity %d", c)
                else cl = string.format("Global RAN node identity %d", c) end
                local ct = tree:add(ursp_post, buf(cs, cell_size), cl)
                local mcc, mnc, pe = decode_plmn(buf, offset)
                ct:add(f_loc_mcc, buf(offset, 3), mcc):set_text("Mobile Country Code (MCC): " .. mcc)
                ct:add(f_loc_mnc, buf(offset, 3), mnc):set_text("Mobile Network Code (MNC): " .. mnc)
                offset = pe
                local id_len = cell_size - 3
                local id_hex = bytes_to_hex(buf, offset, id_len)
                if area_type == 0x02 then ct:add(f_loc_nci, buf(offset, id_len)):set_text("NCI: " .. id_hex)
                elseif area_type == 0x01 then ct:add(f_loc_eci, buf(offset, id_len)):set_text("ECI: " .. id_hex)
                else ct:add(f_loc_gnb, buf(offset, id_len)):set_text("gNB ID: " .. id_hex) end
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
local f_fqdn_val      = Field.new("nas-5gs.ursp.traff_desc.dest_fqdn")
local f_rule_len      = Field.new("nas-5gs.ursp.rule_len")
local f_rsd_len       = Field.new("nas-5gs.ursp.r_sel_desc_len")

function ursp_post.dissector(tvb, pinfo, tree)
    local epd = f_nas_epd()
    if not epd then return end

    -- Collect rule/RSD field instances for position tracking
    local rule_fields = { f_rule_len() }
    local rsd_fields = { f_rsd_len() }

    local has_content = false
    local items = {}  -- {label, build_fn}

    -- =========================================================================
    -- Collect: Location criteria (0x40) and Time window (0x80)
    -- =========================================================================
    local comp_types = { f_rsd_comp_type() }
    if #comp_types > 0 then
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
                                    :set_text(string.format("Length of location criteria contents: %d", loc_len))
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
                type_name="Connection capabilities (Rel-18)",
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
                            if os_name then
                                subtree:add(f_os_name, tvb(os_fi.offset, os_fi.len), os_name)
                                    :set_text("OS: " .. os_name)
                            end
                            if app_decoded then
                                subtree:add(f_app_decoded, tvb(app_fi.offset, app_fi.len), app_decoded)
                                    :set_text(app_decoded)
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
    -- Collect: Destination FQDN correction
    -- =========================================================================
    local fqdns = { f_fqdn_val() }
    if #fqdns > 0 then
        for _, fqdn_fi in ipairs(fqdns) do
            local fqdn_hex = bytes_to_hex(tvb, fqdn_fi.offset, fqdn_fi.len)
            local fqdn_ascii = hex_to_ascii(fqdn_hex)
            if fqdn_ascii and fqdn_fi.display ~= fqdn_ascii then
                local rn = find_rule_position(tvb, fqdn_fi.offset, rule_fields, rsd_fields)
                local label = string.format("URSP rule %d → Traffic descriptor", rn)
                table.insert(items, {label=label, offset=fqdn_fi.offset, len=fqdn_fi.len,
                    type_name="Destination FQDN (corrected)",
                    build=function(subtree)
                        subtree:add(f_fqdn_correct, tvb(fqdn_fi.offset, fqdn_fi.len), fqdn_ascii)
                            :set_text("Destination FQDN: " .. fqdn_ascii)
                    end})
                has_content = true
            end
        end
    end

    -- =========================================================================
    -- Build the single protocol tree with all items
    -- =========================================================================
    if not has_content then return end

    local root = tree:add(ursp_post, tvb(), "[Extended Info: decoded by ursp_nas_dissector.lua]")

    for _, item in ipairs(items) do
        local loc_tree = root:add(ursp_post, tvb(item.offset, item.len), item.label)
        local type_tree = loc_tree:add(ursp_post, tvb(item.offset, item.len), item.type_name)
        item.build(type_tree)
    end
end

register_postdissector(ursp_post)
