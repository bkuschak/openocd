-- Wireshark packet dissector for the remote_swd protocol.
-- Adapted from ChatGPT.
--
-- Place this file into the Wireshark plugins directory.
--   macOS/Linux: ~/.config/wireshark/plugins/
--   Windows: AppData\Roaming\Wireshark\plugins\

-- Define protocol
local remote_swd_proto = Proto("remote_swd", "OpenOCD remote_swd protocol")

-- Enumerated values for bit fields
local field1_enum = {
    [0] = "Unknown",
    [1] = "Protocol Version",
    [2] = "HW/SW Version",
    [3] = "Serial Number",
    [4] = "Speed",
    [5] = "Reset",
    [6] = "Switch Sequence",
    [7] = "Read Register",
    [8] = "Write Register",
    [9] = "Unknown",
    [10] = "Unknown",
    [11] = "Unknown",
    [12] = "Unknown",
    [13] = "Unknown",
    [14] = "Unknown",
    [15] = "Unknown"
}

local field5_enum = {
    [0] = "ACK none",
    [1] = "ACK OK",
    [2] = "ACK WAIT",
    [3] = "ACK unknown",
    [4] = "ACK FAULT",
    [5] = "ACK unknown",
    [6] = "ACK unknown",
    [7] = "ACK unknown"
}

-- Define fields
local f_field1 = ProtoField.uint8("remote_swd.opcode", "Opcode", base.DEC, field1_enum, 0x0F)
local f_field2_ack = ProtoField.bool("remote_swd.flags.ack", "Expect ACK", 8, nil, 0x10)
local f_field2_data = ProtoField.bool("remote_swd.flags.data", "Expect Data", 8, nil, 0x20)
local f_field3 = ProtoField.uint8("remote_swd.ap_delay_clks", "AP delay clocks", base.DEC)
local f_field4 = ProtoField.uint8("remote_swd.cmd", "SWD command", base.HEX)
local f_field5 = ProtoField.uint8("remote_swd.ack", "SWD ack", base.HEX, field5_enum, 0x07)
local f_field6 = ProtoField.uint32("remote_swd.data", "SWD data", base.HEX)

remote_swd_proto.fields = { f_field1, f_field2_ack, f_field2_data, f_field3, f_field4, f_field5, f_field6 }

-- Struct size in bytes
local STRUCT_SIZE = 8

-- Dissector
function remote_swd_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = remote_swd_proto.name

    local total_len = buffer:len()

    -- TCP reassembly: if not enough data for one struct, ask for more
    if total_len < STRUCT_SIZE then
        pinfo.desegment_len = STRUCT_SIZE - total_len
        return
    end

    -- Reassemble if data is not a multiple of struct size
    if (total_len % STRUCT_SIZE) ~= 0 then
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return
    end

    -- Dissect
    local subtree = tree:add(remote_swd_proto, buffer(), "Operations")

    local offset = 0
    local struct_num = 0

    while offset + STRUCT_SIZE <= total_len do
        local struct_buf = buffer(offset, STRUCT_SIZE)
        local struct_tree = subtree:add(remote_swd_proto, struct_buf, "Operation " .. struct_num)

        struct_tree:add(f_field1, struct_buf(0, 1))
        struct_tree:add(f_field2_ack, struct_buf(0, 1))
        struct_tree:add(f_field2_data, struct_buf(0, 1))
        struct_tree:add(f_field3, struct_buf(1, 1))
        struct_tree:add(f_field4, struct_buf(2, 1))
        struct_tree:add(f_field5, struct_buf(3, 1))
        struct_tree:add_le(f_field6, struct_buf(4, 4))

        offset = offset + STRUCT_SIZE
        struct_num = struct_num + 1
    end
end

-- Register the protocol to a TCP port (e.g., 5253)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(5253, remote_swd_proto)
