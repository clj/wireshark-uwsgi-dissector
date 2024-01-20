local plugin_info = {
    version = "2024-01-20.1",
    author = "Markku Leiniö",
    repository = "https://github.com/markkuleinio/wireshark-uwsgi-dissector",
}
set_plugin_info(plugin_info)
local uwsgi_protocol = Proto("uWSGI", "uwsgi Protocol")
-- For some reason the protocol name is shown in UPPERCASE in Protocol column
-- (and in Proto.name), so let's define a string to override that
local PROTOCOL_NAME = "uWSGI"

local p_modifier1 = ProtoField.uint8("uwsgi.modifier1", "Modifier1", base.DEC)
local p_modifier2 = ProtoField.uint8("uwsgi.modifier2", "Modifier2", base.DEC)
local p_datasize = ProtoField.uint16("uwsgi.datasize", "Data size", base.DEC)

uwsgi_protocol.fields = {
    p_modifier1, p_modifier2, p_datasize,
}

local default_settings =
{
    debug_level = DEBUG,
    ports = "8001",   -- the default TCP port
}


-- #######################################
-- protocol dissector function
-- #######################################
function uwsgi_protocol.dissector(buffer, pktinfo, tree)
    if pktinfo.dst_port ~= tonumber(default_settings.ports) then
        -- Not interested, let HTTP (or other) dissector handle this
        return 0
    end
    -- Set Protocol column manually to get it in mixed case instead of all caps
    pktinfo.cols.protocol = PROTOCOL_NAME
    local pktlength = buffer:len()
    local offset = 0
    local subtree = tree:add(uwsgi_protocol, buffer(), "uWSGI Protocol")
    local modifier1 = buffer(offset, 1):uint()
    pktinfo.cols.info = "uWSGI (" .. pktinfo.src_port .. " → " .. pktinfo.dst_port .. ") Modifier1=" .. tostring(modifier1)
    local datasize = buffer(offset+1, 2):le_uint()
    local modifier2 = buffer(offset+3, 1):uint()
    subtree:add_le(p_modifier1, buffer(offset, 1))
    subtree:add_le(p_datasize, buffer(offset+1, 2))
    subtree:add_le(p_modifier2, buffer(offset+3, 1))
    offset = offset + 4
    if modifier1 == 0 then
        local vartree = subtree:add(uwsgi_protocol, buffer(offset, datasize), "Vars")
        local max_offset = offset + datasize
        while offset < max_offset do
            local orig_offset = offset
            local keysize = buffer(offset, 2):le_uint()
            offset = offset + 2
            local key = buffer(offset, keysize):string()
            offset = offset + keysize
            local valuesize = buffer(offset, 2):le_uint()
            offset = offset + 2
            local value = buffer(offset, valuesize):string()
            offset = offset + valuesize
            vartree:add(buffer(orig_offset, keysize+valuesize+4), key .. ": " .. value)
        end
    elseif modifier1 == 72 then
        subtree:add(uwsgi_protocol, buffer(offset), "Raw HTTP")
    end
end


local function enableDissector()
    DissectorTable.get("tcp.port"):add(default_settings.ports, uwsgi_protocol)
end
-- call it now, because we're enabled by default
enableDissector()

local function disableDissector()
    DissectorTable.get("tcp.port"):remove(default_settings.ports, uwsgi_protocol)
end

-- Register our preferences
uwsgi_protocol.prefs.ports = Pref.range("Port(s)", default_settings.ports, "Set the TCP port(s) for uWSGI, default is 8001", 65535)

uwsgi_protocol.prefs.text = Pref.statictext("This dissector is written in Lua by Markku Leiniö. Version: " .. plugin_info.version, "")


-- the function for handling preferences being changed
function uwsgi_protocol.prefs_changed()
    if default_settings.ports ~= uwsgi_protocol.prefs.ports then
        disableDissector()
        default_settings.ports = uwsgi_protocol.prefs.ports
        enableDissector()
    end
end
