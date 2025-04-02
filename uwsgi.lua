-- The uwsgi (lowercase!) protocol is described at:
-- https://uwsgi-docs.readthedocs.io/en/latest/Protocol.html

local plugin_info = {
    version = "2025-04-02.1",
    author = "Markku Leiniö, Christian L. Jacobsen",
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
    ports = "",   -- uWSGI doesn't have a registered port
}


-- #######################################
-- protocol dissector function
-- #######################################
function uwsgi_protocol.dissector(buffer, pktinfo, tree)
    -- Set Protocol column manually to get it in mixed case instead of all caps
    pktinfo.cols.protocol = PROTOCOL_NAME
    pktinfo.conversation = uwsgi_protocol
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
        local vars = {}
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
            vars[key] = value
        end
        local payload = buffer(offset)
        if payload:len() > 0 then
            local content_type = vars["CONTENT_TYPE"] or vars["HTTP_CONTENT_TYPE"]
            if content_type then
                local media_type_dissector_table = DissectorTable.get("media_type")
                local subtype_end = content_type:find("[%s;]")
                if subtype_end then
                    content_type = content_type:sub(0, subtype_end - 1)
                end
                if media_type_dissector_table then
                    local media_type_dissector = media_type_dissector_table:get_dissector(content_type)
                    media_type_dissector:call(payload:tvb(), pktinfo, tree)
                end
            end
            subtree:add(payload, "HTTP Request Body")
        end
    elseif modifier1 == 72 then
        subtree:add(uwsgi_protocol, buffer(), "Raw HTTP Response")
        Dissector.get("http"):call(buffer():tvb(), pktinfo, tree)
    end
    return pktlength
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
uwsgi_protocol.prefs.ports = Pref.range("Port(s)", default_settings.ports, "Set the TCP port(s) for uWSGI", 65535)

uwsgi_protocol.prefs.text = Pref.statictext("This dissector is written in Lua by Markku Leiniö. Version: " .. plugin_info.version, "")


-- the function for handling preferences being changed
function uwsgi_protocol.prefs_changed()
    if default_settings.ports ~= uwsgi_protocol.prefs.ports then
        disableDissector()
        default_settings.ports = uwsgi_protocol.prefs.ports
        enableDissector()
    end
end
