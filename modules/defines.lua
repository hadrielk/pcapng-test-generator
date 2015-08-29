----------------------------------------
--
-- Copyright (c) 2015, Hadriel Kaplan
--
-- author: Hadriel Kaplan <hadrielk@yahoo.com>
--
-- This code is licensed under the MIT license.
--
-- Version: 1.0
--
------------------------------------------

--[[

    This script is a Lua module (not stand-alone) for pcapng_test_gen.

    This module follows the classic Lua module method of storing
    its public methods/functions in a table and passing back the
    table to the caller of this module file.

]]

-- prevent wireshark loading this file as a plugin
if not _G['pcapng_test_gen'] then return end


local Defines = {}

Defines.blocks = {
    ["IDB"]  = 0x00000001,
    ["PB" ]  = 0x00000002,
    ["SPB"]  = 0x00000003,
    ["NRB"]  = 0x00000004,
    ["ISB"]  = 0x00000005,
    ["EPB"]  = 0x00000006,
    ["IRIG"] = 0x00000007,
    ["AFDX"] = 0x00000008,
    ["CB" ]  = 0x00000BAD,
    ["PCB"]  = 0x40000BAD,
    ["SHB"]  = 0x0A0D0D0A,
    -- these aren't actual block types - just the numbers I use for unknown blocks
    ["UNKNOWN_SPEC"]  = 0x01234567,
    ["UNKNOWN_LOCAL"] = 0x81234567,
}


Defines.options = {
    -- common
    ["end_of_opt"]     = 0,
    ["comment"]        = 1,
    -- SHB only
    ["shb_hardware"]   = 2,
    ["shb_os"]         = 3,
    ["shb_userappl"]   = 4,
    -- IDB only
    ["if_name"]        = 2,
    ["if_description"] = 3,
    ["if_IPv4addr"]    = 4,
    ["if_IPv6addr"]    = 5,
    ["if_MACaddr"]     = 6,
    ["if_EUIaddr"]     = 7,
    ["if_speed"]       = 8,
    ["if_tsresol"]     = 9,
    ["if_tzone"]       = 10,
    ["if_filter"]      = 11,
    ["if_os"]          = 12,
    ["if_fcslen"]      = 13,
    ["if_tsoffset"]    = 14,
    -- EPB only
    ["epb_flags"]      = 2,
    ["epb_hash"]       = 3,
    ["epb_dropcount"]  = 4,
    -- NRB only
    ["ns_dnsname"]     = 2,
    ["ns_dnsIP4addr"]  = 3,
    ["ns_dnsIP6addr"]  = 4,
    -- ISB only
    ["isb_starttime"]  = 2,
    ["isb_endtime"]    = 3,
    ["isb_ifrecv"]     = 4,
    ["isb_ifdrop"]     = 5,
    ["isb_filteraccept"] = 6,
    ["isb_osdrop"]     = 7,
    ["isb_usrdeliv"]   = 8,

    -- custom opts
    ["custom_string"]  = 2988,
    ["custom_bytes"]   = 2989,
    ["custom_string_no_copy"] = 19372,
    ["custom_bytes_no_copy"]  = 19373,

    -- unknown
    ["UNKNOWN_SPEC"]   = 0x0123,
    ["UNKNOWN_LOCAL"]  = 0x8123,

    -- these aren't actually option codes, but I'm re-using Options for NRB
    -- Records, so I need this here
    ["nrb_record_end"]  = 0,
    ["nrb_record_ipv4"] = 1,
    ["nrb_record_ipv6"] = 2,
}

Defines.endian = "<"


function Defines:getBlockCode(btype)
    return self.blocks[btype]
end


function Defines:getOptionCode(otype)
    assert(self.options[otype], "No such option type:" .. tostring(otype))
    return self.options[otype]
end


function Defines:setBigEndian(is_big)
    if is_big then
        self.endian = ">"
    else
        self.endian = "<"
    end
end


function Defines:getEndian()
    return self.endian
end


function Defines.pad(len)
    if len % 4 > 0 then
        return 4 - (len % 4)
    end
    return 0
end


local null_chars = {
    [0] = "",
    [1] = Struct.pack("B",   0),
    [2] = Struct.pack("BB",  0, 0),
    [3] = Struct.pack("BBB", 0, 0, 0),
}


function Defines.getPad(len)
    return null_chars[Defines.pad(len)]
end


return Defines
