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

-- prevent wireshark loading this file as a plugin
if not _G['pcapng_test_gen'] then return end


local block = require "blocks"
local input = require "input"


local test = {
    category    = 'basic',
    description = "EPBs with all options",
}


local timestamp = UInt64(0x64ca47aa, 0x0004c397)

function test:compile()
    local idb0 = block.IDB(0, input.linktype.ETHERNET, 0, "eth0")

    self.blocks = {
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
                    :addOption( 'comment', self.testname),
        idb0,
        block.EPB( idb0, input:getData(1),  timestamp )
                    :addOption( 'comment', self.testname .. "-1")
                    :addOption( block.OptionFormat ('epb_flags', "I4", 0x00) )
                    :addOption( block.OptionFormat ('epb_dropcount', "E", UInt64(0)) )
                    :addOption( 'custom_string', "a fake string")
                    :addOption( 'custom_bytes',  "some fake bytes")
                    :addOption( 'custom_string_no_copy', "my fake string")
                    :addOption( 'custom_bytes_no_copy',  "my fake bytes")
                    :addOption( 'UNKNOWN_SPEC',  "try this one")
                    :addOption( 'UNKNOWN_LOCAL', "and this one"),

        block.EPB( idb0, input:getData(2),  timestamp + 1000 )
                    :addOption( 'UNKNOWN_SPEC',  "try this one")
                    :addOption( 'comment', self.testname .. "-2")
                    :addOption( block.OptionFormat ('epb_flags', "I4", 0x48000000) )
                    :addOption( block.OptionFormat ('epb_dropcount', "E", UInt64(12345)) )
                    :addOption( 'custom_string', "a fake string")
                    :addOption( 'custom_bytes',  "some fake bytes")
                    :addOption( 'custom_string_no_copy', "my fake string")
                    :addOption( 'custom_bytes_no_copy',  "my fake bytes")
                    :addOption( 'UNKNOWN_LOCAL', "and this one"),
    }
end


return test
