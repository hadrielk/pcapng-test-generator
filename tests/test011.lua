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
    description = "Mix of SPBs and EPBs",
}


local timestamp = UInt64(0x64ca47aa, 0x0004c397)

function test:compile()
    local idb0 = block.IDB(0, input.linktype.ETHERNET, 0, "eth0")

    self.blocks = {
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
            :addOption('comment', self.testname),
        idb0,
        block.SPB( input:getData(1) ),
        block.EPB( idb0, input:getData(2), timestamp ),
        block.SPB( input:getData(3) ),
        block.EPB( idb0, input:getData(4), timestamp + 2000 ),
    }
end


return test
