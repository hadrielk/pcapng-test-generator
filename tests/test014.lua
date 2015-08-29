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
    description = "Empty - only SHB, multiple IDB and ISB",
}


local timestamp = UInt64(0x64ca47aa, 0x0004c397)

function test:compile()
    local idb0 = block.IDB(0, input.linktype.ETHERNET, 96, "silly ethernet interface")
    local idb1 = block.IDB(1, input.linktype.NULL, 0, "en1")
    local idb2 = block.IDB(0, input.linktype.ETHERNET, 128, "silly ethernet interface 2")

    self.blocks = {
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
            :addOption('comment', self.testname),
        idb0,
        idb1,
        block.ISB(idb1, timestamp),
        block.ISB(idb0),
        idb2,
        block.ISB(idb2, timestamp - 1000),
    }
end


return test
