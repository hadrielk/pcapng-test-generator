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
    description = "Two IDBs same linktype, different snaplen",
}


local timestamp = UInt64(0x64ca47aa, 0x0004c397)

function test:compile()
    local idb0 = block.IDB(0, input.linktype.ETHERNET, 96, "eth0")
    local idb1 = block.IDB(1, input.linktype.ETHERNET, 128, "en1")

    self.blocks = {
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
            :addOption('comment', self.testname),
        idb0,
        idb1,
        block.EPB( idb0, input:getData(1,96),  timestamp ),
        block.EPB( idb1, input:getData(2,128), timestamp + 1000 ),
        block.EPB( idb0, input:getData(3,96),  timestamp + 2000 ),
        block.EPB( idb1, input:getData(4,128), timestamp + 3000 ),
    }
end


return test
