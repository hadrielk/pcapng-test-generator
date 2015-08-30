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
    description = "Empty - only SHB, IDB, and ISB",
}


local timestamp = UInt64(0x64ca47aa, 0x0004c397)


function test:compile()
    local idb0 = block.IDB(0, input.linktype.ETHERNET, 96, "silly ethernet interface")

    self.blocks = {
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
            :addOption('comment', self.testname),
        idb0,
        block.ISB(idb0)
            :addOption( block.OptionFormat ('isb_starttime', "I4 I4", { timestamp:higher(), timestamp:lower() }) )
            :addOption( block.OptionFormat ('isb_endtime',   "I4 I4", { timestamp:higher(), (timestamp + 1000):lower() }) )
            :addOption( block.OptionFormat ('isb_ifdrop',    "E", UInt64(10)) ),
    }
end


return test
