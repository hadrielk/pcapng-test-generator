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
    description = "SPBs",
}


function test:compile()
    local idb0 = block.IDB(0, input.linktype.ETHERNET, 0, "eth0")

    self.blocks = {
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
            :addOption('comment', self.testname),
        idb0,
        block.SPB( input:getData(1) ),
        block.SPB( input:getData(2) ),
        block.SPB( input:getData(3) ),
        block.SPB( input:getData(4) ),
    }
end


return test
