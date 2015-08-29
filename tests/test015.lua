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
    description = "Empty - only SHB, IDB, and NRB",
}


function test:compile()
    self.blocks = {
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
            :addOption('comment', self.testname),
        block.IDB(0, input.linktype.ETHERNET, 96, "silly ethernet interface")
            :addOption('comment', self.testname .. " IDB"),
        block.NRB()
            :addRecord('nrb_record_ipv4', "192.168.1.2", "example.com")
            :addRecord('nrb_record_ipv4', "192.168.3.4", "example.net")
            :addRecord('nrb_record_ipv4', "10.1.2.3",    "example.org")
            :addOption('comment', self.testname .. " NRB")
    }
end


return test
