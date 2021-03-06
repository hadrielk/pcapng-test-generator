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
    description = "Empty - only SHB and CB/DCB",
}


local pen1 = 32473  -- the official PEN for examples
local pen2 = 36724  -- my PEN (the KRAP one)


function test:compile()
    self.blocks = {
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
            :addOption('comment', self.testname),
        block.CB(pen1, "an example Custom Block"),
        block.CB(pen1, "an example Custom Block not to be copied", true)
            :addOption('comment', self.testname .. " DCB"),
        block.CB(pen2, "my Custom Block")
            :addOption('comment', self.testname .. " CB"),
        block.CB(pen2, "all your block are belong to us", true),
    }
end


return test
