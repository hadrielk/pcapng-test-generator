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
    category    = 'difficult',
    description = "ISBs with various options, in different SHB sections",
}


local timestamp = UInt64(0x64ca47aa, 0x0004c397)

function test:compile()
    local idb0 = block.IDB(0, input.linktype.ETHERNET, 96, "eth0")
    local idb1 = block.IDB(1, input.linktype.NULL, 0, "null1")
    -- will be in new section, so ID=0
    local idb2 = block.IDB(0, input.linktype.ETHERNET, 128, "silly ethernet interface 2")

    self.blocks = {
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
            :addOption('comment', self.testname .. " SHB-0"),
        idb0,
        idb1,

        block.EPB( idb0, input:getData(1, 96), timestamp ),
        block.ISB(idb1, timestamp),

        ---- new SHB section ----
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
            :addOption('UNKNOWN_SPEC')
            :addOption('UNKNOWN_LOCAL', self.testname .. " NRB")
            :addOption('comment', self.testname .. " SHB-1"),
        idb2,

        block.EPB( idb2, input:getData(2, 128), timestamp ),

        block.ISB(idb2, timestamp + 1000)
            :addOption( block.OptionFormat ('isb_starttime', "I4 I4", { timestamp:higher(), timestamp:lower() }) )
            :addOption( block.OptionFormat ('isb_endtime',   "I4 I4", { timestamp:higher(), (timestamp + 1000):lower() }) )
            :addOption( block.OptionFormat ('isb_filteraccept', "E", UInt64(42)) )
            :addOption( block.OptionFormat ('isb_ifdrop',    "E", UInt64(10)) )
            :addOption('UNKNOWN_SPEC')
            :addOption('UNKNOWN_LOCAL', self.testname .. " NRB")
            :addOption('comment', self.testname .. " ISB-2"),

        block.SPB( input:getData(3, 128) ),

        ---- new SHB section ----
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
            :addOption('comment', self.testname .. " SHB-2"),

        idb0,
        idb1,

        block.ISB(idb0)
            :addOption( block.OptionFormat ('isb_starttime', "I4 I4", { timestamp:higher(), timestamp:lower() }) )
            :addOption( block.OptionFormat ('isb_endtime',   "I4 I4", { timestamp:higher(), (timestamp + 1000):lower() }) )
            :addOption( block.OptionFormat ('isb_ifrecv',    "E", UInt64(100)) )
            :addOption( block.OptionFormat ('isb_ifdrop',    "E", UInt64(1)) )
            :addOption( block.OptionFormat ('isb_filteraccept', "E", UInt64(9)) )
            :addOption( block.OptionFormat ('isb_osdrop',    "E", UInt64(42)) )
            :addOption( block.OptionFormat ('isb_usrdeliv',  "E", UInt64(6)) )
            :addOption('comment', self.testname .. " ISB-0"),

        block.EPB( idb1, input:getData(5), timestamp + 3000 ),

        block.ISB(idb0),
    }
end


return test
