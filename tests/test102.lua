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
    category    = 'advanced',
    description = "All block types, intermixed",
}


local pen1 = 32473  -- the official PEN for examples
local pen2 = 36724  -- my PEN (the KRAP one)

local timestamp = UInt64(0x64ca47aa, 0x0004c397)

function test:compile()
    local idb0 = block.IDB(0, input.linktype.ETHERNET, 96, "eth0")
    local idb1 = block.IDB(1, input.linktype.NULL, 0, "null1")
    local idb2 = block.IDB(2, input.linktype.ETHERNET, 0, "silly!\r\nethernet interface 2")

    self.blocks = {
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
            :addOption('comment', self.testname),
        block.CB(pen1, "an example Custom Block"),
        block.NRB()
            :addRecord('nrb_record_ipv4', "192.168.1.2", "a")
            :addRecord('nrb_record_ipv4', "192.168.1.2", "example.com")
            :addRecord('nrb_record_ipv4', "192.168.1.8", "example.com")
            :addRecord('nrb_record_ipv6', "FC01:DEAD::BEEF", "example.com")
            :addRecord('nrb_record_ipv4', "10.1.2.3",    "example.org")
            :addRecord('nrb_record_ipv4', "192.168.1.2", "example.net")
            :addRecord('UNKNOWN_SPEC', "foobar")
            :addOption('comment', self.testname .. " NRB")
            :addOption('UNKNOWN_SPEC')
            :addOption('UNKNOWN_LOCAL', self.testname .. " NRB"),
        idb0,
        idb1,
        block.ISB(idb1, timestamp),

        block.EPB( idb0, input:getData(1, 96), timestamp ),

        block.ISB(idb0),
        block.ISB(idb1, timestamp - 1000),
        block.CB(pen1, "an example Custom Block not to be copied", true)
            :addOption('comment', self.testname .. " DCB"),

        idb2,

        block.EPB( idb2, input:getData(2), timestamp ),

        block.ISB(idb2, timestamp + 1000)
            :addOption( block.OptionFormat ('isb_starttime', "I4 I4", { timestamp:higher(), timestamp:lower() }) )
            :addOption( block.OptionFormat ('isb_endtime',   "I4 I4", { timestamp:higher(), (timestamp + 1000):lower() }) )
            :addOption( block.OptionFormat ('isb_filteraccept', "E", UInt64(42)) )
            :addOption( block.OptionFormat ('isb_ifdrop',    "E", UInt64(10)) )
            :addOption('comment', self.testname .. " ISB-2"),

        block.SPB( input:getData(3, 96) ),
        -- empty one
        block.NRB(),

        block.EPB( idb0, input:getData(4), timestamp + 2000 ),

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
        block.CB(pen2, "all your block are belong to us", true),
        block.NRB()
            :addRecord('nrb_record_ipv4', "192.168.1.2", "qux.example.com")
            :addRecord('nrb_record_ipv4', "192.168.1.3", "bar.example.com")
            :addRecord('nrb_record_ipv6', "FC01:FEED::BEEF", "bar.example.net")
            :addRecord('UNKNOWN_SPEC', "foobar")
            :addRecord('nrb_record_ipv6', "FC01:DEAD::BEEF", "foo.example.com")
            :addRecord('UNKNOWN_LOCAL', "unknown")
            :addRecord('nrb_record_ipv4', "10.1.2.4",    "bar.example.org")
            :addOption('comment', self.testname .. " NRB"),

        block.ISB(idb0),
    }
end


return test
