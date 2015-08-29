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
    description = "NRB with IPv4+6, unknown types, duplicate entries, etc.",
}


local timestamp = UInt64(0x64ca47aa, 0x0004c397)

function test:compile()
    local idb0 = block.IDB(0, input.linktype.ETHERNET, 0, "eth0")

    self.blocks = {
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
            :addOption('comment', self.testname),
        idb0,
        block.NRB()
            :addRecord('nrb_record_ipv4', "192.168.1.2", "example.com")
            :addRecord('nrb_record_ipv4', "192.168.1.2", "example.com")
            :addRecord('nrb_record_ipv6', "FC01:DEAD::BEEF", "example.com")
            :addRecord('nrb_record_ipv4', "10.1.2.3",    "example.org")
            :addRecord('nrb_record_ipv4', "192.168.1.2", "example.net")
            :addRecord('UNKNOWN_SPEC', "foobar")
            :addOption('comment', self.testname .. " NRB")
            :addOption('UNKNOWN_SPEC')
            :addOption('UNKNOWN_LOCAL', self.testname .. " NRB"),
        block.SPB( input:getData(1) ),
        block.NRB()
            :addOption('comment', self.testname .. " empty NRB"),
        block.NRB(),
        block.EPB( idb0, input:getData(2), timestamp ),
        block.NRB()
            :addRecord('nrb_record_ipv6', "FC01:DEAD::BEEF", "foo.example.com")
            :addRecord('nrb_record_ipv6', "FC01:DEAD::BEEF", "foo.example.net")
            :addRecord('nrb_record_ipv4', "10.1.2.3",    "foo.example.org"),
        block.SPB( input:getData(3) ),
        block.EPB( idb0, input:getData(4), timestamp + 2000 ),
        block.NRB()
            :addRecord('nrb_record_ipv4', "192.168.1.2", "qux.example.com")
            :addRecord('nrb_record_ipv4', "192.168.1.3", "bar.example.com")
            :addRecord('nrb_record_ipv6', "FC01:FEED::BEEF", "bar.example.net")
            :addRecord('UNKNOWN_SPEC', "foobar")
            :addRecord('nrb_record_ipv6', "FC01:DEAD::BEEF", "foo.example.com")
            :addRecord('UNKNOWN_LOCAL', "unknown")
            :addRecord('nrb_record_ipv4', "10.1.2.4",    "bar.example.org")
            :addOption('comment', self.testname .. " NRB"),
    }
end


return test
