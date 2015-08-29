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
    description = "2 IDBs with all options",
}


local timestamp = UInt64(0x64ca47aa, 0x0004c397)

function test:compile()
    local idb0 = block.IDB(0, input.linktype.ETHERNET, 96, "eth-_0 foo")
                    :addOption( 'comment', self.testname .. ", and more\nfoo\r\nbar")
                    :addOption( 'if_description', "silly ethernet interface")
                    :addOption( block.OptionIPv4   ('if_IPv4addr', "10.1.2.3", "255.255.255.0") )
                    :addOption( block.OptionIPv6   ('if_IPv6addr', "2100:0db8::1a2b/64") )
                    :addOption( block.OptionHex    ('if_MACaddr', "00 01 02 03 04 05") )
                    :addOption( block.OptionHex    ('if_EUIaddr', "02 34 56 FF FE 78 9A BC") )
                    :addOption( block.OptionFormat ('if_speed', "E", UInt64(1000000000)) )
                    :addOption( block.OptionFormat ('if_tsresol', "B", 9) )
                    :addOption( block.OptionFormat ('if_filter', "B", 0, "tcp port 23 and host 192.0.2.5") )
                    :addOption( 'if_os', "Microsoft Windows for Workgroups 3.11b\npatch 42")
                    :addOption( block.OptionFormat ('if_fcslen', "B", 0) )
                    :addOption( block.OptionFormat ('if_tsoffset', "E", UInt64(0)) )
                    :addOption( 'custom_string', "a fake string")
                    :addOption( 'custom_bytes',  "some fake bytes")
                    :addOption( 'custom_string_no_copy', "my fake string")
                    :addOption( 'custom_bytes_no_copy',  "my fake bytes")
                    :addOption( 'UNKNOWN_SPEC',  "try this one")
                    :addOption( 'UNKNOWN_LOCAL', "and this one")


    -- options in reverse order
    local idb1 = block.IDB(1, input.linktype.ETHERNET, 128, "en1")
                    :addOption( 'UNKNOWN_LOCAL', "and this one")
                    :addOption( 'UNKNOWN_SPEC',  "try this one")
                    :addOption( 'custom_bytes_no_copy',  "my fake bytes")
                    :addOption( 'custom_string_no_copy', "my fake string")
                    :addOption( 'custom_bytes',  "some fake bytes")
                    :addOption( 'custom_string', "a fake string")
                    :addOption( block.OptionFormat ('if_tsoffset', "E", UInt64(0)) )
                    :addOption( block.OptionFormat ('if_fcslen', "B", 0) )
                    :addOption( 'if_os', "Novell NetWare 4.11\nbut not using IPX")
                    :addOption( block.OptionFormat ('if_filter', "B", 0, "tcp port 23 and host 192.0.2.5") )
                    :addOption( block.OptionFormat ('if_tsresol', "B", 9) )
                    :addOption( block.OptionFormat ('if_speed', "E", UInt64(100000000)) )
                    :addOption( block.OptionHex    ('if_EUIaddr', "02 34 56 FF FE 78 9A BD") )
                    :addOption( block.OptionHex    ('if_MACaddr', "00 01 02 03 04 06") )
                    :addOption( block.OptionIPv6   ('if_IPv6addr', "2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64") )
                    :addOption( block.OptionIPv4   ('if_IPv4addr', "10.1.2.4", "255.255.255.0") )
                    :addOption( 'if_description', "silly ethernet interface 2")
                    :addOption( 'comment', self.testname)

    self.blocks = {
        block.SHB("Apple MBP", "OS-X 10.10.5", "pcap_writer.lua")
            :addOption('comment', self.testname),
        idb0,
        block.EPB( idb0, input:getData(1,96),  timestamp ),
        idb1,
        block.EPB( idb1, input:getData(2,128), timestamp + 1000 ),
        block.EPB( idb0, input:getData(3,96),  timestamp + 2000 ),
        block.EPB( idb1, input:getData(4,128), timestamp + 3000 ),
    }
end


return test
