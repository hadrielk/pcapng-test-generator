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


local Defines = require "defines"
local pad     = Defines.pad
local getPad  = Defines.getPad

local Block   = require "block"


--------------------------------------------------------------------------------
-- The EPB class
--
local EPB = {}
local EPB_mt = { __index = EPB }

function EPB.new(idb, pkt, timestamp, caplen)
    assert(idb and type(idb) == 'table', "Not given IDB object or table")
    assert(pkt and type(pkt) == 'table', "Not given packet data/len table")

    local data, origlen = pkt[1], pkt[2]
    assert(data, "Not given data")
    assert(origlen, "Not given packet len")

    timestamp = timestamp or UInt64(0)
    if not caplen then
        local snaplen = idb.snaplen
        if snaplen > 0 then
            caplen = math.min(origlen, snaplen)
        else
            caplen = origlen
        end
    end

    local new_class = Block.new('EPB')
    new_class['interface_id'] = idb.interface_id
    new_class['timestamp']    = timestamp
    new_class['caplen']       = caplen
    new_class['origlen']      = origlen
    new_class['data']         = data

    setmetatable( new_class, EPB_mt )

    return new_class
end

function EPB.call(_, ...)
    return EPB.new(...)
end

setmetatable( EPB, { __index = Block, __call = EPB.call } ) -- make it inherit from Block


-- EPB body fields = interface id, Timestamp (High), Timestamp (Low), caplen, origlen, data
local body_fmt = "I4 I4 I4 I4 I4 c0"

function EPB:pack()
    local body = Struct.pack(self.endian .. body_fmt,
                             self.interface_id,
                             self.timestamp:higher(),
                             self.timestamp:lower(),
                             self.caplen,
                             self.origlen,
                             self.data)
    -- invoke base Block class' pack()
    return Block.pack(self, body)
end


return EPB
