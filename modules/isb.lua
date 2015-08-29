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
-- The ISB class
--
local ISB = {}
local ISB_mt = { __index = ISB }

function ISB.new(idb, timestamp)
    assert(idb and type(idb) == 'table', "Not given IDB object or table")

    timestamp = timestamp or UInt64(0)

    local new_class = Block.new('ISB')
    new_class['interface_id'] = idb.interface_id
    new_class['timestamp']    = timestamp

    setmetatable( new_class, ISB_mt )

    return new_class
end

function ISB.call(_, ...)
    return ISB.new(...)
end

setmetatable( ISB, { __index = Block, __call = ISB.call } ) -- make it inherit from Block


-- ISB body fields = interface id, Timestamp (High), Timestamp (Low)
local body_fmt = "I4 I4 I4"

function ISB:pack()
    local body = Struct.pack(self.endian .. body_fmt,
                             self.interface_id,
                             self.timestamp:higher(),
                             self.timestamp:lower())
    -- invoke base Block class' pack()
    return Block.pack(self, body)
end


return ISB
