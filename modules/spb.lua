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
-- The SPB class
--
local SPB = {}
local SPB_mt = { __index = SPB }

function SPB.new(pkt)
    assert(pkt and type(pkt) == 'table', "Not given packet data/len table")

    local data, origlen = pkt[1], pkt[2]
    assert(data, "Not given data")
    assert(origlen, "Not given packet len")

    local new_class = Block.new('SPB')
    new_class['origlen'] = origlen
    new_class['data']    = data

    setmetatable( new_class, SPB_mt )

    return new_class
end

function SPB.call(_, ...)
    return SPB.new(...)
end

setmetatable( SPB, { __index = Block, __call = SPB.call } ) -- make it inherit from Block


-- SPB body fields = origlen, data
local body_fmt = "I4 c0"

function SPB:pack()
    local body = Struct.pack(self.endian .. body_fmt,
                             self.origlen,
                             self.data)
    -- invoke base Block class' pack()
    return Block.pack(self, body)
end


return SPB
