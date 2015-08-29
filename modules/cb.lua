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
-- The CB class
--
local CB = {}
local CB_mt = { __index = CB }

function CB.new(pen, data, do_not_copy)
    assert(pen, "Not given PEN number")

    local new_class = Block.new(do_not_copy and 'PCB' or 'CB')
    new_class['pen']  = pen
    new_class['data'] = data

    setmetatable( new_class, CB_mt )

    return new_class
end

function CB.call(_, ...)
    return CB.new(...)
end

setmetatable( CB, { __index = Block, __call = CB.call } ) -- make it inherit from Block


-- CB body fields = PEN, data
local body_fmt = "I4 c0"

function CB:pack()
    local body = Struct.pack(self.endian .. body_fmt,
                             self.pen,
                             self.data)
    -- invoke base Block class' pack()
    return Block.pack(self, body)
end


return CB
