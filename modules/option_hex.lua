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

local Option  = require "option"


--------------------------------------------------------------------------------
-- The OptionHex base class
--
local OptionHex = {}
local OptionHex_mt = { __index = OptionHex }


function OptionHex.new(otype, hex, str)
    local new_class = Option.new(otype)
    new_class['hex'] = hex
    new_class['str'] = str
    setmetatable( new_class, OptionHex_mt )
    return new_class
end


function OptionHex.call(_, ...)
    return OptionHex.new(...)
end

setmetatable( OptionHex, { __index = Option, __call = OptionHex.call } ) -- make it inherit from Option


function OptionHex:pack()
    local value = Struct.fromhex(self.hex)
    if self.str then
        value = value .. self.str
    end

    -- set that in the base class
    Option.setValue(self, value)

    -- invoke base class pack
    return Option.pack(self)
end


return OptionHex
