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
-- The OptionFormat base class
--
local OptionFormat = {}
local OptionFormat_mt = { __index = OptionFormat }


function OptionFormat.new(otype, fmt, val, str)
    local new_class = Option.new(otype)
    new_class['fmt'] = fmt
    new_class['val'] = val
    new_class['str'] = str
    setmetatable( new_class, OptionFormat_mt )
    return new_class
end


function OptionFormat.call(_, ...)
    return OptionFormat.new(...)
end

setmetatable( OptionFormat, { __index = Option, __call = OptionFormat.call } ) -- make it inherit from Option

-- due to Lua 5.1/5.2 changes
local unpack = unpack or table.unpack


function OptionFormat:pack()
    local value
    if type(self.val) == 'table' then
        value = Struct.pack(self.endian .. self.fmt, unpack(self.val))
    else
        value = Struct.pack(self.endian .. self.fmt, self.val)
    end
    if self.str then
        value = value .. self.str
    end

    -- set that in the base class
    Option.setValue(self, value)

    -- invoke base class pack
    return Option.pack(self)
end


return OptionFormat
