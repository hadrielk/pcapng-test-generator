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


------------------------------------------
-- local private functions

-- packs an IP string like "192.168.1.2" - but is not strict about it
local function pack(ip)
    local t = {}
    for num in ip:gmatch("%d+") do
        t[#t + 1] = Struct.pack("B", tonumber(num))
    end
    return table.concat(t)
end


--------------------------------------------------------------------------------
-- The OptionIPv4 base class
--
local OptionIPv4 = {}
local OptionIPv4_mt = { __index = OptionIPv4 }


function OptionIPv4.new(otype, ip, mask, str)
    local new_class = Option.new(otype)
    new_class['ip']   = ip
    new_class['mask'] = mask
    new_class['str']  = str
    setmetatable( new_class, OptionIPv4_mt )
    return new_class
end


function OptionIPv4.call(_, ...)
    return OptionIPv4.new(...)
end

setmetatable( OptionIPv4, { __index = Option, __call = OptionIPv4.call } ) -- make it inherit from Option


function OptionIPv4:pack()
    local value = pack(self.ip)
    if self.mask then
        value = value .. pack(self.mask)
    end
    if self.str then
        value = value .. self.str
    end

    -- set that in the base class
    Option.setValue(self, value)

    -- invoke base class pack
    return Option.pack(self)
end


return OptionIPv4
