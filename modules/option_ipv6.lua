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

local zero = Struct.pack("B", 0)
local full_patt   = GRegex.new("((?:[a-fA-F0-9]+:)*)((?::[a-fA-F0-9]+)+)(?:/([0-9]+))?")
local first_patt  = GRegex.new("([a-fA-F0-9]{2})([a-fA-F0-9]{2})?:")
local second_patt = GRegex.new(":([a-fA-F0-9]{2})([a-fA-F0-9]{2})?")

-- packs an IPv6 string like "2100:0db8::1a2b/64" - but is not strict about it
local function pack(ip)
    -- split string into parts
    local first, second, prefix = full_patt:match(ip)

    if not prefix then
        prefix = ""
    else
        prefix = Struct.pack("B", tonumber(prefix))
    end

    -- this will hold each byte
    local bytes = {}

    if first then
        -- break first half into bytes
        for num1, num2 in GRegex.gmatch(first, first_patt) do
            bytes[#bytes + 1] = Struct.fromhex(num1)
            if num2 then
                bytes[#bytes + 1] = Struct.fromhex(num2)
            else
                bytes[#bytes + 1] = zero
            end
        end
    end

    -- fill remaining positions with byte 0
    while #bytes < 16 do
        bytes[#bytes + 1] = zero
    end
 
    if second then
        -- now go backwards for the second half, by filling a temp table
        -- and copying from it to our bytes table
        local t = {}
        for num1, num2 in GRegex.gmatch(second, second_patt) do
            t[#t + 1] = Struct.fromhex(num1)
            if num2 then
                t[#t + 1] = Struct.fromhex(num2)
            else
                t[#t + 1] = zero
            end
        end

        local start = 16 - #t
        for index, value in ipairs(t) do
            bytes[start + index] = value
        end
    end

    -- concat and add the prefix
    return table.concat(bytes) .. prefix
end


--------------------------------------------------------------------------------
-- The OptionIPv6 base class
--
local OptionIPv6 = {}
local OptionIPv6_mt = { __index = OptionIPv6 }


function OptionIPv6.new(otype, ip, str)
    local new_class = Option.new(otype)
    new_class['ip']   = ip
    new_class['str']  = str
    setmetatable( new_class, OptionIPv6_mt )
    return new_class
end


function OptionIPv6.call(_, ...)
    return OptionIPv6.new(...)
end

setmetatable( OptionIPv6, { __index = Option, __call = OptionIPv6.call } ) -- make it inherit from Option


function OptionIPv6:pack()
    local value = pack(self.ip)
    if self.str then
        value = value .. self.str
    end

    -- set that in the base class
    Option.setValue(self, value)

    -- invoke base class pack
    return Option.pack(self)
end


return OptionIPv6
