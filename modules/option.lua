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


--------------------------------------------------------------------------------
-- The Option base class, from which others derive
--
-- All Options have a type
--
local Option = {}
local Option_mt = { __index = Option }


function Option.new(otype, value)
    assert(otype, "Not given an option type")
    local new_class = {  -- the new instance
        ["otype"]   = otype,
        ["code"]    = Defines:getOptionCode(otype),
        ["endian"]  = Defines:getEndian(),
        ["value"]   = value,
    }
    setmetatable( new_class, Option_mt )
    return new_class
end

function Option.call(_, ...)
    return Option.new(...)
end

setmetatable( Option, { __call = Option.call } )


function Option:getType()
    return self.otype
end


function Option:setValue(value)
    self.value = value
    return self
end


-- all options have a code, length, value, pad
local opt_fmt = "I2 I2 c0 c0"

function Option:pack()
    self.value = self.value or ""

    local opt_len = string.len(self.value)

    return Struct.pack(self.endian .. opt_fmt,
                       self.code,
                       opt_len,
                       self.value,
                       getPad(opt_len))
end


return Option
