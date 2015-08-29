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

local Block      = require "block"
local Option     = require "option"
local OptionList = require "option_list"
local OptionIPv4 = require "option_ipv4"
local OptionIPv6 = require "option_ipv6"


--------------------------------------------------------------------------------
-- The NRB class
--
local NRB = {}
local NRB_mt = { __index = NRB }


function NRB.new()
    local new_class = Block.new('NRB')
    -- Record lists essentially behave like Option lists, so we just re-use it
    new_class['records'] = OptionList.new(),
    setmetatable( new_class, NRB_mt )
    return new_class
end

function NRB.call(_, ...)
    return NRB.new(...)
end

setmetatable( NRB, { __index = Block, __call = NRB.call } ) -- make it inherit from Block


-- NRB Record strings have a null to terminate them, so we use this for that
local zero = Struct.pack("B", 0)


-- adds a Record entry (an Option object is used as a Record entry)
function NRB:addRecord(otype, ip, str)
    if str then
        str = str .. zero
    end

    if otype == 'nrb_record_ipv4' then
        self.records:add( OptionIPv4(otype, ip, nil, str) )
    elseif otype == 'nrb_record_ipv6' then
        self.records:add( OptionIPv6(otype, ip, str))
    else
        self.records:add( Option(otype, ip) )
    end
    return self
end


-- the nrb_record_end option
local nrb_record_end = Struct.pack("I2 I2", 0, 0)

function NRB:pack()
    local recs = self.records:pack()
    if string.len(recs) == 0 then
        -- still have to add an end-of-record entry
        recs = nrb_record_end
    end

    -- invoke base Block class' pack()
    return Block.pack(self, recs)
end


return NRB
