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
-- The OptionList class
--
local OptionList = {}
local OptionList_mt = { __index = OptionList }

function OptionList.new()
    local new_class = {  -- the new instance
        ["options"] = {},
    }
    setmetatable( new_class, OptionList_mt )
    return new_class
end

function OptionList.call(_, ...)
    return OptionList.new(...)
end

setmetatable( OptionList, { __call = OptionList.call } )


-- add a Option object
function OptionList:add(opt)
    self.options[#self.options+1] = opt
end


-- the end_of_opt option
local end_opt = Struct.pack("I2 I2", 0, 0)

function OptionList:pack()
    local result = ""

    if #self.options > 0 then
        for _, opt in ipairs(self.options) do
            result = result .. opt:pack()
        end
        -- add the end opt
        result = result .. end_opt
    end

    return result
end


return OptionList
