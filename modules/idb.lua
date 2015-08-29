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
-- The IDB class
--
local IDB = {}
local IDB_mt = { __index = IDB }


function IDB.new(interface_id, linktype, snaplen, name)
    assert(interface_id, "Not given an interface_id")
    assert(linktype, "Not given linktype")

    snaplen = snaplen or 0

    local new_class = Block.new('IDB')
    new_class['interface_id'] = interface_id
    new_class['linktype']     = linktype
    new_class['snaplen']      = snaplen
    setmetatable( new_class, IDB_mt )

    if name then
        new_class:addOption('if_name', name)
    end

    return new_class
end

function IDB.call(_, ...)
    return IDB.new(...)
end

setmetatable( IDB, { __index = Block, __call = IDB.call } ) -- make it inherit from Block


function IDB:getInterfaceID()
    return self.interface_id
end


function IDB:getSnaplen()
    return self.snaplen
end


-- IDB body fields = linktype, reserved, snaplen
local body_fmt = "I2 x2 I4"

function IDB:pack()
    local body = Struct.pack(self.endian .. body_fmt,
                             self.linktype,
                             self.snaplen)
    -- invoke base Block class' pack()
    return Block.pack(self, body)
end


return IDB
