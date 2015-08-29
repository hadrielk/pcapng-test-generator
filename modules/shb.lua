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
local Option  = require "option"


--------------------------------------------------------------------------------
-- The SHB base class, from which others derive
--
-- All SHBs have a type
--
local SHB = {}
local SHB_mt = { __index = SHB }


function SHB.new(hardware, os, userappl)
    local new_class = Block.new('SHB')
    new_class['magic']          = 0x1A2B3C4D
    new_class['major_version']  = 1
    new_class['minor_version']  = 0
    new_class['section_length'] = Int64(-1)
    setmetatable( new_class, SHB_mt )

    if hardware then
        new_class:addOption('shb_hardware', hardware)
    end

    if os then
        new_class:addOption('shb_os', os)
    end

    if userappl then
        new_class:addOption('shb_userappl', userappl)
    end

    return new_class
end

function SHB.call(_, ...)
    return SHB.new(...)
end

setmetatable( SHB, { __index = Block, __call = SHB.call } ) -- make it inherit from Block


function SHB:setMagic(magic)
    self.magic = magic
    return self
end


function SHB:setVersion(major, minor)
    assert(major and minor, "Not given major or minor")
    self.major_version = major
    self.minor_version = minor
    return self
end


function SHB:setLength(length)
    self.section_length = length
    return self
end


-- SHB body fields = magic, major version, minor version, section length
local body_fmt = "I4 I2 I2 e"

function SHB:pack()
    local body = Struct.pack(self.endian .. body_fmt,
                             self.magic,
                             self.major_version,
                             self.minor_version,
                             self.section_length)
    -- invoke base Block class' pack()
    return Block.pack(self, body)
end


return SHB
