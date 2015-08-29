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

local Option     = require "option"
local OptionList = require "option_list"


--------------------------------------------------------------------------------
-- The Block base class, from which others derive
--
-- All Blocks have a type
--
local Block = {}
local Block_mt = { __index = Block }


function Block.new(btype)
    local new_class = {  -- the new instance
        ["btype"]   = btype,
        ["code"]    = Defines:getBlockCode(btype),
        ["endian"]  = Defines:getEndian(),
        ["options"] = OptionList.new(),
    }
    setmetatable( new_class, Block_mt )
    return new_class
end


function Block:getType()
    return self.btype
end


-- adds an Option object
function Block:addOption(opt, value)
    if type(opt) == 'table' then
        assert(opt.getType, "Not passed an Option object")
        self.options:add(opt)
    else
        self.options:add(Option(opt, value))
    end
    return self
end


-- all blocks have a code, length, body, body pad, options, ending length
local block_fmt = "I4 I4 c0 c0 c0 I4"

function Block:pack(body)
    assert(body, "Not given body")

    local body_len = string.len(body)

    local opts = self.options:pack()

    local block_len = 4 + 4 + body_len + pad(body_len) + string.len(opts) + 4

    return Struct.pack(self.endian .. block_fmt,
                       self.code,
                       block_len,
                       body, getPad(body_len),
                       opts,
                       block_len)
end


return Block
