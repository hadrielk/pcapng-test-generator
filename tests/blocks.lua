
-- prevent wireshark loading this file as a plugin
if not _G['pcapng_test_gen'] then return end


local Blocks = {
    SHB          = require ("shb"),
    IDB          = require ("idb"),
    EPB          = require ("epb"),
    SPB          = require ("spb"),
    ISB          = require ("isb"),
    NRB          = require ("nrb"),
    CB           = require ("cb"),
    Option       = require ("option"),
    OptionIPv4   = require ("option_ipv4"),
    OptionIPv6   = require ("option_ipv6"),
    OptionHex    = require ("option_hex"),
    OptionFormat = require ("option_format"),
}


return Blocks
