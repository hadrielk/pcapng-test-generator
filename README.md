# pcapng-test-generator
Wireshark Lua plugin to generate [pcapng](https://github.com/pcapng/pcapng) test capture files

## Overview

This is a Lua plugin for tshark (the command line version of Wireshark), that generates [pcapng](https://github.com/pcapng/pcapng) capture files useful for testing pcapng file readers/parsers. This was created in order to provide test capture files for Wireshark's test suite, but may be useful to other pcapng file reading software as well.

The plugin generates the files in this repository's 'output_le' and 'output_be' directories. The first one is the test captures in little endian format, the second in big endian format (i.e., as if a big-endian capture device had generated the files).

You do not need to use the Lua plugin to use the test capture files in the output directories - I only included the Lua code in case someone wants to add more tests, or to inspect what its doing.

The test capture files are each automatically documented in a '.txt' file of their same name.

## Caveats

You will need Wireshark/tshark version 1.12 or newer to use the Lua plugin.
The Lua plugin is intended to work with tshark, and is *not* intended to be copied into the Personal Plugins directory; instead, it should be loaded by the command line. For example:

    tshark -r empty.pcap -X lua_script:pcapng_test_gen.lua


## Details

The Lua plugin is written to be invoked through tshark, instead of as a stand-alone Lua script, so that it could use the Struct, GRegex, and Dir library functions exposed by Wireshark's Lua API. Struct is used to encode the fields into the file. GRegex is used for a more powerful regular expresssion library than Lua's built-in "pattern" support. Dir is used to create directories regardless of platform type.

The main controlling Lua script is `pcapng_test_gen.lua`, which loads each `testXXX.lua` file in the `tests` directory, calls their `compile()` function, creates a `.txt` descriptive file from their compiled table of blocks, and then packs them into the file by calling `pack()` on each block object. The capture test file creation model was made this way so that each `testXXX.lua` file can be as simple/short as possible, while still providing metadata about what it was creating.

To create more test files, create a new `testXXX.lua` file in the `tests` directory, where `XXX` is the next number available. You should be able to get the basic idea of what a test Lua script should look like by examining the existing ones.
