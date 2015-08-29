# pcapng-test-generator
Wireshark Lua plugin to generate [pcapng](https://github.com/pcapng/pcapng) test capture files

## Overview

This is a Lua plugin for tshark (the command line version of Wireshark), that generates [pcapng](https://github.com/pcapng/pcapng) capture files useful for testing pcapng file readers/parsers. This was created in order to provide test capture files for Wireshark's test suite, but may be useful to other pcapng file reading software as well.

The plugin generates the files in this repository's 'output_le' and 'output_be' directories. The first one is the test captures in little endian format, the second in big endian format (i.e., as if a big-endian capture device had generated the files).

You do not need to use the Lua plugin to use the test capture files in the output directories - I only included the Lua code in case someone wants to add more tests, or to inspect what its doing.

The test capture files are each automatically documented in a '.txt' file of their same name.

You will need Wireshark/tshark version 1.12 or newer to use the Lua plugin.
