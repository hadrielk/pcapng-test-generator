-- latest development release of Wireshark supports plugin version information
if set_plugin_info then
    local my_info = {
        version   = "1.0",
        author    = "Hadriel Kaplan",
        email     = "hadrielk@yahoo.com",
        copyright = "Copyright (c) 2015, Hadriel Kaplan",
        license   = "MIT license",

        details   = [[

    This is a plugin for Wireshark, to write pcapng test files.

    Wireshark can already write pcapng files, of course, but this plugin
    allows it to write them in ways it wouldn't, so I can create test files.
    For example, it can write them in big endian byte order, or create
    multiple SHB blocks, duplicate blocks, etc.

    ]],

        help      = [[

    HOW TO RUN THIS SCRIPT:

    Load this script from the command line using tshark:
        tshark -X lua_script:pcapng_test_gen

    To only run one test (test #3):
        tshark -X lua_script:pcapng_test_gen -X lua_script1:3

    ]],
    }

    set_plugin_info(my_info)
end


-- capture command line arguments
local args = { ... }


----------------------------------------
-- sanity checking stuff
local wireshark_name = "Wireshark"
if not GUI_ENABLED then
    wireshark_name = "Tshark"
end
-- verify Wireshark is new enough
if get_version then
    local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
    if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
            error(  "Sorry, but your " .. wireshark_name .. " version (" .. get_version() .. ") is too old for this script!\n" ..
                    "This script needs " .. wireshark_name .. "version 1.11.3 or higher.\n" )
    end
else
    error(  "Sorry, but your wireshark/tshark version is too old for this script!\n" ..
            "This script needs version 1.11.3 or higher.\n" )
end

-- enable loading of our modules
_G['pcapng_test_gen'] = true


-- help wireshark find our modules
package.prepend_path("modules")
package.prepend_path("tests")

local Defines = require "defines"

local tests = {}


local function compile_test(num, big_endian)
    assert(not tests[num], "Test " .. num .. " has already been compiled")

    if big_endian then
        Defines:setBigEndian(true)
    end

    local testname = string.format("test%03d", num)

    local test = require (testname)
    assert(type(test) == 'table', testname .. ".lua did not return a table: " .. type(test))

    test.testname = testname

    test:compile()

    tests[num] = test
end


local function get_file_path(test, directory)
    local filepath

    if directory then
        -- this returns false if the directory already exists, so just check for nil
        assert(Dir.make(directory) ~= nil, "Could not create directory: " .. directory)
        filepath = directory .. __DIR_SEPARATOR__ .. test.category
    else
        filepath = test.category
    end

    assert(Dir.make(filepath) ~= nil, "Could not create directory: " .. filepath)

    return filepath .. __DIR_SEPARATOR__ .. test.testname
end


-- create a sorted block name table, so we output the same description order each time
local sorted_btypes = {}
for n in pairs(Defines.blocks) do table.insert(sorted_btypes, n) end
table.sort(sorted_btypes)


local function describe_content(test)
    local summary, details = "\nBlock counts:\n", "\nBlock sequence: "
    local t = {}

    for index, block in ipairs(test.blocks) do
        btype = block:getType()
        details = details .. btype .. ", "
        t[btype] = (t[btype] or 0) + 1
    end
    -- get rid of excess comma space at end
    details = string.sub(details, 1, string.len(details) - 2)

    for _, name in ipairs(sorted_btypes) do
        if t[name] then
            summary = summary .. "\t" .. name .. ": " .. t[name] .. "\n"
        end
    end

    return summary .. details
end


local function describe_test(num, directory)
    local test = tests[num]
    assert(test and test.testname, "Test " .. num .. " has not been compiled")

    local filename = get_file_path(test, directory) .. ".txt"

    local file, err = io.open(filename, 'w')
    assert(file, "Error opening file:" .. filename .. "\nError message: " .. tostring(err))

    file:write("Description: " .. test.description .. "\n")
    file:write("Category:    " .. test.category .. "\n")
    file:write(describe_content(test) .. "\n")

    file:close()
end

local function run_test(num, directory)
    local test = tests[num]
    assert(test and test.testname, "Test " .. num .. " has not been compiled")

    local filename = get_file_path(test, directory) .. ".pcapng"

    local file, err = io.open(filename, 'wb')
    assert(file, "Error opening file:" .. filename .. "\nError message: " .. tostring(err))

    if test.run then
        test:run(file)
    else
        assert(test.blocks, string.format("Test 'test%03d' has no blocks to write!", num))
        -- iterate over the blocks, packing them into the file
        for _, block in ipairs(test.blocks) do
            file:write( block:pack() )
        end
    end

    file:close()
end


local function do_tests(test_nums, big_endian)
    local directory = "output_le"
    if big_endian then directory = "output_be" end

    for _, num in ipairs(test_nums) do
        print(string.format("Generating test file test#%03d.pcapng", num))
        compile_test(num, big_endian)
        describe_test(num, directory)
        run_test(num, directory)
    end
end


local function execute(test_num)
    local test_nums = {}

    if test_num then
        test_nums[1] = test_num
    else
        -- figure out the numbers
        for filename in Dir.open("tests", ".lua") do
            local num = filename:match("^test(%d+)%.lua$")
            if num then
                test_nums[#test_nums + 1] = tonumber(num)
            end
        end
        table.sort(test_nums)
    end

    do_tests(test_nums)
    -- clear tests
    tests = {}

    -- do it again in big endian
    print("\nGenerating same tests in big endian format")
    do_tests(test_nums, true)
end


--------------------------------------------------------------------------------
-- main section
--------------------------------------------------------------------------------

local test_num


if #args > 0 then
    -- user specified a specific test number
    local arg = tonumber(args[1])
    if arg then
        test_num = arg
        print(string.format("Generating only test #%03d", arg))
    else
        error("Argument is not a number: " .. args[1])
    end
else
    print("Generating all test files in little endian format")
end


-- do it!
execute(test_num)


print("\nFinished generating tests")


-- disable loading of our modules
_G['pcapng_test_gen'] = nil
