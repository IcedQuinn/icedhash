
import json, icedbintext

const
    blake2_cases = slurp"../../tests/blake2-kat.json"

echo("TAP version 13")
echo("# Blake2b hashes")

var buffer: seq[uint8]
new_seq(buffer, uint64.sizeof * 8)

var js = parseJson(blake2_cases)
var tests = 0
for testcase in js:
    if testcase["hash"].get_str() == "blake2b":
        var in_key  = to_hex_string(testcase["in"].get_str()).to_binary
        var key_key = to_hex_string(testcase["key"].get_str()).to_binary
        var out_key = to_hex_string(testcase["out"].get_str()).to_binary

        zeromem(addr buffer[0], uint64.sizeof * 8)
        inc tests

        if (key_key.len > 0) and (in_key.len > 0):
            blake2b(
                addr buffer[0],
                addr in_key[0],
                addr key_key[0],
                len(out_key).uint,
                len(in_key).uint,
                len(key_key).uint)
        elif (key_key.len > 0) and (in_key.len == 0):
            blake2b(
                addr buffer[0],
                nil,
                addr key_key[0],
                len(out_key).uint,
                0,
                len(key_key).uint)
        elif (key_key.len == 0) and (in_key.len > 0):
            blake2b(
                addr buffer[0],
                addr in_key[0],
                nil,
                len(out_key).uint,
                len(in_key).uint,
                0)
        else:
            blake2b(
                addr buffer[0],
                nil,
                nil,
                len(out_key).uint,
                0,
                0)

        if out_key.to_hex_string_lower == to_hex_string_lower(buffer):
            echo("ok ", tests)
        else:
            echo("not ok ",tests)

echo("1..",tests)
