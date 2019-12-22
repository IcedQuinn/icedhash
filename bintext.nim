
const
    #LOWER_LETTERS_ALL = "abcdefghijklmnopqrstuvqxyz"
    #UPPER_LETTERS_ALL = "ABCDEFGHIJKLMNOPQRSTUVQXYZ"
    LOWER_HEX = "0123456789abcdef"
    UPPER_HEX = "0123456789ABCDEF"
    ALL_HEX = "0123456789abcdefABCDEF"
    #NUMBERS = "0123456789"

type
    hexstring* = string

# XXX don't know about endian implications of all this

proc binary_len*(input: hexstring): int =
    ## Returns the number of bytes that can be extracted from a given hex string.
    if (len(input) mod 2) == 0:
        return len(input) /% 2
    else:
        return 0

proc to_binary*(input: hexstring): seq[uint8] =
    ## Convert a hexadecimal string to the sequence of raw bytes it represents.
    assert (len(input) mod 2) == 0
    newseq(result, input.binary_len)
    var i = 0
    var j = 0
    while i < len(input):
        var p = ALL_HEX.find(input[i])
        if p > 15: dec p, 6 # shift uppercase matches downward
        result[j] = p.uint8 shl 4
        inc i

        p = ALL_HEX.find(input[i])
        if p > 15: dec p, 6 # shift uppercase matches downward
        result[j] += p.uint8
        inc i
        inc j

proc to_hex_string*(input: string): hexstring =
    ## Validates a string contains only hexadecimal characters and returns a hexstring.
    block goodjob:
        result = input.hexstring

        if len(input) == 0: return
        if (len(input) mod 2) != 0: break

        for i in 0..<len(input):
            if ALL_HEX.find(input[i]) < 0:
                raise new_exception(ValueError, "Non-hex character in hexadecimal string")
        return
    raise new_exception(ValueError, "Must have even number of ASCII characters")

proc to_hex_string(bytes: openarray[uint8]; code: string; start: int = 0, len: int = -1): hexstring =
    ## Converts an array of bytes to a string of hex-like
    ## characters. You must provide a codebook of sixteen characters which
    ## are assumed to be [0-9a-f], though a strange person might choose
    ## to use something else. An internal method but harmless to use.
    assert len(code) >= 16

    let actual_start = if start >= 0: start else: len(bytes)-start
    let actual_len = if len >= 0: len else: len(bytes)

    assert (actual_start+actual_len) <= len(bytes)

    for i in actual_start..<actual_start+actual_len:
        result &= code[(bytes[i] and 0xF0) shr 4]
        result &= code[(bytes[i] and 0x0F)]

proc to_hex_string_upper*(bytes: openarray[uint8]; start: int = 0, len: int = -1): hexstring =
    ## Converts an array of bytes to a string of hexadecimal characters, using uppsercase letters.
    to_hex_string(bytes, UPPER_HEX, start, len)

proc to_hex_string_lower*(bytes: openarray[uint8]; start: int = 0, len: int = -1): hexstring =
    ## Converts an array of bytes to a string of hexadecimal characters, using lowercase letters.
    to_hex_string(bytes, LOWER_HEX, start, len)

when is_main_module:
    var tests = 0
    echo("TAP version 13")
    var b: array[0..5, uint8]

    proc ok(b: bool) =
        inc tests
        if b:
            echo("ok ", tests)
        else:
            echo("not ok ", tests)

    b[0] = 255
    b[1] = 127
    b[2] = 15

    ok(b.to_hex_string_lower == "ff7f0f000000")
    ok(b.to_hex_string_upper == "FF7F0F000000")
    ok(b.to_hex_string_lower.to_binary == b)

    echo("1..", tests)
