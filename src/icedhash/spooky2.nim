## This module implements the Spooky (V2) non-cryptographic hash, as described
## at https://www.burtleburtle.net/bob/hash/spooky.html.
##
## It is made available under CC-0 (the original code is public domain,
## to which CC-0 is almost identical to.)
##
## The module is presently built for portability and correctness though
## it assumes the underlying system is little-endian. Performance
## patches are welcome.

import primitives

const
    SPOOKY2_MAX_OUT_BYTES* = 8
    SPOOKY2_CONST* = 0xdeadbeefdeadbeef'u64 ## Cannot be zero, even, or a regular mix of 1's and 0's.
    SPOOKY2_VARIABLES* = 12
    SPOOKY2_BLOCKSIZE* = SPOOKY2_VARIABLES * uint64.sizeof

type
    Spooky2State* = object
        state: array[SPOOKY2_VARIABLES, uint64]
        buf: array[SPOOKY2_BLOCKSIZE, uint8]
        counter: int ## Total bytes processed.
        buflen: int ## Bytes trapped in the buffer.

static:
    # only a hard requirement because i don't swap it on big endy systems yet
    assert cpu_endian == little_endian

proc compress(data: ptr uint64; s: var array[SPOOKY2_VARIABLES, uint64]) {.inline.} =
    ## This mix function is for input that is >= 96 bytes in length.
    template G(di, a, b, c, d, e, ro: int) =
        s[a] += data[di]
        s[b] = s[b] xor s[c]
        s[d] = s[d] xor s[a]
        s[a] = rot(s[a], ro)
        s[d] += s[e]

    G(0, 0, 2, 10, 11, 1, 11)
    G(1, 1, 3, 11, 0, 2, 32)
    G(2, 2, 4, 0, 1, 3, 43)
    G(3, 3, 5, 1, 2, 4, 31)
    G(4, 4, 6, 2, 3, 5, 17)
    G(5, 5, 7, 3, 4, 6, 28)
    G(6, 6, 8, 4, 5, 7, 39)
    G(7, 7, 9, 5, 6, 8, 57)
    G(8, 8, 0, 6, 7, 9, 55)
    G(9, 9, 1, 7, 8, 10, 54)
    G(10, 10, 0, 8, 9, 11, 22)
    G(11, 11, 1, 9, 10, 0, 46)

proc compress_end_partial(s: var array[SPOOKY2_VARIABLES, uint64]) {.inline.} =
    template G(a, b, c, ro: int) =
        s[a] += s[b]
        s[c] = s[c] xor s[a]
        s[b] = rot(s[b], ro)

    G(11, 1, 2, 44)
    G(0, 2, 3, 15)
    G(1, 3, 4, 34)
    G(2, 4, 5, 21)
    G(3, 5, 6, 38)
    G(4, 6, 7, 33)
    G(5, 7, 8, 10)
    G(6, 8, 9, 13)
    G(7, 9, 0, 38)
    G(8, 10, 1, 53)
    G(9, 11, 0, 42)
    G(10, 0, 1, 54)

proc compress_end(data: ptr uint64; s: var array[SPOOKY2_VARIABLES, uint64]) {.inline.} =
    for i in 0..11:
        s[i] += data[i]

    compress_end_partial(s)
    compress_end_partial(s)
    compress_end_partial(s)

proc compress_short(s: var array[SPOOKY2_VARIABLES, uint64]) {.inline.} =
    ## This mix function is used for particularly short inputs.
    template G(a, b, c, ro: int) =
        s[a] = rot(s[a], ro)
        s[a] += s[b]
        s[c] = s[c] xor s[a]

    G(2, 3, 0, 50)
    G(3, 0, 1, 52)
    G(0, 1, 2, 30)
    G(1, 2, 3, 41)
    G(2, 3, 0, 54)
    G(3, 0, 1, 48)
    G(0, 1, 2, 38)
    G(1, 2, 3, 37)
    G(2, 3, 0, 62)
    G(3, 0, 1, 34)
    G(0, 1, 2, 5)
    G(1, 2, 3, 36)

proc compress_short_end(s: var array[SPOOKY2_VARIABLES, uint64]) {.inline.} =
    template G(a, b, ro: int) =
        s[a] = s[a] xor s[b]
        s[b] = rot(s[b], ro)
        s[a] += s[b]

    G(3, 2, 15)
    G(0, 3, 52)
    G(1, 0, 26)
    G(2, 1, 51)
    G(3, 2, 28)
    G(0, 3, 9)
    G(1, 0, 47)
    G(2, 1, 54)
    G(3, 2, 32)
    G(0, 3, 25)
    G(1, 0, 63)

proc init*  (S: var Spooky2State; key: pointer = nil; keylen: uint = 0) =
    ## Prepares a Spooky V2 state for use. You may provide a key which is used to salt the hash.

    # just to be safe (states might get reused)
    # TODO maybe just initialize *some* bits since we will manually overwrite others
    zeromem(addr S, S.sizeof)

    # copy salt in to state
    copymem(addr S.state[0], key, min(keylen, uint64.sizeof * 2))

    # fill the rest of state with IV
    for i in 2..<SPOOKY2_VARIABLES:
        S.state[i] = SPOOKY2_CONST

proc update*(S: var Spooky2State; input: pointer; inlen: uint) =
    ## Incrementally feeds some data to the hasher.
    var minput = input
    var minlen = inlen
    if minlen > 0'u:
        var left: uint = S.buflen.uint
        var fill: uint = SPOOKY2_BLOCKSIZE.uint - left
        if minlen > fill:
            S.buflen = 0

            if fill > 0'u64:
                copymem(addr S.buf[left], minput, fill)
                minput += fill
                minlen -= fill

            inc S.counter, SPOOKY2_BLOCKSIZE
            compress(cast[ptr uint64](input), S.state)

            while minlen > SPOOKY2_BLOCKSIZE.uint:
                inc S.counter, SPOOKY2_BLOCKSIZE
                compress(cast[ptr uint64](input), S.state)
                minput += SPOOKY2_BLOCKSIZE
                minlen -= SPOOKY2_BLOCKSIZE

        copymem(addr S.buf[S.buflen], minput, minlen)
        S.buflen += minlen.int

proc short*(S: var Spooky2State; data: ptr uint64) =
    var length = S.counter
    var remainder = S.counter mod 32
    var mdata = data

    if S.counter > 15:
        while length > uint64.sizeof * 4:
            S.state[2] += mdata[0]
            S.state[3] += mdata[1]
            seek mdata, uint64.sizeof * 4
            dec length, uint64.sizeof * 4
            S.state[0] += mdata[2]
            S.state[1] += mdata[3]

        if remainder >= 16:
            S.state[2] += mdata[0]
            S.state[3] += mdata[1]
            compress_short(S.state)
            seek mdata, 2
            remainder -= 16

    S.state[3] += (S.counter shl 56).uint64
    if remainder > 8:
        S.state[2] += mdata[0]
        S.state[3] += mdata[1]
    if remainder > 0:
        S.state[2] += mdata[0]
    else:
        S.state[2] += SPOOKY2_CONST
        S.state[3] += SPOOKY2_CONST

    compress_short_end(S.state)

proc final* (S: var Spooky2State; output: pointer; outlen: uint) =
    ## Completes a hashing and returns the resulting hash to `output`.
    if likely(S.counter < SPOOKY2_BLOCKSIZE):
        # if this message was particularly short, run the code path for short hashes
        zeromem(addr S.buf[S.buflen], S.buf.sizeof - S.buflen)
        short(S, cast[ptr uint64](addr S.buf[0]))
    else:
        # if there is a whole block left, mix it
        if S.buflen == SPOOKY2_BLOCKSIZE:
            compress(cast[ptr uint64](addr S.buf[0]), S.state)
            S.buflen = 0

        # pad and salt the last partial block
        zeromem(addr S.buf[S.buflen], S.buf.sizeof - S.buflen)
        S.buf[S.buf.len-1] = (S.counter mod SPOOKY2_BLOCKSIZE).uint8
        compress_end(cast[ptr uint64](S.buf[0]), S.state)

    copymem(output, addr S.state[0], min(outlen, uint64.sizeof * 2))

proc spooky2*(
    output, input, key: pointer;
    outlen, inlen, keylen: uint) =
        ## Convenience to perform all steps of a Spooky V2 hashing upon
        ## some data and receive a result.
        var s: Spooky2State
        init(s, key, keylen)
        update(s, input, inlen)
        final(s, output, outlen)

when is_main_module:
    echo "TAP version 13"
    echo "Bail out! algorithm is known to be implemented wrong"

    import icedbintext
    var x = "i am the toad"
    var buffer: array[SPOOKY2_MAX_OUT_BYTES, uint8]
    spooky2(
        addr buffer[0], addr x[0], nil,
        SPOOKY2_MAX_OUT_BYTES.uint, x.len.uint, 0'u)
    echo(buffer.to_hex_string_lower)


