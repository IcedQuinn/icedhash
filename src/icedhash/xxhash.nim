# xxHash - Extremely Fast Hash algorithm
# Header File
# Copyright (C) 2012-2020 Yann Collet
#
# BSD 2-Clause License
# (https://www.opensource.org/licenses/bsd-license.php)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#    * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
#    * Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# You can contact the author at:
#   - xxHash homepage: https://www.xxhash.com
#   - xxHash source repository: https://github.com/Cyan4973/xxHash

import primitives

const
    XXH_VERSION_MAJOR*: int   = 0
    XXH_VERSION_MINOR*: int   = 7
    XXH_VERSION_RELEASE*: int = 4
    XXH_VERSION_NUMBER*: int  = (XXH_VERSION_MAJOR * 100 * 100 + XXH_VERSION_MINOR * 100 + XXH_VERSION_RELEASE)

    XXH3_SECRET_SIZE_MIN* = 136
    XXH3_SECRET_DEFAULT_SIZE* = 192 # minimum XXH3_SECRET_SIZE_MIN
    XXH3_INTERNALBUFFER_SIZE* = 256

    PRIME32_1: uint32 = 0x9E3779B1'u32 # 0b10011110001101110111100110110001
    PRIME32_2: uint32 = 0x85EBCA77'u32 # 0b10000101111010111100101001110111
    PRIME32_3: uint32 = 0xC2B2AE3D'u32 # 0b11000010101100101010111000111101
    PRIME32_4: uint32 = 0x27D4EB2F'u32 # 0b00100111110101001110101100101111
    PRIME32_5: uint32 = 0x165667B1'u32 # 0b00010110010101100110011110110001

    PRIME64_1: uint64 = 0x9E3779B185EBCA87'u64 # 0b1001111000110111011110011011000110000101111010111100101010000111
    PRIME64_2: uint64 = 0xC2B2AE3D27D4EB4F'u64 # 0b1100001010110010101011100011110100100111110101001110101101001111
    PRIME64_3: uint64 = 0x165667B19E3779F9'u64 # 0b0001011001010110011001111011000110011110001101110111100111111001
    PRIME64_4: uint64 = 0x85EBCA77C2B2AE63'u64 # 0b1000010111101011110010100111011111000010101100101010111001100011
    PRIME64_5: uint64 = 0x27D4EB2F165667C5'u64 # 0b0010011111010100111010110010111100010110010101100110011111000101

# Definitions
type
    XXH32_state* = object
        total_len_32: uint32
        large_len: uint32
        v1: uint32
        v2: uint32
        v3: uint32
        v4: uint32
        mem32: array[0..3, uint32]
        memsize: uint32
        reserved: uint64

    XXH64_state* = object
        total_len: uint64
        v1: uint64
        v2: uint64
        v3: uint64
        v4: uint64
        mem64: array[0..3, uint64]
        memsize: uint32
        reserved32: uint64
        reserved64: uint32

    XXH3_state* = object
        acc: array[0..7, uint64]
        customSecret: array[0..XXH3_SECRET_DEFAULT_SIZE-1, uint8]
        buffer: array[0..XXH3_INTERNALBUFFER_SIZE-1, uint8]
        bufferedSize: uint32
        nbStripesPerBlock: uint32
        nbStripesSoFar: uint32
        secretLimit: uint32
        reserved32: uint32
        reserved32_2: uint64
        totalLen: uint64
        seed: uint64
        reserved64: uint32
        secret: cstring

    XXH32_canonical* = array[0..3, uint8]
    XXH64_canonical* = array[0..7, uint8]

    XXH128_hash* = object
        low64, high64: uint64

    XXH128_canonical* = object
        digest: array[0..15, uint8]

    XXH_alignment = enum
        XXH_aligned
        XXH_unaligned

static:
    assert sizeof(XXH32_canonical) == sizeof(uint32)
    assert sizeof(XXH64_canonical) == sizeof(uint64)

proc XXH_read32(memPtr: pointer): uint32 =
    ## Portable and safe solution. Generally efficient.
    ## see: https://stackoverflow.com/a/32095106/646947
    copymem(addr result, memPtr, result.sizeof)

# TODO
# clang/gcc
#  define XXH_rotl32 __builtin_rotateleft32
#  define XXH_rotl64 __builtin_rotateleft64
# msvc
#  define XXH_rotl32(x,r) _rotl(x,r)
#  define XXH_rotl64(x,r) _rotl64(x,r)

template XXH_rotl32(x, r: untyped): untyped =
    ((x shl r) or (x shr (32 - r)))

template XXH_rotl64(x, r: untyped): untyped =
    ((x shl r) or (x shr (64 - r)))

# TODO
# clang/gcc
#  define XXH_swap32 __builtin_bswap32
# msvc
#  define XXH_swap32 _byteswap_ulong

proc XXH_swap32 (x: uint32): uint32 {.inline.} =
    return  ((x shl 24) and 0xff000000'u32 ) or
            ((x shl  8) and 0x00ff0000'u32 ) or
            ((x shr  8) and 0x0000ff00'u32 ) or
            ((x shr 24) and 0x000000ff'u32 )

proc XXH_readLE32(p: pointer): uint32 =
    when cpu_endian == little_endian:
        return XXH_read32(p)
    else:
        return XXH_swap32(XXH_read32(p))

proc XXH_readBE32(p: pointer): uint32 =
    when cpu_endian == little_endian:
        return XXH_swap32(XXH_read32(p))
    else:
        return XXH_read32(p)

proc XXH_readLE32_align(p: pointer; align: XXH_alignment): uint32 {.inline.} =
    case align
    of XXH_unaligned:
        return XXH_readLE32(p);
    of XXH_aligned:
        when cpu_endian == little_endian:
            return cast[ptr uint32](p)[]
        else:
            return XXH_swap32(cast[ptr uint32](p)[])

proc XXH32_round(acc, input: uint32): uint32 =
    result  = acc
    result += input * PRIME32_2
    result  = XXH_rotl32(result, 13)
    result *= PRIME32_1

proc XXH32_avalanche(h32: uint32): uint32 =
    result  = h32
    result  = result xor (result shr 15)
    result *= PRIME32_2
    result  = result xor (result shr 13)
    result *= PRIME32_3
    result  = result xor (result shr 16)

#define XXH_get32bits(p) XXH_readLE32_align(p, align)

proc XXH32_finalize(ch32: uint32; cp: ptr uint8; clen: int; align: XXH_alignment): uint32 =
    var h32 = ch32
    var p   = cp

    template XXH_get32bits(p: untyped): untyped =
        XXH_readLE32_align(p, align)

    template process1() =
        h32 += p[] * PRIME32_5
        p += 1
        h32 = XXH_rotl32(h32, 11) * PRIME32_1

    template process4() =
        h32 += XXH_get32bits(p) * PRIME32_3
        p += 4
        h32  = XXH_rotl32(h32, 17) * PRIME32_4

    var len = clen and 15

    while len >= 4:
        process4()
        len -= 4

    while len > 0:
        process1()
        len -= 1

    return XXH32_avalanche(h32)

proc XXH32_endian_align(cinput: ptr uint8; clen: int; seed: uint32; align: XXH_alignment): uint32 {.inline.} =
    var input = cinput
    var bEnd: ptr uint8 = input + clen;
    var h32 {.noinit.}: uint32
    var len = clen

    template XXH_get32bits(p: untyped): untyped =
        XXH_readLE32_align(p, align)

    if input == nil:
        len   = 0
        bEnd  = cast[ptr uint8](16)
        input = bEnd

    if len >= 16:
        let limit: ptr uint8 = bEnd - 15

        var v1: uint32 = seed + PRIME32_1 + PRIME32_2
        var v2: uint32 = seed + PRIME32_2
        var v3: uint32 = seed + 0
        var v4: uint32 = seed - PRIME32_1

        while true:
            v1 = XXH32_round(v1, XXH_get32bits(input))
            input += 4
            v2 = XXH32_round(v2, XXH_get32bits(input))
            input += 4
            v3 = XXH32_round(v3, XXH_get32bits(input))
            input += 4
            v4 = XXH32_round(v4, XXH_get32bits(input))
            input += 4
            if input >= limit: break

        h32 = XXH_rotl32(v1, 1) + XXH_rotl32(v2, 7) + XXH_rotl32(v3, 12) + XXH_rotl32(v4, 18)
    else:
        h32 = seed + PRIME32_5;

    h32 += len.uint32

    return XXH32_finalize(h32, input, len and 15, align)

proc xxh32*(input: pointer; len: int; seed: uint32): uint32 =
    # Simple version, good for code maintenance, but unfortunately slow for small inputs
    # XXH32_state state;
    # XXH32_init(&state, seed);
    # XXH32_update(&state, (const xxh_u8*)input, len);
    # return XXH32_final(&state);
    runnable_examples:
        var s = "i am groot"
        echo xxh32(addr s[0], s.len, 1337)

    if (cast[int](input) and 3) == 0: # Input is 4-bytes aligned, leverage the speed benefit
        return XXH32_endian_align(cast[ptr uint8](input), len, seed, XXH_aligned);
    return XXH32_endian_align(cast[ptr uint8](input), len, seed, XXH_unaligned);

proc init*(statePtr: var XXH32_state; seed: uint32) =
    var state: XXH32_state

    state.v1 = seed + PRIME32_1 + PRIME32_2;
    state.v2 = seed + PRIME32_2;
    state.v3 = seed + 0;
    state.v4 = seed - PRIME32_1;

    # do not write into reserved, planned to be removed in a future version
    copymem(addr statePtr, addr state, state.sizeof - state.reserved.sizeof)

proc update*(state: var XXH32_state; input: pointer; len: int) =
    if input == nil: return

    var p: ptr uint8    = cast[ptr uint8](input)
    let bEnd: ptr uint8 = p + len;

    state.total_len_32 += len.uint32
    state.large_len = state.large_len or (((len >= 16) or (state.total_len_32 >= 16)).uint32)

    if (state.memsize.int + len) < 16: # fill in tmp buffer
        copymem(cast[ptr uint8](cast[int](addr state.mem32) + state.memsize.int), input, len)
        state.memsize += len.uint32
        return

    if state.memsize >= 0: # some data left from previous update
        copymem(cast[ptr uint8](cast[int](addr state.mem32) + state.memsize.int), input, 16 - state.memsize.int)
        var p32: ptr uint32 = cast[ptr uint32](addr state.mem32)
        state.v1 = XXH32_round(state.v1, XXH_readLE32(p32))
        p32 += 1
        state.v2 = XXH32_round(state.v2, XXH_readLE32(p32))
        p32 += 1
        state.v3 = XXH32_round(state.v3, XXH_readLE32(p32))
        p32 += 1
        state.v4 = XXH32_round(state.v4, XXH_readLE32(p32))
        p += 16 - state.memsize.int
        state.memsize = 0

    if p <= (bEnd - 16):
        let limit: ptr uint8 = bEnd - 16;

        var v1: uint32 = state.v1
        var v2: uint32 = state.v2
        var v3: uint32 = state.v3
        var v4: uint32 = state.v4

        while true:
            v1 = XXH32_round(v1, XXH_readLE32(p))
            p+=4
            v2 = XXH32_round(v2, XXH_readLE32(p))
            p+=4
            v3 = XXH32_round(v3, XXH_readLE32(p))
            p+=4
            v4 = XXH32_round(v4, XXH_readLE32(p))
            p+=4
            if p > limit: break

        state.v1 = v1
        state.v2 = v2
        state.v3 = v3
        state.v4 = v4

    if p < bEnd:
        let z = bEnd - p
        copymem(cast[pointer](addr state.mem32), p, z)
        state.memsize = z.uint32

proc final*(state: var XXH32_state): uint32 =
    var h32 {.noinit.}: uint32

    if state.large_len > 0:
        h32 = XXH_rotl32(state.v1, 1) + XXH_rotl32(state.v2, 7) + XXH_rotl32(state.v3, 12) + XXH_rotl32(state.v4, 18)
    else:
        h32 = state.v3 + PRIME32_5

    h32 += state.total_len_32;

    return XXH32_finalize(h32, cast[ptr uint8](addr state.mem32), state.memsize.int, XXH_aligned)

proc canonicalFromHash*(dst: var XXH32_canonical; hash: uint32) =
    var yhash = hash
    when cpu_endian == little_endian: yhash = XXH_swap32(yhash)
    copymem(addr dst, addr yhash, dst.sizeof)

proc hashFromCanonical*(src: XXH32_canonical): uint32 =
    return XXH_readBE32(unsafeaddr src)

proc XXH_read64(memPtr: pointer): uint64 =
    copymem(addr result, memPtr, result.sizeof)

#if defined(_MSC_VER)     /* Visual Studio */
#  define XXH_swap64 _byteswap_uint64
#elif XXH_GCC_VERSION >= 403
#  define XXH_swap64 __builtin_bswap64
#else
proc XXH_swap64 (x: uint64): uint64 =
    return ((x shl 56) and 0xff00000000000000'u64) or
        ((x shl 40) and 0x00ff000000000000'u64) or
        ((x shl 24) and 0x0000ff0000000000'u64) or
        ((x shl 8)  and 0x000000ff00000000'u64) or
        ((x shr 8)  and 0x00000000ff000000'u64) or
        ((x shr 24) and 0x0000000000ff0000'u64) or
        ((x shr 40) and 0x000000000000ff00'u64) or
        ((x shr 56) and 0x00000000000000ff'u64)
#endif

proc XXH_readLE64(p: pointer): uint64 {.inline.} =
    when cpu_endian == little_endian:
        return XXH_read64(p)
    else:
        return XXH_swap64(XXH_read64(p))

proc XXH_readBE64(p: pointer): uint64 {.inline.} =
    when cpu_endian == little_endian:
        return XXH_swap64(XXH_read64(p))
    else:
        return XXH_read64(p)

proc XXH_readLE64_align(p: pointer; align: XXH_alignment): uint64 {.inline.} =
    case align
    of XXH_unaligned:
        return XXH_readLE64(p)
    of XXH_aligned:
        when cpu_endian == little_endian:
            return cast[ptr uint64](p)[]
        else:
            return XXH_swap64(cast[ptr uint64](p)[])

proc XXH64_round(acc, input: uint64): uint64 =
    result  = acc
    result += input * PRIME64_2
    result  = XXH_rotl64(result, 31)
    result *= PRIME64_1

proc XXH64_mergeRound(acc, val: uint64): uint64 =
    let val = XXH64_round(0, val)
    result  = acc
    result  = result xor val
    result  = result * PRIME64_1 + PRIME64_4

proc XXH64_avalanche(h64: uint64): uint64 =
    result = h64
    result  = result xor (result shr 33)
    result *= PRIME64_2
    result  = result xor (result shr 29)
    result *= PRIME64_3
    result  = result xor (result shr 32)

#define XXH_get64bits(p) XXH_readLE64_align(p, align)

proc XXH64_finalize(ch64: uint64; cp: ptr uint8; clen: int; align: XXH_alignment): uint64 =
    var h64 = ch64
    var len = clen
    var p = cp

    template XXH_get32bits(p: untyped): untyped =
        XXH_readLE32_align(p, align)

    template XXH_get64bits(p: untyped): untyped =
        XXH_readLE64_align(p, align)

    template PROCESS1_64() =
        h64 = h64 xor (p[] * PRIME64_5)
        p += 1
        h64 = XXH_rotl64(h64, 11) * PRIME64_1

    template PROCESS4_64() =
        h64 = h64 xor (XXH_get32bits(p).uint64 * PRIME64_1)
        p += 4
        h64 = XXH_rotl64(h64, 23) * PRIME64_2 + PRIME64_3

    template PROCESS8_64() =
        let k1: uint64 = XXH64_round(0, XXH_get64bits(p))
        p += 8
        h64 = h64 xor k1
        h64 = XXH_rotl64(h64, 27) * PRIME64_1 + PRIME64_4

    # Rerolled version for 32-bit targets is faster and much smaller.
    len = len and 31
    while len >= 8:
        PROCESS8_64()
        len -= 8
    if len >= 4:
        PROCESS4_64()
        len -= 4
    while len > 0:
        PROCESS1_64()
        len -= 1
    return XXH64_avalanche(h64)

proc XXH64_endian_align(cinput: ptr uint8; clen: int; seed: uint64; align: XXH_alignment): uint64 {.inline.} =
    var input = cinput
    var len = clen

    var bEnd: ptr uint8 = input + len
    var h64 {.noinit.} : uint64

    template XXH_get64bits(p: untyped): untyped =
        XXH_readLE64_align(p, align)

    if input == nil:
        len   = 0
        bEnd  = cast[ptr uint8](32)
        input = bEnd

    if len >= 32:
        let limit: ptr uint8 = bEnd - 32

        var v1: uint64 = seed + PRIME64_1 + PRIME64_2
        var v2: uint64 = seed + PRIME64_2
        var v3: uint64 = seed + 0
        var v4: uint64 = seed - PRIME64_1

        while true:
            v1 = XXH64_round(v1, XXH_get64bits(input))
            input+=8
            v2 = XXH64_round(v2, XXH_get64bits(input))
            input+=8
            v3 = XXH64_round(v3, XXH_get64bits(input))
            input+=8
            v4 = XXH64_round(v4, XXH_get64bits(input))
            input+=8
            if input > limit: break

        h64 = XXH_rotl64(v1, 1) + XXH_rotl64(v2, 7) + XXH_rotl64(v3, 12) + XXH_rotl64(v4, 18)
        h64 = XXH64_mergeRound(h64, v1)
        h64 = XXH64_mergeRound(h64, v2)
        h64 = XXH64_mergeRound(h64, v3)
        h64 = XXH64_mergeRound(h64, v4)
    else:
        h64  = seed + PRIME64_5

    h64 += len.uint64

    return XXH64_finalize(h64, input, len, align)

proc xxh64*(input: pointer; len: int; seed: uint64): uint64 =
    # /* Simple version, good for code maintenance, but unfortunately slow for small inputs */
    # XXH64_state state;
    # XXH64_init(&state, seed);
    # XXH64_update(&state, (const xxh_u8*)input, len);
    # return XXH64_final(&state);
    runnable_examples:
        var s = "i am groot"
        echo xxh64(addr s[0], s.len, 1337)
    if (cast[int](input) and 7) == 0: # Input is aligned, let's leverage the speed advantage
        return XXH64_endian_align(cast[ptr uint8](input), len, seed, XXH_aligned)
    return XXH64_endian_align(cast[ptr uint8](input), len, seed, XXH_unaligned)

proc init*(statePtr: var XXH64_state; seed: uint64) =
    var state: XXH64_state
    state.v1 = seed + PRIME64_1 + PRIME64_2
    state.v2 = seed + PRIME64_2
    state.v3 = seed + 0
    state.v4 = seed - PRIME64_1
    # do not write into reserved64, might be removed in a future version
    copymem(addr statePtr, addr state, state.sizeof - state.reserved64.sizeof)

proc update*(state: var XXH64_state; input: pointer; len: int) =
    if input == nil: return

    var p: ptr uint8    = cast[ptr uint8](input)
    let bEnd: ptr uint8 = p + len

    state.total_len += len.uint64

    if (state.memsize.int + len) < 32: # fill in tmp buffer
        copymem(cast[ptr uint8](cast[int](addr state.mem64) + state.memsize.int), input, len)
        state.memsize += len.uint32

    if state.memsize > 0: # tmp buffer is full
        copymem(cast[ptr uint8](cast[int](addr state.mem64) + state.memsize.int), input, 32 - state.memsize)
        state.v1 = XXH64_round(state.v1, XXH_readLE64(addr state.mem64[0]))
        state.v2 = XXH64_round(state.v2, XXH_readLE64(addr state.mem64[1]))
        state.v3 = XXH64_round(state.v3, XXH_readLE64(addr state.mem64[2]))
        state.v4 = XXH64_round(state.v4, XXH_readLE64(addr state.mem64[3]))
        p += 32 - state.memsize.int
        state.memsize = 0

    if (p + 32) <= bEnd:
        var limit: ptr uint8 = bEnd - 32;

        var v1: uint64 = state.v1
        var v2: uint64 = state.v2
        var v3: uint64 = state.v3
        var v4: uint64 = state.v4

        while true:
            v1 = XXH64_round(v1, XXH_readLE64(p))
            p+=8
            v2 = XXH64_round(v2, XXH_readLE64(p))
            p+=8
            v3 = XXH64_round(v3, XXH_readLE64(p))
            p+=8
            v4 = XXH64_round(v4, XXH_readLE64(p))
            p+=8
            if p > limit: break

        state.v1 = v1
        state.v2 = v2
        state.v3 = v3
        state.v4 = v4

    if p < bEnd:
        copymem(addr state.mem64, p, bEnd-p)
        state.memsize = cast[uint32](bEnd - p)

proc final*(state: var XXH64_state): uint64 =
    var h64: uint64

    if state.total_len >= 32:
        var v1: uint64 = state.v1
        var v2: uint64 = state.v2
        var v3: uint64 = state.v3
        var v4: uint64 = state.v4

        h64 = XXH_rotl64(v1, 1) + XXH_rotl64(v2, 7) + XXH_rotl64(v3, 12) + XXH_rotl64(v4, 18)

        h64 = XXH64_mergeRound(h64, v1)
        h64 = XXH64_mergeRound(h64, v2)
        h64 = XXH64_mergeRound(h64, v3)
        h64 = XXH64_mergeRound(h64, v4)
    else:
        h64  = state.v3 + PRIME64_5

    h64 += state.total_len.uint64

    return XXH64_finalize(h64, cast[ptr uint8](addr state.mem64), state.total_len.int, XXH_aligned);

proc canonicalFromHash*(dst: var XXH64_canonical; hash: uint64) =
    var yhash = hash
    when cpu_endian == little_endian: yhash = XXH_swap64(yhash)
    copymem(addr dst, addr yhash, dst.sizeof)

proc hashFromCanonical*(src: XXH64_canonical): uint64 =
    return XXH_readBE64(unsafeaddr src)

when is_main_module:
   echo "TAP version 13"
   echo "1..1"
   echo "Bail out! no tests implemented"

