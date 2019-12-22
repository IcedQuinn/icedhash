## This module implements the Blake2b cryptographic hash, as described
## in https://blake2.net/blake2.pdf It is made available under CC-0
## as the original authors intended.
##
## The module is presently built for portability and correctness though
## it assumes the underlying system is little-endian. Performance
## patches are welcome.
##
## Blake2b supports salting, MAC, and tree hashing.

const
   BLOCKBYTES    = 128
   OUTBYTES      = 64
   KEYBYTES      = 64
   SALTBYTES     = 16
   PERSONALBYTES = 16

let IV: array[8, uint64] = [
      0x6a09e667f3bcc908'u64,
      0xbb67ae8584caa73b'u64,
      0x3c6ef372fe94f82b'u64,
      0xa54ff53a5f1d36f1'u64,
      0x510e527fade682d1'u64,
      0x9b05688c2b3e6c1f'u64,
      0x1f83d9abfb41bd6b'u64,
      0x5be0cd19137e2179'u64]

let SIGMA: array[12, array[16, uint8]] = [
    [0'u8, 1'u8, 2'u8, 3'u8, 4'u8, 5'u8, 6'u8, 7'u8, 8'u8, 9'u8, 10'u8, 11'u8, 12'u8, 13'u8, 14'u8, 15'u8],
    [14'u8, 10'u8, 4'u8, 8'u8, 9'u8, 15'u8, 13'u8, 6'u8, 1'u8, 12'u8, 0'u8, 2'u8, 11'u8, 7'u8, 5'u8, 3'u8],
    [11'u8, 8'u8, 12'u8, 0'u8, 5'u8, 2'u8, 15'u8, 13'u8, 10'u8, 14'u8, 3'u8, 6'u8, 7'u8, 1'u8, 9'u8, 4'u8],
    [7'u8, 9'u8, 3'u8, 1'u8, 13'u8, 12'u8, 11'u8, 14'u8, 2'u8, 6'u8, 5'u8, 10'u8, 4'u8, 0'u8, 15'u8, 8'u8],
    [9'u8, 0'u8, 5'u8, 7'u8, 2'u8, 4'u8, 10'u8, 15'u8, 14'u8, 1'u8, 11'u8, 12'u8, 6'u8, 8'u8, 3'u8, 13'u8],
    [2'u8, 12'u8, 6'u8, 10'u8, 0'u8, 11'u8, 8'u8, 3'u8, 4'u8, 13'u8, 7'u8, 5'u8, 15'u8, 14'u8, 1'u8, 9'u8],
    [12'u8, 5'u8, 1'u8, 15'u8, 14'u8, 13'u8, 4'u8, 10'u8, 0'u8, 7'u8, 6'u8, 3'u8, 9'u8, 2'u8, 8'u8, 11'u8],
    [13'u8, 11'u8, 7'u8, 14'u8, 12'u8, 1'u8, 3'u8, 9'u8, 5'u8, 0'u8, 15'u8, 4'u8, 8'u8, 6'u8, 2'u8, 10'u8],
    [6'u8, 15'u8, 14'u8, 9'u8, 11'u8, 3'u8, 0'u8, 8'u8, 12'u8, 2'u8, 13'u8, 7'u8, 1'u8, 4'u8, 10'u8, 5'u8],
    [10'u8, 2'u8, 8'u8, 4'u8, 7'u8, 6'u8, 1'u8, 5'u8, 15'u8, 11'u8, 9'u8, 14'u8, 3'u8, 12'u8, 13'u8, 0'u8],
    [0'u8, 1'u8, 2'u8, 3'u8, 4'u8, 5'u8, 6'u8, 7'u8, 8'u8, 9'u8, 10'u8, 11'u8, 12'u8, 13'u8, 14'u8, 15'u8],
    [14'u8, 10'u8, 4'u8, 8'u8, 9'u8, 15'u8, 13'u8, 6'u8, 1'u8, 12'u8, 0'u8, 2'u8, 11'u8, 7'u8, 5'u8, 3'u8]]

type
    Blake2bState* = object
        ## An object containing state for an ongoing Blake2b hashing.
        h        : array[8, uint64]
        t        : array[2, uint64]
        f        : array[2, uint64]
        buf      : array[BLOCKBYTES, uint8]
        buflen   : uint64
        outlen   : uint64

    Blake2bParam* {.packed.} = object
        ## A set of parameters used to initialize a new Blake2b hashing.

        digest_length*: uint8 ## Length of hash to be returned, between 1 and 64 bytes.
        key_length*   : uint8 ## Length of key, if using Blake as a MAC. Between 0 and 64 bytes.
        fanout*       : uint8 ## Number of child nodes each leaf may have when creating tree hashes.
        depth*        : uint8 ## Maximum height of a tree when creating tree hashes.
        leaf_length*  : uint32 ## Size of leaves when creating tree hashes.
        node_offset*  : uint64 ## Which child this node is in a tree hash.
        node_depth*   : uint8 ## Current depth of a tree hash.
        inner_length* : uint8
        reserved      : array[14, uint8]
        salt*         : array[SALTBYTES, uint8] ## For salting a particular hash. Optional.
        personal*     : array[PERSONALBYTES, uint8] ## Another kind of salt. Optional.

static:
    assert Blake2bParam.sizeof == 64
    assert IV.sizeof == Blake2bState.h.sizeof

proc `[]`[T](a: ptr T; b: int): T {.inline.} =
    return cast[ptr T](cast[int](a) + (b * T.sizeof))[]

proc `[]=`[T](a: ptr T; b: int; c: T) {.inline.} =
    cast[ptr T](cast[int](a) + (b * T.sizeof))[] = c

proc lastblock*(self: var Blake2bState): bool =
    ## Returns whether the state is looking at the last block to be
    ## processed. Typically set by `final`.
    return self.f[0] != 0

proc `lastblock=`*(self: var Blake2bState; b: bool) =
    self.f[0] = if b: uint64.high else: 0

proc lastnode*(self: var Blake2bState): bool =
    ## Returns whether the state is looking at the last node in a particular subtree.
    return self.f[1] != 0

proc `lastnode=`*(self: var Blake2bState; b: bool) =
    ## Sets whether the state is looking at the last node in a
    ## particular subtree. You would set this when creating tree
    ## hashes, and you have finished hashing the last sibling at a
    ## particular level.
    self.f[1] = if b: uint64.high else: 0

# TODO extract pointer arithmetic to another module
template `+=`(a: var pointer; offset: uint32) =
   a += offset.int

template `+=`(a: var pointer; offset: uint) =
   a += offset.int

proc `+=`(a: var pointer; offset: int) =
   a = cast[pointer](cast[int](a) + offset)

proc inc(S: var Blake2bState; amount: uint64) =
    ## Discount 128-bit integer addition; first adds amount to least
    ## significant byte, and on an overflow we add one to the most
    ## significant byte.
    S.t[0] += amount
    S.t[1] += (if S.t[0] < amount: 1 else: 0)

proc init*(S: var Blake2bState; P: var Blake2bParam) =
    ## Initialize a Blake2b hasher with the given parameter object. You
    ## only need to use this if you are going to do something in-depth
    ## (such as tree hashing.)

    zeromem(addr S, S.sizeof)

    var vv = cast[ptr uint64](unsafeaddr IV[0])
    var pp = cast[ptr uint64](addr P)
    var hh = cast[ptr uint64](addr S.h[0])

    for i in 0..<8:
        hh[i] = vv[i] xor pp[i]

    S.outlen = P.digest_length

proc rot(a: uint64; c: int): uint64 {.inline.} =
    # Rotation; stolen from blake's reference implementation
    return (a shr c) + (a shl (64-c))

proc G(r, g: int; m: ptr uint64; a, b, c, d: var uint64) =
    a = a + b + m[SIGMA[r][2*g].int]
    d = rot((d xor a), 32)
    c = c + d
    b = rot((b xor c), 24)
    a = a + b + m[SIGMA[r][(2*g)+1].int]
    d = rot((d xor a), 16)
    c = c + d
    b = rot((b xor c), 63)

proc compress(S: var Blake2bState; blk: ptr uint8) =
    # construct initialization block
    # XXX we could probably just keep this in the state object to be honest
    var v: array[16, uint64]
    v[0] = S.h[0]
    v[1] = S.h[1]
    v[2] = S.h[2]
    v[3] = S.h[3]
    v[4] = S.h[4]
    v[5] = S.h[5]
    v[6] = S.h[6]
    v[7] = S.h[7]
    v[8] = IV[0]
    v[9] = IV[1]
    v[10] = IV[2]
    v[11] = IV[3]
    v[12] = S.t[0] xor IV[4]
    v[13] = S.t[1] xor IV[5]
    v[14] = S.f[0] xor IV[6]
    v[15] = S.f[1] xor IV[7]

    for round in 0..11:
        G(round, 0, cast[ptr uint64](blk), v[0], v[4], v[8], v[12])
        G(round, 1, cast[ptr uint64](blk), v[1], v[5], v[9], v[13])
        G(round, 2, cast[ptr uint64](blk), v[2], v[6], v[10], v[14])
        G(round, 3, cast[ptr uint64](blk), v[3], v[7], v[11], v[15])
        G(round, 4, cast[ptr uint64](blk), v[0], v[5], v[10], v[15])
        G(round, 5, cast[ptr uint64](blk), v[1], v[6], v[11], v[12])
        G(round, 6, cast[ptr uint64](blk), v[2], v[7], v[8], v[13])
        G(round, 7, cast[ptr uint64](blk), v[3], v[4], v[9], v[14])

    # write chain function back in to our state
    S.h[0] = (S.h[0] xor v[0]) xor v[8]
    S.h[1] = (S.h[1] xor v[1]) xor v[9]
    S.h[2] = (S.h[2] xor v[2]) xor v[10]
    S.h[3] = (S.h[3] xor v[3]) xor v[11]
    S.h[4] = (S.h[4] xor v[4]) xor v[12]
    S.h[5] = (S.h[5] xor v[5]) xor v[13]
    S.h[6] = (S.h[6] xor v[6]) xor v[14]
    S.h[7] = (S.h[7] xor v[7]) xor v[15]

proc update*(S: var Blake2bState; input: pointer; inlen: uint) =
    ## Feeds more data in to an ongoing Blake2 hashing. Data is
    ## automatically split in to appropriate size chunks and processed.
    var minput = input
    var minlen = inlen
    if minlen > 0'u:
        var left: uint = S.buflen.uint
        var fill: uint = BLOCKBYTES.uint - left

        if minlen > fill:
            S.buflen = 0

            if fill > 0'u64:
                copymem(addr S.buf[left], minput, fill)
                minput += fill
                minlen -= fill

            inc S, BLOCKBYTES
            compress(S, addr S.buf[0])

            while minlen > BLOCKBYTES.uint:
                inc S, BLOCKBYTES
                compress(S, cast[ptr uint8](minput))
                minput += BLOCKBYTES
                minlen -= BLOCKBYTES

        copymem(addr S.buf[S.buflen], minput, minlen)
        S.buflen += minlen

proc init*(S: var Blake2bState; outlen: uint64; key: pointer = nil; keylen: uint = 0) =
    ## Initialize a Blake2b hasher targeted for a sequential hash
    ## job. Optionally accepts a key and the length of that key.
    if (outlen == 0) or (outlen > OUTBYTES.uint64):
        raise new_exception(ValueError, "Output bytes must be betwen 1 and 64")

    if (keylen > 0'u64) and (keylen > KEYBYTES.uint64):
        raise new_exception(ValueError, "Key length must be zero, or between 1 and 64")

    var p: Blake2bParam
    p.digest_length = outlen.uint8
    p.fanout        = 1
    p.depth         = 1

    # FML nim actually needs a 64-bit zero even though zero fits in every fucking numeric type
    if keylen > 0'u64:
        p.key_length = keylen.uint8

    init(S, p)

    if keylen > 0'u64:
        var blk: array[BLOCKBYTES, uint8];
        copymem(addr blk[0], key, keylen)
        update(S, addr blk[0], BLOCKBYTES.uint32)
        zeromem(addr blk[0], BLOCKBYTES)

proc final*(S: var Blake2bState; layer_last: bool; output: pointer; outlen: uint) =
    ## Marks a hashing as complete and returns the computed
    ## hash. `layer_last` should be true if this is the last sibling
    ## in a particular subtree, otherwise false.
    if S.lastblock: return
    if outlen > S.outlen.uint64:
        raise new_exception(ValueError, "Cannot request more out bytes than hasher can produce!")

    inc S, S.buflen

    S.lastblock = true
    if layer_last:
        S.lastnode = true

    if S.buflen < BLOCKBYTES:
        zeromem(addr S.buf[S.buflen], BLOCKBYTES.uint - S.buflen.uint)

    compress(S, addr S.buf[0])

    if output == nil: return

    copymem(output, addr S.h[0], outlen)

proc blake2b*(output, input, key: pointer; outlen, inlen, keylen: uint): int =
    ## Utility function that accepts an output buffer, optional
    ## input and optional key and performs a sequential hash in a
    ## single call.
    var S: Blake2bState

    # Verify parameters
    if (input == nil) and (inlen > 0'u): return -1
    if output == nil: return -1
    if (key == nil) and (keylen > 0'u): return -1
    if (outlen != 0'u32) and (outlen > OUTBYTES.uint): return -1
    if keylen > KEYBYTES.uint: return -1

    init(S, outlen, key, keylen)
    update(S, input, inlen)
    final(S, false, output, outlen)

when is_main_module:
    include blake2b_test
