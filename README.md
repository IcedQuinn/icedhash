`icedhash` is a collection of cryptographic and non-cryptographic
hashing routines which have been ported to native Nim.

# Conventions

In this section we will describe hash functions in a general way.

Each hash function has its own capabilities and slightly different
parameters. If you wish to make use of those special features then you
will need to create wrappers to specific implementations. Fortunately
those wrappers are cheap in Nim—​they are likely to be inlined away and
you will pay very little or not at all.

## Seeds and Keys

Some hashing algorithms have a concept of *keys* or *seeds*. This is a
piece of secondary information you can use to alter the result of a hash
algorithm.

There is no generic way to handle these. Some algorithms like the Blake
and XXHash family allow taking salt or a seed as a separate parameter.
Some algorithms do not support this at all—​you have to rely on HMAC or
some other salting mechanism.

## One-shot APIs

A one-shot API consumes an entire buffer, calculates a hash, and outputs
that hash in a single function call. These are based on the following
function signature:

``` nim
OneShotHash* = proc(
  output, input: pointer;
  out_len, in_len: int) {.nimcall.}
```

## Streaming APIs

Streaming APIs consist of multiple distinct steps:

1.  Initializing the stream kernel

2.  Feeding data on a piece-by-piece basis

3.  Finalization; telling a stream kernel there is no more data to
    process and extracting the actual hash

As of 20231107 this is now based on a \[type
concept\](<https://nim-lang.org/docs/manual_experimental.html#concepts>):

``` nim
StreamingHash* = concept var x
  # Prepares the hasher for streaming.
  init(x)
  # Pushes some amount of bytes in to the device.
  update(x, pointer, int)
  # Finish the job and output the bytes
  final(x, pointer, int)
```

# Hashes

## Blake 2

### API

-   `import icedhash/blake2b` for blake2b.

-   `import icedhash/blake2s` for blake2s.

#### One-shot

``` nim
proc blake2b*(output, input, key: pointer;
              outlen, inlen, keylen: uint)
proc blake2s*(output, input, key: pointer;
              outlen, inlen, keylen: uint)
```

Process an entire message in one sequential pass.

-   **output, outlen**. Buffer to store the finished digest. Length must
    be between one and sixty-four bytes for 2b, or one and thirty-two
    bytes for 2s.

-   **input, inlen**. Buffer holding the message to hash. Can be nil
    (but why?) Length must be between zero and sixty-four bytes for 2b,
    or one and thirty-two bytes for 2s.

-   **key, keylen**. Buffer holding the key for MAC signing. Can be nil.

#### Streaming

The streaming API is for data which is processed in chunks. It works
like this:

-   Call `init` to prepare a state object,

-   Call `update` to feed data to the hasher as it comes in,

-   Call `final` when you are done.

``` nim
proc init*  (S: var Blake2bState;
             outlen: uint64;
             key: pointer = nil;
             keylen: uint = 0)
proc init*  (S: var Blake2sState;
             outlen: uint64;
             key: pointer = nil;
             keylen: uint = 0)
```

``` nim
proc update*(S: var Blake2bState;
             input: pointer;
             inlen: uint)
proc update*(S: var Blake2sState;
             input: pointer;
             inlen: uint)
```

``` nim
proc final* (S: var Blake2bState;
             layer_last: bool;
             output: pointer;
             outlen: uint)
proc final* (S: var Blake2sState;
             layer_last: bool;
             output: pointer;
             outlen: uint)
```

#### Advanced

``` nim
proc init*(S: var Blake2bState;
           P: var Blake2bParam)
proc init*(S: var Blake2sState;
           P: var Blake2sParam)
```

Used instead of other `init` procs when you want to specify all of the
Blake parameters yourself. You might need to do this for tree hashing
modes or to include custom salts.

``` nim
proc lastblock*(self: var Blake2bState): bool
proc lastblock*(self: var Blake2sState): bool
```

``` nim
proc `lastblock=`*(self: var Blake2bState;
                   b: bool)
proc `lastblock=`*(self: var Blake2sState;
                   b: bool)
```

You don’t *normally* need to set this as it will be done in the call to
`final`.

``` nim
proc lastnode*(self: var Blake2bState): bool
proc lastnode*(self: var Blake2sState): bool
```

``` nim
proc `lastnode=`*(self: var Blake2bState;
                  b: bool)
proc `lastnode=`*(self: var Blake2sState;
                  b: bool)
```

If you are using Blake for tree hashing, you set this to `true` before
calling `final` when dealing with the last sibling in a particular
subtree.

## Blake 3

Patches welcome.

## XXHash

XXHash is a non-cryptographic hash by [Yann
Collet](https://github.com/Cyan4973/xxHash).

A streaming interface is supported but the general intended use for
XXHash is through the one-shot `xxh32` or `xxh64` procedures.

Unlike Spooky and Blake the output size of a hash is always fixed by
which version of the algorithm you use. `xxh32` creates 32-bit hashes
and `xxh64` creates 64-bit hashes.

### API

-   `import icedhash/xxhash`

#### One-shot

``` nim
proc xxh32*(input: pointer; len: int; seed: uint32): uint32
proc xxh64*(input: pointer; len: int; seed: uint64): uint64
```

Process an entire message in one sequential pass.

-   **input**. Pointer to the first byte to be hashed.

-   **len**. Number of bytes to be hashed.

-   **seed**. A seed, salt, or key. Allows different hash results for
    the same input.

<div class="note">

As a *non-cryptographic* hash this is more reliable for probablistic
algorithms which need more than one hash per object, or as a thin layer
of security to make it harder for attackers to design malicious
payloads. It should not be used in place of a proper MAC.

</div>

#### Streaming

The streaming API is for data which is processed in chunks. It works
like this:

-   Call `init` to prepare a state object,

-   Call `update` to feed data to the hasher as it comes in,

-   Call `final` when you are done.

``` nim
proc init*(state: var XXH32_state;
           seed: XXH32_hash)

proc init*(state: var XXH64_state;
           seed: XXH64_hash)
```

``` nim
proc update*(state: var XXH32_state;
             input: pointer;
             len: int): XXH_errorcode
proc update*(state: var XXH64_state;
             input: pointer;
             len: int): XXH_errorcode
```

``` nim
proc final*(state: var XXH32_state; output: pointer; out_len: uint)
proc final*(state: var XXH64_state; output: pointer; out_len: uint)
```

## Dependencies

For end users:

-   None!

For people hacking on icedhash:

-   [Lets](https://lets-cli.org/). Top-level task runner.

-   [kyua](https://github.com/jmmv/kyua). To run the test suites and
    generate reports.

-   [asciidoctor](https://docs.asciidoctor.org/). To generate the
    README.

-   [pandoc](https://pandoc.org/). To generate the README.

-   [tup](https://gittup.org/tup/manual.html). For compiling tests.

-   icedbintext. For converting hashes to hexadecimal outputs.

## License

-   Blake2b and Blake2s are available under CC-0. (Implemented from
    paper.)

-   SpookyV2 is available under CC-0. (Ported.)

-   XXHash is available under BSD. (Ported.)
