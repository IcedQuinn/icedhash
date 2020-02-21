  - [Iced Quinn's Thing Hasher](#icedquinns-thing-hasher)
      - [Blake](#blake)
          - [API](#api)
      - [Spooky V2](#spooky-v2)
          - [API](#api-1)
      - [Dependencies](#dependencies)
      - [License](#license)

# Iced Quinn's Thing Hasher

## Blake

### API

  - `import icedhash/blake2b` for blake2b.
  - `import icedhash/blake2s` for blake2s.

#### One-shot

``` nim
proc blake2b*(output, input, key: pointer;
              outlen, inlen, keylen: uint)
proc blake2s*(output, input, key: pointer;
              outlen, inlen, keylen: uint)
```

Process an entire message in one sequential pass.

  - **output, outlen**. Buffer to store the finished digest. Length must
    be between one and sixty-four bytes for 2b, or one and thirty-two
    bytes for 2s.
  - **input, inlen**. Buffer holding the message to hash. Can be nil
    (but why?) Length must be between zero and sixty-four bytes for 2b,
    or one and thirty-two bytes for 2s.
  - **key, keylen**. Buffer holding the key for MAC signing. Can be nil.

#### Streaming

The streaming API is for data which is processed in chunks. It works
like this:

  - Call `init` to prepare a state object,
  - Call `update` to feed data to the hasher as it comes in,
  - Call `final` when you are done.

<!-- end list -->

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
proc init*        (S: var Blake2bState;
                   P: var Blake2bParam)
proc init*        (S: var Blake2sState;
                   P: var Blake2sParam)
```

Used instead of other `init` procs when you want to specify all of the
Blake parameters yourself. You might need to do this for tree hashing
modes or to include custom salts.

``` nim
proc lastblock*   (self: var Blake2bState): bool
proc lastblock*   (self: var Blake2sState): bool
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
proc lastnode*    (self: var Blake2bState): bool
proc lastnode*    (self: var Blake2sState): bool
```

``` nim
proc `lastnode=`* (self: var Blake2bState;
                   b: bool)
proc `lastnode=`* (self: var Blake2sState;
                   b: bool)
```

If you are using Blake for tree hashing, you set this to `true` before
calling `final` when dealing with the last sibling in a particular
subtree.

## Spooky V2

WARNING: SpookyV2 hashes are currently broken in this version.

### API

  - `import icedhash/spooky2`

#### One-shot

``` nim
proc spooky2*(output, input, key: pointer;
              outlen, inlen, keylen: uint)
```

Process an entire message in one sequential pass.

  - **output, outlen**. Buffer to store the finished digest. Length must
    be between one and eight bytes.
  - **key, keylen**. Buffer holding the key for salting. Can be up to
    eight bytes.

It should be repeated that Spooky V2 is *not a cryptographic hash* so
salting is not equivalent to MAC signing (as it is with Blake.) It is
still useful if you need to make hash collisions a bit less predictable.

#### Streaming

The streaming API is for data which is processed in chunks. It works
like this:

  - Call `init` to prepare a state object,
  - Call `update` to feed data to the hasher as it comes in,
  - Call `final` when you are done.

<!-- end list -->

``` nim
proc init*  (S: var Spooky2State;
             outlen: uint64;
             key: pointer = nil;
             keylen: uint = 0)
```

``` nim
proc update*(S: var Spooky2State;
             input: pointer;
             inlen: uint)
```

``` nim
proc final* (S: var Spooky2State;
             output: pointer;
             outlen: uint)
```

## Dependencies

For running the test suite; otherwise use whatever you want to deal with
digests.

  - icedbintext.
  - [redo](https://github.com/apenwarr/redo)

## License

  - Blake2b and Blake2s are available under CC-0, as the upstream
    authors intended.
  - SpookyV2 is available under CC-0 (upstream is public domain.)
