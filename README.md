# Iced Quinn's Thing Hasher

## Blake
### API

 - `import icedhash_blake/blake2b` for blake2b.
 - `import icedhash_blake/blake2s` for blake2s.
 - `import icedhash_blake` for everything.

#### One-shot
```nim
proc blake2b*(output, input, key: pointer;
              outlen, inlen, keylen: uint)
proc blake2s*(output, input, key: pointer;
              outlen, inlen, keylen: uint)
```

Process an entire message in one sequential pass.

 - **output, outlen**. Buffer to store the finished digest. Length must be between one and sixty-four bytes for 2b, or one and thirty-two bytes for 2s.
 - **input, inlen**. Buffer holding the message to hash. Can be nil (but why?) Length must be between zero and sixty-four bytes for 2b, or one and thirty-two bytes for 2s.
 - **key, keylen**. Buffer holding the key for MAC signing. Can be nil.

#### Steaming
The streaming API is for data which is processed in chunks. It works like this:

 - Call `init` to prepare a state object,
 - Call `update` to feed data to the hasher as it comes in,
 - Call `final` when you are done.

```nim
proc init*  (S: var Blake2bState;
             outlen: uint64;
             key: pointer = nil;
             keylen: uint = 0)
proc init*  (S: var Blake2sState;
             outlen: uint64;
             key: pointer = nil;
             keylen: uint = 0)
```

```nim
proc update*(S: var Blake2bState;
             input: pointer;
             inlen: uint)
proc update*(S: var Blake2sState;
             input: pointer;
             inlen: uint)
```

```nim
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
```nim
proc init*        (S: var Blake2bState;
                   P: var Blake2bParam)
proc init*        (S: var Blake2sState;
                   P: var Blake2sParam)
```

Used instead of other `init` procs when you want to specify all of the Blake parameters yourself. You might need to do this for tree hashing modes or to include custom salts.

```nim
proc lastblock*   (self: var Blake2bState): bool
proc lastblock*   (self: var Blake2sState): bool
```

```nim
proc `lastblock=`*(self: var Blake2bState;
                   b: bool)
proc `lastblock=`*(self: var Blake2sState;
                   b: bool)
```

You don't *normally* need to set this as it will be done in the call to `final`.

```nim
proc lastnode*    (self: var Blake2bState): bool
proc lastnode*    (self: var Blake2sState): bool
```

```nim
proc `lastnode=`* (self: var Blake2bState;
                   b: bool)
proc `lastnode=`* (self: var Blake2sState;
                   b: bool)
```

If you are using Blake for tree hashing, you set this to `true` before calling `final` when dealing with the last sibling in a particular subtree.

## Dependencies

For running the test suite; otherwise use whatever you want to deal with digests.

 - icedbintext.
 - [redo](https://github.com/apenwarr/redo)

## License
Blake2b and Blake2s are available under CC-0, as the upstream authors intended.
