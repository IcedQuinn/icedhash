## Spooky V2
### API

 - `import icedhash/spooky2`

#### One-shot
```nim
proc spooky2*(output, input, key: pointer;
              outlen, inlen, keylen: uint)
```

Process an entire message in one sequential pass.

 - **output, outlen**. Buffer to store the finished digest. Length must be between one and eight bytes.
 - **key, keylen**. Buffer holding the key for salting. Can be up to eight bytes.

It should be repeated that Spooky V2 is *not a cryptographic hash* so
salting is not equivalent to MAC signing (as it is with Blake.) It is
still useful if you need to make hash collisions a bit less predictable.

#### Steaming
The streaming API is for data which is processed in chunks. It works like this:

 - Call `init` to prepare a state object,
 - Call `update` to feed data to the hasher as it comes in,
 - Call `final` when you are done.

```nim
proc init*  (S: var Spooky2State;
             outlen: uint64;
             key: pointer = nil;
             keylen: uint = 0)
```

```nim
proc update*(S: var Spooky2State;
             input: pointer;
             inlen: uint)
```

```nim
proc final* (S: var Spooky2State;
             output: pointer;
             outlen: uint)
```
