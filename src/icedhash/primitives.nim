## This module implements primitives used across hashing algorithms.

proc rot*(a: uint64; c: int): uint64 {.inline.} =
    ## Rotation; stolen from blake's reference implementation
    return (a shr c) + (a shl (64-c))

proc rot*(a: uint32; c: int): uint32 {.inline.} =
    ## Rotation; stolen from blake's reference implementation
    return (a shr c) + (a shl (32-c))

proc `[]`*[T](a: ptr T; b: int): T {.inline.} =
    ## Retrieval for pointer arithmetic.
    return cast[ptr T](cast[int](a) + (b * T.sizeof))[]

proc `[]=`*[T](a: ptr T; b: int; c: T) {.inline.} =
    ## Setting for pointer arithmetic.
    cast[ptr T](cast[int](a) + (b * T.sizeof))[] = c

proc `+=`*[T:SomeInteger](a: var pointer; offset: T) {.inline.} =
   a = cast[pointer](cast[int](a) + offset.int)

proc `+=`*[K;T:SomeInteger](a: var ptr K; offset: T) {.inline.} =
   a += K.sizeof*offset.int

proc `+`*[K;T:SomeInteger](a: ptr K; b: T): ptr K {.inline.} =
    result = cast[ptr K](cast[int](a) + (b.int * K.sizeof))

proc `-`*[K;T:SomeInteger](a: ptr K; b: T): ptr K {.inline.} =
    result = cast[ptr K](cast[int](a) - (b.int * K.sizeof))

proc `-`*(a, b: pointer): int =
    return cast[int](a) - cast[int](b)

proc seek*[T](a: var ptr T; offset: int) {.inline.} =
    var x = cast[pointer](a)
    x += offset * T.sizeof
    a = cast[ptr T](x)

{.experimental: "strictNotNil".}
proc prepare_output*(output: pointer not nil; out_len, used_len: uint) =
    assert output != nil

    # nothing to prepare; all will be overridden
    if out_len < used_len: return
    # XXX can make more efficient by only zeroing what we won't write, but have to unit test it
    zeromem(output, out_len)

when is_main_module:
   echo "TAP version 13"
   echo "1..1"
   echo "Bail out! no tests implemented"

