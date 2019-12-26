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

template `+=`*(a: var pointer; offset: uint32) =
   a += offset.int

template `+=`*(a: var pointer; offset: uint) =
   a += offset.int

proc `+=`*(a: var pointer; offset: int) =
   a = cast[pointer](cast[int](a) + offset)
