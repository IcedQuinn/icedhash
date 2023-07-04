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

proc `+=`*(a: var pointer; offset: int) {.inline.} =
   a = cast[pointer](cast[int](a) + offset)

proc seek*[T](a: var ptr T; offset: int) {.inline.} =
    var x = cast[pointer](a)
    x += offset * T.sizeof
    a = cast[ptr T](x)

when is_main_module:
   echo "TAP version 13"
   echo "1..1"
   echo "Bail out! no tests implemented"

