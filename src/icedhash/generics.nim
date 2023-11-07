
type
   ## Signature for hashes that consume an entire buffer and output a
   ## hash in one shot.
   OneShotHash* = proc(
      output, input: pointer;
      out_len, in_len: int) {.nimcall.}

   ## Signature for hashes which carry a secondary salt.
   OneShotKeyedHash* = proc(
      output, input, key: pointer;
      out_len, in_len, key_len: int) {.nimcall.}

   ## A generic, streamable hash.
   StreamingHash* = concept var x
      # Prepares the hasher for streaming.
      init(x)
      # Pushes some amount of bytes in to the device.
      update(x, pointer, int)
      # Finish the job and output the bytes
      final(x, pointer, int)

