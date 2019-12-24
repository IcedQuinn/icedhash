import icedhash_blake/blake2b
export blake2b
import icedhash_blake/blake2s
export blake2s

when is_main_module:
    include icedhash_blake/test
