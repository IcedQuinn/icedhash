import icedhash/blake2b
export blake2b
import icedhash/blake2s
export blake2s
import icedhash/spooky2
export spooky2

when is_main_module:
    include icedhash/test
