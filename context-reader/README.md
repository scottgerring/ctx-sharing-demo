# Context Reader

An out-of-process reader for the [polar signals custom-labels](https://github.com/polarsignals/custom-labels/tree/master)
thread local storage format.

It needs:

* Linux 
* ELF binaries
* ARM64 or X86-64

You'll have to run it as root, or give it `CAP_SYS_PTRACE`.

**Exciting Caveat**: For the moment, we're finding the TLs _in the static binary_, not at runtime. This means things that are dynamically
loading code - say, Java - won't work yet. This shouldn't be too dramatic to change once we've got an example that does this to work
against.

## How, even?

* The user passes us a PID to watch, and we make sure its running, then go find the binary behind it.
* We use [goblin](https://docs.rs/goblin/latest/goblin/) to hunt around in its symbol tables to find `custom_labels_abi_version` and `custom_labels_current_set`; the former confirms we're reading what we expect to read, the latter is the actual, current, TL data.

At this point we're ready to start polling the process every interval (the default is 1s). For each poll:

* We use [procfs](http://docs.rs/procfs/latest/procfs/) to read the current threads out of the process
* For each thread:
  * Use `ptrace` to attach to the thread, and wait for it to stop
  * Read the pointer to the current label set out of the TL location we discovered at startup
  * If it's _not_ `0`, we've got thread labels!
    * Use `process_vm_readv` via the [nix](https://docs.rs/nix/latest/nix/) crate to read out our TL, and then
      chase the pointers back.
    * Print it to screen!

There is some fairly sinister linux trickery in [src/tls_reader.rs](src/tls_reader.rs) to support this; the rest
is fairly straightforward. If we wanted to do this _more seriously_, we'd probably want to use polarsignals' library
directly for the serialization types; I've not done this because I wanted to make sure we could make this work without
the C bindings it contains.
