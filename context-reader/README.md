# Context Reader

An out-of-process reader for the [polar signals custom-labels](https://github.com/polarsignals/custom-labels/tree/master)
_Thread Local Storage Format_, as well as our own TLS v2 proposal, as well as the [OTEP-4719](https://github.com/open-telemetry/opentelemetry-specification/pull/4719/changes)
_Process Context Format_. 

When you launch the process pointed at a particular PID, it loads the processes maps from `/proc/<pid>/maps`, hunts
around for process context mappings, as well as custom-labels v1 and v2 TLS variables.

It then loops forever, printing out any v1 and v2 labels on the process threads periodically. 

It needs:

* Linux 
* ELF binaries
* ARM64 or X86-64

You'll have to run it as root, or give it `CAP_SYS_PTRACE`.


## How's it work?

At startup, we hunt for configuration for the two label formats, and then having found at least one of them, 
read them out of the running process. 

* We use [procfs](http://docs.rs/procfs/latest/procfs/) to read the current threads out of the process
* For each thread:
  * Use `ptrace` to attach to the thread, and wait for it to stop
  * Read the pointer to the current label set out of the TL location we discovered at startup
  * If it's _not_ `0`, we've got thread labels!
    * Use `process_vm_readv` via the [nix](https://docs.rs/nix/latest/nix/) crate to read out our TL, and then
      chase the pointers back.
    * Print it to screen!

