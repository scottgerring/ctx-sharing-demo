# Context Sharing Demo

This repo contains a minimal implementation of our v2 proposal for the **TLS Context Storage Mechanism**, as well as a sample
implementation of a writer and a reader. 

**NOTE: all of this is **Linux Only!**. There is a `.devcontainer` in the root of the repository to make it easier to work on this on 
non-linux machines in for instance VSCode or RustRover.**

## Components

* [custom-labels](custom-labels): A fork of the PolarSignals custom-labels repository, with added support for the v2 TLS proposal, as well as a minimal implementation of [OTEP-4719 - Process Context](https://github.com/open-telemetry/opentelemetry-specification/pull/4719/files), which the TLS implementation relies upon
* [context-writer](context-writer): An application that launches a bunch of threads and writes webserver-looking context information to them
* [context-reader](context-reader): An application that can be used to read v1 and v2 TLS information out of a running process, periodically dumping it out to the screen

In the [datadog](datadog) directory, you will additionally find an  actix web implementation using a version of [dd-trace-rs](TODO) modified to 
capture the thread context automatically.  

## Getting started

From a Linux machine (or a devcontainer) with the Rust and LLVM tooling installed:

```bash
# Build and run the reader and the writer, and then launch them both, showing the reader 
# polling context out of the writer using ptrace. 
./run-context-writer-demo.sh
```

You can also use context-reader to check that the TLS info is appearing properly in the binary of
a running process: 
```bash
cd context-reader
cargo run -- --print-tls 12345

> 2025-12-11T13:22:19.444095Z  INFO context_reader::tls_symbols::elf_reader: Found OBJECT symbol __libc_enable_secure in dynsyms
> 2025-12-11T13:22:19.444099Z  INFO context_reader::tls_symbols::process: Found 10 TLS/OBJECT symbols in: "/lib/aarch64-linux-gnu/ld-2.31.so"
> ╭                                                                   ╮
>   Symbol Name                   Type  Source  Binary              
>   custom_labels_current_set_v2  TLS   dynsym  context-writer      
>   custom_labels_current_set     TLS   dynsym  context-writer      
>   errno                         TLS   dynsym  libc-2.31.so
> ...         
```

If your symbols don't appear, try adding `--include-obj` and `--include-symtab` to see if they've
ended up somewhere else. 
