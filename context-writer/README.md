# Context Writer

A very simple sample application that launches a handful of threads and writes TLS context information to them using
the `custom-labels` v2 format. The context data is designed to look like what would come out of a HTTP server, but 
it is just faked up to give a straightforward standalone demo. 

## Build Configuration
There is unfortunately no easy way to, as a library (e.g. custom-labels) tell the Rust compiler to export symbols
in an end-user application; the application must explicitly pass linker flags through to LLVM to do so. To see how 
this works, check out [.cargo/config.toml](.cargo/config.toml).

