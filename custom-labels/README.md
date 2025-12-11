# Custom Labels
This is fork of [polarsignals/custom-labels](https://github.com/polarsignals/custom-labels) which adds a 
**new label scheme** and a minimal Rust implementation of **OTEP 4719: Process Context**.  

## Process Context
This is a partial implementation of [OTEP 4719: Process Context](https://github.com/open-telemetry/opentelemetry-specification/pull/4719) in Rust.
It provides straightforward APIs for both reading and writing process context, and deals with the serialization
as well as the management of the mappings.

_It has been largely mechanically converted from the [sig-profiling implementation](https://github.com/open-telemetry/sig-profiling/tree/main/process-context/c-and-cpp)
into Rust and shouldn't be used for anything serious!_

