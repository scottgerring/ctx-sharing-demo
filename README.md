# Context Sharing Demo

This is a project that shows thread-local context stored by a Rust webserver, and read out from out of process following
the [polarsignals custom labels TL storage format](https://github.com/polarsignals/custom-labels/tree/master). It's
made up of the following bits:

### A Demo App

* [opentelemetry-rust context-observer-test fork](https://github.com/bantonsson/opentelemetry-rust/tree/ban/context-observer-test) - Björn's context observer branch gives us the basic hook we need to capture what's happening in OTel. We will have to work to get this upstreamed before we can update dd-trace-rs.
* [dd-trace-rs context-observer-test fork](https://github.com/scottgerring/dd-trace-rs/tree/scottgerring/context-observer-test) - add an implementation of the context observer that can write to either the polarsignal's label storage (and thus process TL), _or_, to stdout.
* [async-web](async-web) - This is the Rust app. It is instrumented with [dd-trace-rs] with the context observation turned on, and some magical build args sprinkled in to ensure that the TL symbols are published in the resulting binary.

### A Reader
* [context-reader](context-reader) - An out of process reader that, given a PID, periodically polls for TL labels and dumps them out to stdout.
* [Dockerfile](dockerfile) and [build-and-run.sh](build-and-run.sh) - An easy way to plug this all together and see if it works in a Linux container (which is rather useful if you happen to be developing on a Mac)

## How to use this?
To make my life easier, the rust dependencies through the demo app to otel all use relative local paths. You'll need to clone the two branches for otel-rust and dd-trace-rs into this directory
for this to work. I will clean this up when other people care :) 


# Scott Scratch

## Open Questions

* Is `local root span ID` something that only _Datadog_ is going to need as part of this, or _everyone_? This goes to whether or not this should be a sort of first-class feature in the context observation mechanism, or not
* What about the set of additional request metadata to capture - is this likely to be a static, globally-agreed set, or is it going to be have to be user configurable? E.g. does dd-trace-rs need to be able to ask otel-rust for a set of metadata that otel-rust does not in advance know of.
* How terrible do we feel about reading span data before it is finalized? Trace & Span IDs should be fine and immutable, other span attributes are not per the OTel spec. Björn observes that that _in practice_ these should be immutable, as things like sampling will not work properly if they are mutated after the span is created. 

## Observations
* The memory format itself uses a root 'label set' with keys/values referenced out by pointer; this means we need to do a bunch of individual reads into the process while it is being suspended to extract state. Could we not do this in one contiguous chunk by constraining the maximum size of the record? 
* The `build.rs` customization required in the user's executable is not great UX:
  * Extra `build-dependency` from the user's app on the polarsignals lib 
  * Custom `build.rs` to invoke the polarsignals customization pieces
  
## Discoverability
`.symtab` vs `.dynsym`. The former is where debug symbols go, the latter is where we need them to be if we want them to be discoverable. It appears this is only achievable with linker flags like: `-Wl,--dynamic-list=./dlist`, where dlist lists the symbols from the custom-labels crate that we want to be discoverable.

An alternative is building the lib to a shared library, where `#[no_mangle]` will see the labels TL ending up predictably in the `dynsym`. But this makes runtime fun, and the community typically expects statically linked bins.

An alternative way of doing the "export this single" thing in Rust involves editing `.cargo/config.toml` - this feels like the sweet spot:

```
[target.'cfg(unix)'] # Match anything unix-ish - linux/mac - regardless of CPU arch 
rustflags = ["-Clink-arg=-Wl,--export-dynamic"]
```

I think concretely we'd be looking at this:
```
 # .cargo/config.toml

  [target.'cfg(target_os = "linux")']
  rustflags = [
      "-Clink-arg=-Wl,--export-dynamic-symbol=custom_labels_abi_version",
      "-Clink-arg=-Wl,--export-dynamic-symbol=custom_labels_current_set",
  ]
```

## Alternative TL Discovery Ideas

Use [shm](https://www.man7.org/linux/man-pages/man7/shm_overview.7.html) to publish info about the TL locations. I could
imagine this is a nightmare when cgroup namespacing is involved, but i've not looked into it. Upside is we'd have the
whole address space for ourselves, and wouldn't need to rely on the discoverabilty of the symbols in the main binary.

Mutate process environment variables at startup to share TL offsets such that they can be accessed from `/proc/123/environ`.
This feels gross, but on the other hand, reading process env vars is a fairly known quantity. Would have to confirm that
mutations after process start are reflected in the `environ` proc file.

