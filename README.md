# Open Questions

* Is `local root span ID` something that only _Datadog_ is going to need as part of this, or _everyone_? This goes to whether or not this should be a sort of first-class feature in the context observation mechanism, or not
* What about the set of additional request metadata to capture - is this likely to be a static, globally-agreed set, or is it going to be have to be user configurable? E.g. does dd-trace-rs need to be able to ask otel-rust for a set of metadata that otel-rust does not in advance know of.
